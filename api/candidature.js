// api/candidature.js — réception des candidatures (espace candidat).
//
// Sécurité appliquée côté serveur (la seule qui fait foi) :
//   1. Honeypot : le champ caché "site_web" rempli => réponse succès factice, rien n'est stocké.
//   2. Cloudflare Turnstile : le jeton est vérifié avec la clé secrète (TURNSTILE_SECRET_KEY).
//   3. Limite par IP : 5 dépôts max par heure (comptés dans la table candidatures via ip_hash).
//   4. Validation stricte : champs bornés, fichier PDF/Word uniquement, 4 Mo max,
//      type réel vérifié par les premiers octets (pas seulement l'extension).
//
// Stockage : Supabase — bucket privé "cvs" + table "candidatures".
// Configuration : voir docs/SETUP-CANDIDATURES.md.

const crypto = require('crypto');
const Busboy = require('busboy');
const { createClient } = require('@supabase/supabase-js');

const MAX_FILE = 4 * 1024 * 1024; // 4 Mo (le corps de requête Vercel est plafonné à 4,5 Mo)
const LIMIT_PER_HOUR = 5;
const CONTENT_TYPES = {
  pdf: 'application/pdf',
  doc: 'application/msword',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
};
// Clé secrète de TEST Cloudflare (accepte tout) tant que TURNSTILE_SECRET_KEY n'est pas configurée.
const TURNSTILE_TEST_SECRET = '1x0000000000000000000000000000000AA';

function goodMagic(buf, ext) {
  if (buf.length < 8) return false;
  if (ext === 'pdf') return buf.slice(0, 5).toString('latin1') === '%PDF-';
  if (ext === 'doc') return buf.slice(0, 4).equals(Buffer.from([0xd0, 0xcf, 0x11, 0xe0]));
  if (ext === 'docx') return buf.slice(0, 4).equals(Buffer.from([0x50, 0x4b, 0x03, 0x04]));
  return false;
}

function validateFields(f) {
  const prenom = (f.prenom || '').trim();
  const nom = (f.nom || '').trim();
  const tel = (f.telephone || '').trim();
  const email = (f.email || '').trim();
  if (prenom.length < 2 || prenom.length > 60) return 'Prénom invalide.';
  if (nom.length < 2 || nom.length > 60) return 'Nom invalide.';
  const digits = tel.replace(/\D/g, '');
  if (digits.length < 9 || digits.length > 15 || tel.length > 20) return 'Téléphone invalide.';
  if (email.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email)) return 'Email invalide.';
  return null;
}

function parseForm(req) {
  return new Promise((resolve, reject) => {
    const bb = Busboy({
      headers: req.headers,
      limits: { fileSize: MAX_FILE, files: 1, fields: 10, fieldSize: 2048 },
    });
    const fields = {};
    let file = null;
    let truncated = false;
    bb.on('field', (name, value) => { fields[name] = value; });
    bb.on('file', (name, stream, info) => {
      const chunks = [];
      stream.on('limit', () => { truncated = true; });
      stream.on('data', (c) => chunks.push(c));
      stream.on('end', () => { file = { name: info.filename || '', buf: Buffer.concat(chunks) }; });
    });
    bb.on('close', () => resolve({ fields, file, truncated }));
    bb.on('error', reject);
    req.pipe(bb);
  });
}

async function verifyTurnstile(token, ip) {
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: process.env.TURNSTILE_SECRET_KEY || TURNSTILE_TEST_SECRET,
        response: token || '',
        remoteip: ip,
      }),
    });
    const d = await r.json();
    return !!d.success;
  } catch (e) {
    return false; // Cloudflare injoignable : on refuse plutôt que de laisser passer.
  }
}

async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Méthode non autorisée.' });
  }
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!supabaseUrl || !supabaseKey) {
    return res.status(503).json({ error: 'Service momentanément indisponible.' });
  }

  let form;
  try {
    form = await parseForm(req);
  } catch (e) {
    return res.status(400).json({ error: 'Requête invalide.' });
  }
  const { fields, file, truncated } = form;

  // 1. Honeypot : réponse succès factice, rien n'est stocké.
  if (fields.site_web) {
    return res.status(200).json({ ok: true });
  }

  const fieldError = validateFields(fields);
  if (fieldError) return res.status(400).json({ error: fieldError });

  const ip = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'inconnue';

  // 2. Turnstile.
  if (!(await verifyTurnstile(fields.turnstile_token, ip))) {
    return res.status(403).json({ error: 'Vérification anti-robots échouée. Rechargez la page et réessayez.' });
  }

  // 4. Fichier.
  if (!file || !file.buf.length) return res.status(400).json({ error: 'CV manquant.' });
  if (truncated || file.buf.length > MAX_FILE) {
    return res.status(400).json({ error: 'Fichier trop lourd : 4 Mo maximum.' });
  }
  const extMatch = file.name.match(/\.(pdf|docx?)$/i);
  const ext = extMatch && extMatch[1].toLowerCase();
  if (!ext || !CONTENT_TYPES[ext] || !goodMagic(file.buf, ext)) {
    return res.status(400).json({ error: 'Format non accepté : PDF ou Word uniquement.' });
  }

  const supabase = createClient(supabaseUrl, supabaseKey, { auth: { persistSession: false } });
  const ipHash = crypto.createHash('sha256')
    .update(ip + (process.env.IP_HASH_SALT || 'swipelink'))
    .digest('hex');

  // 3. Limite par IP : 5 dépôts max par heure.
  const oneHourAgo = new Date(Date.now() - 3600 * 1000).toISOString();
  const { count, error: countError } = await supabase
    .from('candidatures')
    .select('id', { count: 'exact', head: true })
    .eq('ip_hash', ipHash)
    .gte('created_at', oneHourAgo);
  if (countError) return res.status(500).json({ error: 'Erreur interne, réessayez plus tard.' });
  if ((count || 0) >= LIMIT_PER_HOUR) {
    return res.status(429).json({ error: 'Trop de dépôts récents. Réessayez dans une heure.' });
  }

  // Stockage : fichier dans le bucket privé, puis ligne en base.
  const path = `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}.${ext}`;
  const { error: uploadError } = await supabase.storage
    .from('cvs')
    .upload(path, file.buf, { contentType: CONTENT_TYPES[ext] });
  if (uploadError) return res.status(500).json({ error: "Impossible d'enregistrer le CV, réessayez plus tard." });

  const { error: insertError } = await supabase.from('candidatures').insert({
    prenom: fields.prenom.trim(),
    nom: fields.nom.trim(),
    telephone: fields.telephone.trim(),
    email: fields.email.trim().toLowerCase(),
    cv_path: path,
    ip_hash: ipHash,
  });
  if (insertError) {
    await supabase.storage.from('cvs').remove([path]);
    return res.status(500).json({ error: 'Erreur interne, réessayez plus tard.' });
  }

  return res.status(200).json({ ok: true });
}

module.exports = handler;
module.exports.parseForm = parseForm;
module.exports.validateFields = validateFields;
module.exports.goodMagic = goodMagic;
