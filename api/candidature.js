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
// Disjoncteur global et seuil d'alerte, réglables sans redéploiement via les variables Vercel.
const DAILY_CAP = parseInt(process.env.DAILY_CAP || '200', 10);
const ALERT_THRESHOLD = parseInt(process.env.ALERT_THRESHOLD || '50', 10);
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

  // 3a. Limite par IP : 5 dépôts max par heure.
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

  // 3b. Disjoncteur global : borne le coût absolu en cas d'attaque distribuée.
  // Réglé très au-dessus du trafic organique pour ne jamais gêner de vrais candidats.
  const oneDayAgo = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
  const { count: dailyCount, error: dailyError } = await supabase
    .from('candidatures')
    .select('id', { count: 'exact', head: true })
    .gte('created_at', oneDayAgo);
  if (dailyError) return res.status(500).json({ error: 'Erreur interne, réessayez plus tard.' });
  if ((dailyCount || 0) >= DAILY_CAP) {
    return res.status(429).json({
      error: 'Beaucoup de candidatures aujourd’hui ! Réessayez demain, ou envoyez votre CV à contact@swipelink.fr.',
    });
  }

  const email = fields.email.trim().toLowerCase();
  const candidat = {
    prenom: fields.prenom.trim(),
    nom: fields.nom.trim(),
    telephone: fields.telephone.trim(),
    email,
    ip_hash: ipHash,
  };

  // Déduplication : un dépôt avec le même email sous 7 jours met à jour la
  // candidature existante (nouveau CV compris) au lieu de créer un doublon.
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString();
  const { data: existing } = await supabase
    .from('candidatures')
    .select('id, cv_path')
    .eq('email', email)
    .gte('created_at', sevenDaysAgo)
    .limit(1);
  const duplicate = existing && existing[0];

  // Stockage : fichier dans le bucket privé, puis ligne en base.
  const path = `${new Date().toISOString().slice(0, 10)}/${crypto.randomUUID()}.${ext}`;
  const { error: uploadError } = await supabase.storage
    .from('cvs')
    .upload(path, file.buf, { contentType: CONTENT_TYPES[ext] });
  if (uploadError) return res.status(500).json({ error: "Impossible d'enregistrer le CV, réessayez plus tard." });

  if (duplicate) {
    const { error: updateError } = await supabase
      .from('candidatures')
      .update({ ...candidat, cv_path: path })
      .eq('id', duplicate.id);
    if (updateError) {
      await supabase.storage.from('cvs').remove([path]);
      return res.status(500).json({ error: 'Erreur interne, réessayez plus tard.' });
    }
    if (duplicate.cv_path && duplicate.cv_path !== path) {
      await supabase.storage.from('cvs').remove([duplicate.cv_path]);
    }
  } else {
    const { error: insertError } = await supabase.from('candidatures').insert({ ...candidat, cv_path: path });
    if (insertError) {
      await supabase.storage.from('cvs').remove([path]);
      return res.status(500).json({ error: 'Erreur interne, réessayez plus tard.' });
    }
  }

  // Tâches d'arrière-plan best effort : jamais bloquantes pour le candidat.
  try { await maybeAlert(supabase, (dailyCount || 0) + 1); } catch (e) { /* best effort */ }
  try { await purgeOldCandidatures(supabase); } catch (e) { /* best effort */ }

  return res.status(200).json({ ok: true });
}

// Alerte email (via Resend, optionnel) quand le volume du jour devient inhabituel.
// Une seule alerte par jour, verrouillée par la table `alertes` (clé primaire = jour).
async function maybeAlert(supabase, todayCount) {
  if (todayCount < ALERT_THRESHOLD) return;
  const jour = new Date().toISOString().slice(0, 10);
  const { error } = await supabase.from('alertes').insert({ jour, type: 'volume' });
  if (error) return; // déjà alerté aujourd'hui (conflit), ou table absente
  const apiKey = process.env.RESEND_API_KEY;
  const to = process.env.ALERT_EMAIL;
  if (!apiKey || !to) return;
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({
      from: 'Swipelink Alertes <onboarding@resend.dev>',
      to: [to],
      subject: `Swipelink : volume de candidatures inhabituel (${todayCount} en 24 h)`,
      text: `${todayCount} candidatures reçues sur les dernières 24 heures (seuil d'alerte : ${ALERT_THRESHOLD}).\n\n` +
        `Si c'est un vrai pic de candidats, tout va bien — le disjoncteur coupera à ${DAILY_CAP}.\n` +
        `Si c'est du spam, vérifiez la table candidatures dans Supabase.`,
    }),
  });
}

// Rétention RGPD : purge opportuniste des candidatures de plus de 2 ans
// (recommandation CNIL pour les données de recrutement), par petits lots.
async function purgeOldCandidatures(supabase) {
  const twoYearsAgo = new Date(Date.now() - 2 * 365 * 24 * 3600 * 1000).toISOString();
  const { data: old } = await supabase
    .from('candidatures')
    .select('id, cv_path')
    .lt('created_at', twoYearsAgo)
    .limit(10);
  if (!old || !old.length) return;
  const paths = old.map((r) => r.cv_path).filter(Boolean);
  if (paths.length) await supabase.storage.from('cvs').remove(paths);
  await supabase.from('candidatures').delete().in('id', old.map((r) => r.id));
}

module.exports = handler;
module.exports.parseForm = parseForm;
module.exports.validateFields = validateFields;
module.exports.goodMagic = goodMagic;
