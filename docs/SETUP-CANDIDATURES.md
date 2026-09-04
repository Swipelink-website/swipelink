# Espace candidat — mise en service du stockage des CV

Le formulaire `/candidats` envoie les candidatures à la fonction `api/candidature.js`,
qui stocke le CV dans Supabase. Tant que les variables d'environnement ci-dessous ne sont
pas configurées dans Vercel, l'API répond « Service momentanément indisponible » et la page
invite le candidat à écrire à contact@swipelink.fr.

## 1. Créer le projet Supabase

Sur https://supabase.com (gratuit pour commencer) : créer un projet, puis :

### a. La table `candidatures` — SQL Editor, exécuter :

```sql
create table public.candidatures (
  id uuid primary key default gen_random_uuid(),
  prenom text not null,
  nom text not null,
  telephone text not null,
  email text not null,
  cv_path text not null,
  ip_hash text,
  created_at timestamptz not null default now()
);

-- Sécurité : RLS activé sans aucune policy publique.
-- Seule la clé service role (utilisée par l'API, côté serveur) peut lire/écrire.
alter table public.candidatures enable row level security;

create index candidatures_ip_hash_created_at on public.candidatures (ip_hash, created_at);
```

### b. Le bucket de stockage

Storage → New bucket → nom : `cvs` — **laisser le bucket privé** (Public bucket décoché).
Aucune policy à ajouter : seule la clé service role y accède.

## 2. Configurer Vercel

Projet Vercel → Settings → Environment Variables (environnement Production) :

| Variable | Valeur |
|---|---|
| `SUPABASE_URL` | Supabase → Settings → API → Project URL |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase → Settings → API → service_role (⚠️ secrète, jamais côté client) |
| `TURNSTILE_SECRET_KEY` | voir étape 3 |
| `IP_HASH_SALT` | une chaîne aléatoire quelconque (ex. générée sur place), pour pseudonymiser les IP |

Puis redéployer (Deployments → Redeploy) pour que les variables soient prises en compte.

## 3. Activer Cloudflare Turnstile (anti-robots)

1. https://dash.cloudflare.com → Turnstile → Add site (gratuit), domaine `swipelink.fr`.
2. Récupérer la **site key** (publique) et la **secret key**.
3. Dans `candidats.html`, remplacer la valeur de `TURNSTILE_SITE_KEY` (clé de test
   `1x00000000000000000000AA`) par la site key.
4. Mettre la secret key dans la variable `TURNSTILE_SECRET_KEY` sur Vercel.

Tant que les clés de test sont en place, le widget s'affiche et le flux fonctionne,
mais il laisse tout passer : à remplacer avant d'annoncer publiquement la page.

## 4. Consulter les candidatures

- La liste : Supabase → Table Editor → `candidatures`.
- Les CV : Supabase → Storage → `cvs` (chemin dans la colonne `cv_path`).

## Sécurité en place (résumé)

- Honeypot (champ caché) : les robots reçoivent un faux succès, rien n'est stocké.
- Turnstile vérifié côté serveur (échec ou Cloudflare injoignable ⇒ refus).
- Limite par IP : 5 dépôts/heure (IP pseudonymisée par hachage salé, RGPD).
- Fichier : PDF/Word uniquement, 4 Mo max, type réel vérifié par les premiers octets.
- Champs bornés et validés côté serveur (le client ne fait foi de rien).
- Bucket privé + RLS sans policy : aucune lecture publique possible.
