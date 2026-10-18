# WebGuard.AI

Plugin WordPress de securitate: firewall de aplicație + detectare și raportare locală a atacurilor. Blochează la nivel de site și ține evidența evenimentelor de tip **file-injection**, **brute-force**, **scanner-probing** și **SQL-injection**.

## Ce face

- Detectează 4 categorii de atacuri: expunere fișiere sensibile, brute-force (login + Application Passwords), scanare/probing, injecție SQL (inclusiv în corp JSON și cookie-uri).
- Blochează cererile periculoase (HTTP 403) pe **tot site-ul**: front-end, `wp-admin`, `admin-ajax.php` și REST.
- Ban pe IP cu **escaladare la recidivă** (trepte configurabile) și **ban permanent** după N abateri.
- Whitelist / ban list și **tabele live** în admin (refresh la 10 secunde).
- **Import din logul Apache** — prinde și cererile oprite la nivel de server, înainte de PHP.
- **Cloudflare-aware**: folosește IP-ul real al clientului (`CF-Connecting-IP`, folosit doar când `REMOTE_ADDR` este o adresă Cloudflare verificată).
- **Bypass prin cookie secret** pentru administratori cu IP dinamic (PPPoE).
- Anti-lockout: administratorii și editorii autentificați nu sunt niciodată blocați.
- Două tabele proprii; setările sunt păstrate în rândul rezervat al tabelului de IP-uri (fără opțiuni WordPress).

## Cerințe

- WordPress 5.3+ (folosește `wp_date()`).
- PHP 7.4+ (testat pe PHP 8.3).
- Opțional: acces în citire la logul de acces Apache, pentru ingestie.

## Instalare

1. Copiază folderul `WebGuard2.AI` în `wp-content/plugins/`.
2. Activează pluginul din meniul **Plugins**.
3. Configurează opțiunile din meniul **WebGuard.AI** din panoul de administrare.

## Structură

- `webguard.ai.php` – logica principală (detecție, blocare, ban, ingestie log, pagini de admin).
- `templates/` – paginile de administrare (dashboard, whitelist, banlist, evenimente).
- `assets/admin.js` – reîmprospătarea live a tabelelor de evenimente.

## Licență

GPL-2.0-or-later. Vezi fișierul [LICENSE](LICENSE).
