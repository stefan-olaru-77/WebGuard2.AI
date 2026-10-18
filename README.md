# WebGuard.AI

Plugin WordPress de securitate: firewall de aplicație + detectare și raportare locală a atacurilor. Blochează la nivel de site și ține evidența evenimentelor de tip **file-injection**, **brute-force**, **scanner-probing**, **SQL-injection**, **XSS**, **command-injection** și **rate-limit**.

## Ce face

- Detectează **7 categorii** de atacuri (vezi mai jos) și blochează cererile periculoase cu **HTTP 403** pe **tot site-ul**: front-end, `wp-admin`, `admin-ajax.php` și REST.
- **Ban pe IP** cu **escaladare la recidivă** (trepte configurabile) și **ban permanent** după N abateri.
- **Ban pe subnet**: opțiune de a bloca tot intervalul (`/24` la IPv4, `/64` la IPv6), util pentru scanere distribuite.
- **Rate limiting per IP**: ban automat când un IP depășește un prag de cereri într-o fereastră de timp (ex. 240 cereri / 60 s).
- **Whitelist / Ban List** și **tabele live** în admin (refresh la 10 secunde).
- **Căutare, filtrare și paginare** în tabelele de evenimente; **Export CSV** pentru evenimente, banuri și whitelist.
- Coloană **Ban** în toate tabelele cu IP-uri (mai puțin Ban List), care arată dacă IP-ul e banat: `Permanent`, `Temporar 5h:37m` sau `Subnet ...`.
- **Import din logul Apache** — prinde și cererile oprite la nivel de server, înainte de PHP.
- **Cloudflare-aware**: folosește IP-ul real al clientului (`CF-Connecting-IP`, doar când `REMOTE_ADDR` este o adresă Cloudflare verificată).
- **Bypass prin cookie secret / link magic** pentru administratori cu IP dinamic (PPPoE).
- **Anti-lockout**: administratorii și editorii autentificați nu sunt niciodată blocați sau banați.
- Ignoră traficul **local (loopback)** — cererile de la `127.0.0.1` / `::1` (cron, scanări/teste de pe server) nu poluează rapoartele.

## Categorii de detectare

| Categorie | Ce prinde |
|---|---|
| **File Injection** | Acces la fișiere sensibile (`.env`, `.git`, `wp-config.php`, `debug.log`, backup-uri, `.idea` etc.), path traversal și LFI. |
| **Brute Force** | Încercări repetate de autentificare (wp-login și Application Passwords / REST). |
| **Scanner / Probing** | User-Agent de scanner (zgrab, nmap, sqlmap, nikto, wpscan…), clienți HTTP generici neautentificați, căi specifice de scanare, enumerare de utilizatori. |
| **SQL Injection** | Tipare de injecție SQL în query, corp (inclusiv JSON) și cookie-uri. |
| **XSS** | Tipare de cross-site scripting (scripturi, atribute de eveniment, `javascript:`, iframe etc.). |
| **Command Injection** | Tipare de injecție de comenzi (pipe-uri, backtick-uri, `/etc/passwd`, funcții de execuție). |
| **Rate Limit** | IP-uri care depășesc pragul de cereri configurat. |

## Banare

- **Temporar**: durată fixă (implicit din setări) sau din treptele de recidivă.
- **Permanent**: nu expiră, se ridică manual din **Ban List**.
- **Escaladare la recidivă**: durata crește la fiecare abatere, conform listei de trepte; după `permanent_after` abateri devine ban permanent.
- **Pe subnet**: bifează `/24` (IPv4) sau `/64` (IPv6) în orice formular de ban.
- Duratele sunt afișate lizibil: `45s`, `30m`, `5h:37m`, `7z:3h`.

## Raportare

- Tabele live per categorie, cu coloane: Ultima, IP, **Ban**, Hits, Metodă, URI, Cod, User-Agent, Detaliu, Acțiune.
- **Căutare** după IP / URI / User-Agent / detaliu, **filtru** „doar IP-uri banate", **paginare** (50/rând).
- **Export CSV** (UTF-8 cu BOM, pentru Excel) pentru evenimente (cu filtrele curente), banuri și whitelist.
- Toate datele/orele sunt afișate în format `18 oct 2026 19:40:01`, în ora locală a site-ului.

## Setări (Dashboard)

- **Auto-ban la login**: activare, prag încercări eșuate, durată ban, fereastră de numărare.
- **Detectare și blocare**: fișiere sensibile, scanner UA, SQL injection, XSS, command injection; scanarea tuturor suprafețelor (wp-admin / admin-ajax / REST); protecția administratorilor și editorilor.
- **Auto-ban pe evenimente suspecte** și prag separat pentru scanner/probing.
- **Rate limiting**: cereri maxime / fereastră (0 = dezactivat).
- **Recidivă**: activare, trepte de durată, prag pentru ban permanent.
- **Ingestie log Apache**: import automat (cron/minut), auto-ban din log, cale custom către fișierul de log.
- **Raportare**: zile de păstrare, refresh automat al tabelelor.
- Fiecare setare are un **tooltip de ajutor** (iconița „?"), cu explicație de 2–3 fraze.

## Cerințe

- WordPress 5.3+ (folosește `wp_date()`).
- PHP 7.4+ (testat pe PHP 8.3).
- Opțional: acces în citire la logul de acces Apache, pentru ingestie.

## Instalare

1. Copiază folderul `WebGuard2.AI` în `wp-content/plugins/`.
2. Activează pluginul din meniul **Plugins**.
3. Configurează opțiunile din meniul **WebGuard.AI** din panoul de administrare.

## Structură

- `webguard.ai.php` – logica principală (detecție, blocare, ban, rate limiting, ingestie log, pagini de admin).
- `templates/` – paginile de administrare: `dashboard.php`, `events.php`, `banlist.php`, `whitelist.php`.
- `assets/admin.js` – reîmprospătarea live a tabelelor de evenimente.
- `.github/workflows/` – CI: lint PHP la push/PR și Release automat la tag `v*`.

## Date stocate

Două tabele proprii (prefixate cu `base_prefix`), fără opțiuni WordPress pentru date:

- `webguard_ip` – stare IP (`whitelist` / `ban` / `watch` / `rate`), durată/flag ban, număr de ban-uri, contor de cereri pentru rate limiting, precum și rândul rezervat care păstrează setările.
- `webguard_events` – evenimente agregate pe semnătură (categorie, IP, metodă, URI, User-Agent, cod, detaliu, număr de apariții, prima/ultima apariție).

## Licență

GPL-2.0-or-later. Vezi fișierul [LICENSE](LICENSE).
