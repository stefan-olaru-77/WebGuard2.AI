# WebGuard.AI

Plugin WordPress de securitate: firewall de aplicație + detectare și raportare locală a atacurilor. Blochează la nivel de site și ține evidența evenimentelor de tip **file-injection**, **brute-force**, **scanner-probing**, **SQL-injection**, **XSS**, **command-injection** și **rate-limit**.

## Ce face

- Detectează **7 categorii** de atacuri (vezi mai jos) și blochează cererile periculoase cu **HTTP 403** pe **tot site-ul**: front-end, `wp-admin`, `admin-ajax.php` și REST.
- **Ban pe IP** cu **escaladare la recidivă** (trepte configurabile) și **ban permanent** după N abateri.
- **Ban pe subnet**: opțiune de a bloca tot intervalul (`/24` la IPv4, `/64` la IPv6), util pentru scanere distribuite.
- **Rate limiting per IP**: ban automat când un IP depășește un prag de cereri într-o fereastră de timp (ex. 240 cereri / 60 s).
- **Widget în panoul de control WordPress** (`wp-admin/index.php`) cu statusul pe scurt: evenimente pe categorii, reguli/whitelist/banuri, top IP-uri (24h) și link rapid către plugin.
- **Whitelist / Ban List** și **tabele live** în admin (refresh la 10 secunde).
- **Căutare, filtrare și paginare** în tabelele de evenimente; **Export CSV** pentru evenimente, banuri și whitelist.
- Coloană **Ban** în toate tabelele cu IP-uri (mai puțin Ban List), care arată dacă IP-ul e banat: `Permanent`, `Temporar 5h:37m` sau `Subnet ...`.
- **Import din logul Apache** — prinde și cererile oprite la nivel de server, înainte de PHP.
- **Blocare la nivel de kernel prin fail2ban**: pluginul scrie banurile într-un log dedicat; un jail fail2ban le aplică în **nftables**, astfel încât cererea nu mai ajunge la Apache și **nu mai apare în loguri**.
- **Blocare la nivel de Apache (`.htaccess`)**: pluginul scrie IP-urile banate într-un bloc gestionat din `.htaccess`, iar Apache le refuză înainte de PHP. Nu necesită root, dar Apache loghează în continuare cererea (403).
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
- **Integrare fail2ban**: trimite banurile într-un **director de loguri dedicat**, nepublic, citit de fail2ban (blocare la nivel de kernel); directorul poate fi lăsat la alegerea automată sau setat explicit.
- **Blocare la nivel de Apache**: scrie banurile într-un bloc gestionat din `.htaccess`, refuzat de Apache înainte de PHP.
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

## Blocare la nivel de kernel (fail2ban) — opțional

Pluginul funcționează complet **fără** fail2ban: blochează cererile în PHP cu **HTTP 403**. Diferența este că, în acest caz, cererea a ajuns deja la Apache și apare în log. Pentru a opri traficul **înainte** de Apache (fără să mai apară în loguri), se poate integra cu **fail2ban**.

Pluginul **nu are nevoie de privilegii**: rulează ca orice plugin WordPress și doar scrie un fișier de log. Partea de root (instalarea fail2ban, o dată) este responsabilitatea administratorului serverului. Sunt două moduri:

### 1. Mod simplu (recomandat, portabil — fără script de root)

1. Pluginul scrie fiecare ban într-un fișier de log, în formatul
   `<data ISO> BAN <ip> <secunde>` (respectiv `UNBAN <ip>`).
2. Un filtru fail2ban recunoaște liniile `BAN`, iar un jail aplică blocarea în **nftables** pe porturile `http,https`.
3. fail2ban își gestionează **singur** durata: banul expiră automat, iar recidiviștii primesc durate din ce în ce mai mari (`bantime.increment`). Nu e nevoie de nimic care să ruleze cu root în afara fail2ban.

Instalare (o singură dată, ca `root`), folosind fișierele din acest repo:

```bash
# 1. Filtrul si jail-ul
install -D -m 0644 fail2ban/filter.d/webguard-ai.conf /etc/fail2ban/filter.d/webguard-ai.conf
install -D -m 0644 fail2ban/jail.d/webguard-ai.conf   /etc/fail2ban/jail.d/webguard-ai.conf
#    editeaza "logpath" in jail cu calea afisata de plugin in Dashboard

# 2. Validare + reincarcare
fail2ban-client -t
fail2ban-client reload
```

Apoi, în **Dashboard → Integrare fail2ban**, bifează „Trimite banurile la fail2ban". Pluginul scrie logurile într-un **director dedicat**, nu direct într-un fișier împrăștiat prin instalare. Lasă câmpul „Director pentru loguri" gol pentru alegerea automată: pluginul preferă un director **din afara document root-ului** (deci nepublic), de exemplu directorul de log al contului (`log/webguard`) sau folderul privat, și îl creează cu permisiuni restrictive. Dacă ajunge totuși sub document root, îl protejează automat cu `.htaccess`, `index.php` și `web.config`. Calea completă a fișierului este afișată sub câmp și trebuie trecută la `logpath` în jail.

### 2. Mod exact (opțional, necesită root)

Dacă vrei ca durata banului la nivel de kernel să fie **exact** cea decisă de plugin (trepte de recidivă, ban permanent) și ca **ștergerea/whitelist-ul să ridice banul instant**, se folosește o a doua componentă:

- jail-ul se setează pe `bantime = -1` (comentariile din fișierul de jail arată cum);
- scriptul `fail2ban/webguard-f2b-sync.sh` se instalează și se rulează din **cron (root), la fiecare minut**. El aduce fail2ban în acord cu baza de date a pluginului în ambele direcții: ridică banurile expirate/șterse/whitelisted și adaugă cele active lipsă. **Pluginul rămâne sursa de adevăr.**

```bash
install -m 0700 fail2ban/webguard-f2b-sync.sh /root/webguard-f2b-sync.sh
( crontab -l; echo '* * * * * flock -n /tmp/webguard-f2b-sync.lock /root/webguard-f2b-sync.sh >> /var/log/webguard-f2b-sync.log 2>&1' ) | crontab -
```

Calea către `wp-config.php` se poate da prin variabila de mediu `WEBGUARD_WP_CONFIG`.

### Note

- **Subnetele** (`/24`, `/64`) rămân blocate la nivel PHP — setul nftables implicit al fail2ban nu acceptă prefixe.
- Dacă situl este în spatele unui CDN/proxy (ex. Cloudflare), blocarea în kernel oprește doar traficul care ajunge direct la origine; traficul servit de CDN are nevoie de reguli la nivel de edge.
- Pe gazduirile partajate fără `sudo`, folosește **doar modul simplu**.

## Blocare la nivel de Apache (`.htaccess`) — fără root

Pluginul poate scrie IP-urile banate direct în `.htaccess`-ul din document root, iar Apache le refuză **înainte de PHP**. WordPress nu mai rulează pentru ele, deci consumul scade. Nu necesită root: `.htaccess` este deținut de utilizatorul PHP.

Se activează din **Dashboard → Blocare la nivel de Apache (.htaccess)**. Pluginul întreține un bloc delimitat de markeri, pe care îl rescrie **atomic** (fișier temporar + rename):

```apache
# BEGIN WebGuard.AI deny (gestionat automat - nu edita intre markeri)
<RequireAll>
    Require all granted
    Require not ip 1.2.3.4 5.6.7.8 2001:db8::/32
</RequireAll>
# END WebGuard.AI deny
```

- Include IPv4, IPv6 și subneturi (CIDR).
- Loopback-ul (`127.0.0.0/8`, `::1`) este exclus mereu, ca să nu rupă cron-ul.
- Blocul este actualizat la fiecare ban/unban/whitelist și, în plus, printr-un cron la minut (pentru expirări și dacă `.htaccess` este rescris de altcineva).
- Necesită `AllowOverride All` (sau cel puțin `AuthConfig`) pe document root.
- Lista este limitată la 1000 de intrări; peste asta, `.htaccess` devine lent (se parsează la fiecare cerere).

**Important:** Apache **loghează în continuare** cererea refuzată (403). Deci `.htaccess` oprește PHP-ul, dar **nu** elimină linia din access log. Pentru „să nu mai apară deloc în loguri" este nevoie de blocare în kernel (fail2ban) sau la CDN.

**Anti-lockout:** blocarea în `.htaccess` se aplică înainte de PHP, deci link-ul de bypass cu cookie **nu poate** salva un IP aflat în listă. Administratorii nu sunt banați automat (protecția din setări), iar IP-urile din whitelist nu sunt incluse. Dacă îți blochezi din greșeală IP-ul, șterge manual blocul dintre markeri din `.htaccess` (sau dezactivează opțiunea și salvează setările de pe alt IP).

## Structură

- `webguard.ai.php` – logica principală (detecție, blocare, ban, rate limiting, ingestie log, pagini de admin).
- `templates/` – paginile de administrare: `dashboard.php`, `events.php`, `banlist.php`, `whitelist.php`.
- `assets/admin.js` – reîmprospătarea live a tabelelor de evenimente.
- `fail2ban/` – filtrul, jail-ul și scriptul de sincronizare pentru blocarea la nivel de kernel.
- `.github/workflows/` – CI: lint PHP la push/PR și Release automat la tag `v*`.

## Date stocate

Două tabele proprii (prefixate cu `base_prefix`), fără opțiuni WordPress pentru date:

- `webguard_ip` – stare IP (`whitelist` / `ban` / `watch` / `rate`), durată/flag ban, număr de ban-uri, contor de cereri pentru rate limiting, precum și rândul rezervat care păstrează setările.
- `webguard_events` – evenimente agregate pe semnătură (categorie, IP, metodă, URI, User-Agent, cod, detaliu, număr de apariții, prima/ultima apariție).

## Licență

GPL-2.0-or-later. Vezi fișierul [LICENSE](LICENSE).
