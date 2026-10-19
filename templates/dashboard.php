<?php
/**
 * WebGuard.AI - Dashboard
 *
 * Variables (set by WebGuardAI::admin_dashboard()):
 * @var array $stats        total_rules, whitelisted, banned, auto_banned
 * @var array $settings
 * @var array $failed_data
 * @var array $event_counts  category => ['total'=>, 'recent'=>]
 * @var array $categories    category slug => label
 */
if (!defined('ABSPATH')) {
    exit;
}

$stats = isset($stats) && is_array($stats) ? $stats : array();
$settings = isset($settings) && is_array($settings) ? $settings : array();
$failed_data = isset($failed_data) && is_array($failed_data) ? $failed_data : array();
$event_counts = isset($event_counts) && is_array($event_counts) ? $event_counts : array();
$categories = isset($categories) && is_array($categories) ? $categories : array();

$event_pages = array(
    'file_injection'  => 'webguard-events-file',
    'brute_force'     => 'webguard-events-brute',
    'scanner_probing' => 'webguard-events-scanner',
    'sql_injection'   => 'webguard-events-sqli',
    'xss'             => 'webguard-events-xss',
    'command_injection' => 'webguard-events-cmd',
    'rate_limit'      => 'webguard-events-rate',
);

/**
 * Iconita de ajutor cu tooltip la hover/focus.
 */
$wg_help = function ($text) {
    echo '<span class="wg-help" tabindex="0" role="button" aria-label="Ajutor"><span class="wg-help-mark">?</span><span class="wg-help-text">' . esc_html($text) . '</span></span>';
};

?>

<div class="wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php WebGuardAI::render_notice(); ?>

    <h2>Evenimente detectate</h2>
    <div class="webguard-stats">
        <?php foreach ($categories as $slug => $label) : ?>
            <?php
            $total = isset($event_counts[$slug]['total']) ? (int) $event_counts[$slug]['total'] : 0;
            $recent = isset($event_counts[$slug]['recent']) ? (int) $event_counts[$slug]['recent'] : 0;
            $page = isset($event_pages[$slug]) ? $event_pages[$slug] : 'webguard-ai';
            ?>
            <a class="stat-box stat-link" href="<?php echo esc_url(admin_url('admin.php?page=' . $page)); ?>">
                <h3><?php echo esc_html($label); ?></h3>
                <span class="stat-number"><?php echo esc_html($total); ?></span>
                <span class="stat-sub"><?php echo esc_html($recent); ?> in 24h</span>
            </a>
        <?php endforeach; ?>
    </div>

    <h2>Stare firewall login</h2>
    <div class="webguard-stats">
        <div class="stat-box">
            <h3>Total reguli</h3>
            <span class="stat-number"><?php echo esc_html($stats['total_rules'] ?? 0); ?></span>
        </div>
        <div class="stat-box">
            <h3>IP-uri in whitelist</h3>
            <span class="stat-number"><?php echo esc_html($stats['whitelisted'] ?? 0); ?></span>
        </div>
        <div class="stat-box">
            <h3>IP-uri banate</h3>
            <span class="stat-number"><?php echo esc_html($stats['banned'] ?? 0); ?></span>
        </div>
        <div class="stat-box">
            <h3>Ban-uri automate</h3>
            <span class="stat-number"><?php echo esc_html($stats['auto_banned'] ?? 0); ?></span>
        </div>
    </div>

    <p class="webguard-links">
        <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=webguard-whitelist')); ?>">Vezi whitelist</a>
        <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=webguard-banlist')); ?>">Vezi ban list</a>
    </p>

    <h2>Setari</h2>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="webguard_save_settings">
        <?php wp_nonce_field('webguard_save_settings'); ?>

        <h3>Auto-ban la login</h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">Auto-ban activ<?php $wg_help('Activează banarea automată a adreselor IP care acumulează prea multe încercări de autentificare eșuate. Când pragul este atins, IP-ul este blocat pe toată durata configurată. Dezactivează opțiunea dacă preferi să blochezi manual.'); ?></th>
                <td>
                    <label><input type="checkbox" name="auto_ban" value="1" <?php checked(!empty($settings['auto_ban'])); ?>>
                        Activeaza banarea automata dupa incercari de login esuate</label>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-threshold">Prag incercari esuate</label><?php $wg_help('Numărul de încercări de login eșuate de la aceeași adresă IP care declanșează banarea. Se numără doar eșecurile din fereastra de timp de mai jos. O valoare mai mică este mai strictă, dar poate bana utilizatori care greșesc parola.'); ?></th>
                <td><input type="number" min="1" step="1" id="webguard-threshold" name="threshold"
                        value="<?php echo esc_attr($settings['threshold'] ?? 5); ?>" class="small-text"></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-ban-seconds">Durata ban (secunde)</label><?php $wg_help('Durata, în secunde, pentru care un IP rămâne blocat după un ban automat sau manual. După expirare, IP-ul poate accesa din nou site-ul. De exemplu, 3600 înseamnă o oră, iar 86400 o zi.'); ?></th>
                <td><input type="number" min="60" step="60" id="webguard-ban-seconds" name="ban_seconds"
                        value="<?php echo esc_attr($settings['ban_seconds'] ?? 3600); ?>" class="regular-text">
                    <p class="description">Ex: 3600 = 1 ora, 86400 = 24 ore.</p></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-window">Fereastra de numarare (secunde)</label><?php $wg_help('Intervalul de timp, în secunde, în care se numără încercările de login eșuate. Eșecurile mai vechi decât această fereastră nu mai contează la atingerea pragului. Astfel eviți cumularea greșelilor vechi cu cele recente.'); ?></th>
                <td><input type="number" min="60" step="60" id="webguard-window" name="window"
                        value="<?php echo esc_attr($settings['window'] ?? 3600); ?>" class="regular-text"></td>
            </tr>
        </table>

        <h3>Detectie si blocare</h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">Blocheaza fisiere sensibile<?php $wg_help('Răspunde cu eroarea 403 cererilor care vizează fișiere sensibile, precum .env, wp-config.php, .git sau fișiere de backup. Aceste fișiere nu ar trebui să fie accesibile public. Blocarea lor oprește tentativele de a citi date confidențiale.'); ?></th>
                <td><label><input type="checkbox" name="block_sensitive" value="1" <?php checked(!empty($settings['block_sensitive'])); ?>>
                    Raspunde 403 la cereri catre .env, .git, wp-config.php, debug.log etc.</label></td>
            </tr>
            <tr>
                <th scope="row">Blocheaza scanner UA<?php $wg_help('Răspunde cu 403 cererilor al căror User-Agent aparține unor unelte de scanare cunoscute, ca zgrab, nmap sau sqlmap. Astfel sunt oprite automatizările care caută vulnerabilități. Dezactivează opțiunea dacă folosești astfel de unelte în mod legitim.'); ?></th>
                <td><label><input type="checkbox" name="block_scanner" value="1" <?php checked(!empty($settings['block_scanner'])); ?>>
                    Raspunde 403 la User-Agent de scanner (zgrab, nmap, sqlmap...)</label></td>
            </tr>
            <tr>
                <th scope="row">Blocheaza SQL injection<?php $wg_help('Răspunde cu 403 cererilor care conțin tipare specifice de injecție SQL în parametri. Acestea încearcă să manipuleze interogările bazei de date. Este o protecție suplimentară, nu un înlocuitor pentru cod scris corect.'); ?></th>
                <td><label><input type="checkbox" name="block_sqli" value="1" <?php checked(!empty($settings['block_sqli'])); ?>>
                    Raspunde 403 la pattern-uri de SQLi in parametri</label></td>
            </tr>
            <tr>
                <th scope="row">Blocheaza XSS<?php $wg_help('Răspunde cu 403 cererilor care conțin tipare de cross-site scripting (scripturi injectate, atribute de eveniment precum onerror, javascript: sau iframe). Previne executarea de cod în browserul vizitatorilor. Dezactivează dacă observi fals-pozitive pe formulare cu text tehnic.'); ?></th>
                <td><label><input type="checkbox" name="block_xss" value="1" <?php checked(!empty($settings['block_xss'])); ?>>
                    Raspunde 403 la pattern-uri de XSS in parametri</label></td>
            </tr>
            <tr>
                <th scope="row">Blocheaza command injection<?php $wg_help('Răspunde cu 403 cererilor care conțin tipare de injecție de comenzi (pipe-uri către cat, wget, bash, backtick-uri sau căi precum /etc/passwd). Împiedică executarea de comenzi pe server. Este o protecție suplimentară, ține-o activă dacă nu folosești astfel de parametri în mod legitim.'); ?></th>
                <td><label><input type="checkbox" name="block_cmd" value="1" <?php checked(!empty($settings['block_cmd'])); ?>>
                    Raspunde 403 la pattern-uri de command injection</label></td>
            </tr>
            <tr>
                <th scope="row">Toate suprafețele site-ului<?php $wg_help('Extinde inspecția și la wp-admin, admin-ajax.php și punctele REST (/wp-json/), nu doar la partea publică a site-ului. Astfel sunt acoperite toate suprafețele expuse. Poate genera mai multe evenimente, dar oferă protecție completă.'); ?></th>
                <td><label><input type="checkbox" name="scan_all_surfaces" value="1" <?php checked(!empty($settings['scan_all_surfaces'])); ?>>
                    Inspecteaza si wp-admin, admin-ajax.php si REST (/wp-json/), nu doar front-end</label></td>
            </tr>
            <tr>
                <th scope="row">Protejeaza administratorii<?php $wg_help('Nu blochează și nu banează niciodată un administrator autentificat, indiferent de adresa IP. Previne situația în care te excluzi singur din wp-admin. Este recomandat să rămână activată.'); ?></th>
                <td><label><input type="checkbox" name="guard_admins" value="1" <?php checked(!empty($settings['guard_admins'])); ?>>
                    Nu bloca/bana niciodata un administrator autentificat (anti-lockout)</label></td>
            </tr>
            <tr>
                <th scope="row">Protejeaza editorii<?php $wg_help('Nu blochează utilizatorii care pot edita conținut (roluri cu permisiunea edit_posts). Astfel se evită fals-pozitivele atunci când un articol conține text asemănător comenzilor SQL. Protejează redactorii și autorii de blocări accidentale.'); ?></th>
                <td><label><input type="checkbox" name="guard_editors" value="1" <?php checked(!empty($settings['guard_editors'])); ?>>
                    Nu bloca/bana utilizatorii care editeaza continut (roluri cu edit_posts) - evita fals-pozitive pe articole cu text SQL-like</label></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-auto-ban-events">Auto-ban pe evenimente suspecte</label><?php $wg_help('Banează automat un IP după un anumit număr de evenimente suspecte întâlnite în fereastra configurată. Se aplică tuturor categoriilor, cu excepția celei de scanare. Valoarea 0 dezactivează această funcție.'); ?></th>
                <td><input type="number" min="0" step="1" id="webguard-auto-ban-events" name="auto_ban_events"
                        value="<?php echo esc_attr($settings['auto_ban_events'] ?? 0); ?>" class="small-text">
                    <p class="description">Baneaza un IP dupa atatea evenimente suspecte in fereastra de mai sus. 0 = dezactivat.</p></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-scanner-ban-after">Auto-ban doar pentru scanner dupa</label><?php $wg_help('Stabilește după câte evenimente de tip scanner sau probing se aplică banul automat. Categoria este tratată mai blând decât brute-force sau injecția SQL, pentru că poate include trafic legitim. Valoarea 0 înseamnă că nu se banează niciodată pentru scanare.'); ?></th>
                <td><input type="number" min="0" step="1" id="webguard-scanner-ban-after" name="scanner_ban_after"
                        value="<?php echo esc_attr($settings['scanner_ban_after'] ?? 10); ?>" class="small-text">
                    <p class="description">Categoria scanner/probing baneaza abia dupa atatea evenimente (mai blând decat brute-force/SQLi). 0 = niciodata.</p></td>
            </tr>
        </table>

        <h3>Rate limiting (trafic excesiv)</h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><label for="webguard-rate-max">Cereri maxime intr-o fereastra</label><?php $wg_help('Numărul maxim de cereri acceptate de la aceeași adresă IP într-o fereastră de timp. Când este depășit, IP-ul este banat automat. Valoarea 0 dezactivează rate limiting-ul complet. Recomandat 120-240 pentru un site normal.'); ?></th>
                <td><input type="number" min="0" step="1" id="webguard-rate-max" name="rate_max"
                        value="<?php echo esc_attr($settings['rate_max'] ?? 0); ?>" class="small-text">
                    <p class="description">0 = dezactivat. Ex: 240 cereri / 60 secunde.</p></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-rate-window">Fereastra rate limiting (secunde)</label><?php $wg_help('Intervalul de timp, în secunde, în care se numără cererile de la un IP pentru rate limiting. Când fereastra expiră, contorul repornește de la zero. De obicei 60 de secunde este suficient.'); ?></th>
                <td><input type="number" min="10" step="10" id="webguard-rate-window" name="rate_window"
                        value="<?php echo esc_attr($settings['rate_window'] ?? 60); ?>" class="small-text">
                    <p class="description">Durata ferestrei de numarare, in secunde.</p></td>
            </tr>
        </table>

        <h3>Raportare</h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><label for="webguard-retention">Pastreaza evenimentele (zile)</label><?php $wg_help('Numărul de zile cât sunt păstrate evenimentele înregistrate. După acest interval, înregistrările vechi sunt șterse automat. O perioadă mai lungă consumă mai mult spațiu în baza de date.'); ?></th>
                <td><input type="number" min="1" step="1" id="webguard-retention" name="retention_days"
                        value="<?php echo esc_attr($settings['retention_days'] ?? 30); ?>" class="small-text"></td>
            </tr>
            <tr>
                <th scope="row">Tabele live<?php $wg_help('Reîmprospătează automat tabelele cu evenimente la fiecare 10 secunde, fără a reîncărca pagina. Astfel vezi în timp real activitatea suspectă. Dezactivează opțiunea dacă preferi încărcarea manuală.'); ?></th>
                <td><label><input type="checkbox" name="auto_refresh" value="1" <?php checked(!empty($settings['auto_refresh'])); ?>>
                    Reimprospateaza automat tabelele de evenimente (la 10s)</label></td>
            </tr>
        </table>

        <h3>Recidiva (escaladare ban)</h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">Recidiva activa<?php $wg_help('Crește durata banului la fiecare abatere repetată a aceluiași IP. Cei care revin sunt blocați tot mai mult. Duratele se iau din lista de trepte de mai jos.'); ?></th>
                <td><label><input type="checkbox" name="recidive" value="1" <?php checked(!empty($settings['recidive'])); ?>>
                    Durata ban-ului creste la fiecare recidiva</label></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-ladder">Trepte ban (secunde, separate prin virgula)</label><?php $wg_help('Lista duratelor de ban, în secunde, separate prin virgulă, aplicate pe rând la fiecare recidivă. De exemplu, 3600,21600,86400,604800 înseamnă o oră, șase ore, o zi și o săptămână. După epuizarea treptelor se aplică banul permanent.'); ?></th>
                <td><input type="text" id="webguard-ladder" name="recidive_ladder"
                        value="<?php echo esc_attr($settings['recidive_ladder'] ?? '3600,21600,86400,604800'); ?>" class="regular-text">
                    <p class="description">Ex: 3600,21600,86400,604800 = 1h, 6h, 24h, 7 zile.</p></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-permanent-after">Ban permanent dupa N abateri</label><?php $wg_help('A N-a abatere a unui IP devine ban permanent, fără expirare. Numărarea începe de la prima sancțiune înregistrată. O valoare mai mică este mai severă.'); ?></th>
                <td><input type="number" min="1" step="1" id="webguard-permanent-after" name="permanent_after"
                        value="<?php echo esc_attr($settings['permanent_after'] ?? 3); ?>" class="small-text">
                    <p class="description">A N-a abatere a unui IP devine ban permanent.</p></td>
            </tr>
        </table>

        <h3>Ingestie log Apache</h3>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">Import automat (cron/minut)<?php $wg_help('Citește automat logul de acces Apache și înregistrează cererile care au fost oprite înainte de a ajunge la PHP. Astfel vezi și atacurile blocate la nivel de server. Importul rulează o dată pe minut, prin cron.'); ?></th>
                <td><label><input type="checkbox" name="log_ingest" value="1" <?php checked(!empty($settings['log_ingest'])); ?>>
                    Citeste log-ul de acces si inregistreaza cererile oprite de Apache (inainte de PHP)</label></td>
            </tr>
            <tr>
                <th scope="row">Auto-ban din log<?php $wg_help('Aplică banarea automată și asupra evenimentelor importate din logul Apache, nu doar asupra celor detectate în timp real. Extinde protecția la traficul oprit la nivel de server. Necesită ca importul automat să fie activat.'); ?></th>
                <td><label><input type="checkbox" name="log_autoban" value="1" <?php checked(!empty($settings['log_autoban'])); ?>>
                    Aplica auto-ban si pe evenimentele importate din log</label></td>
            </tr>
        </table>

        <h3>Integrare fail2ban</h3>
        <p>Cand pluginul baneaza un IP, scrie o linie intr-un fisier de log. fail2ban citeste acel fisier
            si blocheaza IP-ul la nivel de kernel (nftables/iptables), astfel incat cererea sa nu mai ajunga
            deloc la Apache &mdash; deci sa nu mai apara in loguri. Pluginul rămâne sursa de adevar
            (whitelist, recidiva, dashboard).</p>
        <table class="form-table" role="presentation">
            <tr>
                <th scope="row">Trimite banurile la fail2ban<?php $wg_help('Când este activ, fiecare ban (automat sau manual) este scris într-un fișier de log pe care fail2ban îl citește și aplică blocarea la nivel de kernel. Astfel cererea nu mai ajunge la Apache și nu mai apare în loguri. Dezactivează dacă nu ai un jail fail2ban configurat pentru acest fișier.'); ?></th>
                <td><label><input type="checkbox" name="fail2ban_enabled" value="1" <?php checked(!empty($settings['fail2ban_enabled'])); ?>>
                    Scrie banurile in logul citit de fail2ban</label>
                    <p class="description">Cere un jail fail2ban configurat pentru fisierul de mai jos (vezi README).</p></td>
            </tr>
            <tr>
                <th scope="row"><label for="webguard-f2b-log">Fisier de log pentru fail2ban</label><?php $wg_help('Calea fișierului în care pluginul scrie liniile de ban citite de fail2ban. Lasă gol pentru calea aleasă automat: pluginul folosește primul folder scriibil dintre folderul privat al contului, uploads WordPress și directorul temporar. Fișierul trebuie să fie scriibil de PHP și citibil de fail2ban (root).'); ?></th>
                <td><input type="text" id="webguard-f2b-log" name="fail2ban_log" class="large-text code"
                        value="<?php echo esc_attr($settings['fail2ban_log'] ?? ''); ?>"
                        placeholder="<?php echo esc_attr($this->fail2ban_log_path()); ?>">
                    <p class="description">Gol = <code><?php echo esc_html($this->fail2ban_log_path()); ?></code></p></td>
            </tr>
        </table>

        <?php submit_button('Salveaza setarile'); ?>
    </form>

    <?php $wg_token = (string) ($settings['bypass_token'] ?? ''); ?>
    <h2>Acces de urgenta (IP dinamic / PPPoE)</h2>
    <p>Daca folosesti un IP care se schimba la reconectare (PPPoE), nu-l pune in whitelist.
        Foloseste link-ul de mai jos: il deschizi o singura data per browser si seteaza un cookie secret
        care te scuteste de blocare/ban indiferent de IP. Nu partasi link-ul.</p>
    <?php if ($wg_token !== '') : ?>
        <p><code><?php echo esc_html(home_url('/?webguard_pass=' . $wg_token)); ?></code></p>
    <?php else : ?>
        <p><em>Token-ul nu este inca generat - reincarca pagina.</em></p>
    <?php endif; ?>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="webguard_regen_bypass">
        <?php wp_nonce_field('webguard_regen_bypass'); ?>
        <button type="submit" class="button">Regenereaza token-ul</button>
    </form>

    <?php
    $wg_log_path = $this->log_path();
    $wg_auto_path = $this->auto_log_path();
    $wg_log_state = $this->get_log_state();
    $wg_log_ok = ($wg_log_path !== '' && is_readable($wg_log_path));
    $wg_open_basedir = (string) ini_get('open_basedir');
    ?>
    <h2>Import manual din log</h2>
    <p>Fisier folosit: <code><?php echo esc_html($wg_log_path !== '' ? $wg_log_path : '(negasit)'); ?></code>
        &nbsp;|&nbsp; citit pana la: <strong><?php echo esc_html(number_format((int) $wg_log_state['offset'])); ?></strong> bytes
        &nbsp;|&nbsp; <strong style="color:<?php echo $wg_log_ok ? '#00a32a' : '#d63638'; ?>"><?php echo esc_html($wg_log_ok ? 'lizibil' : 'NU se poate citi'); ?></strong></p>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="webguard_save_log_path">
        <?php wp_nonce_field('webguard_save_log_path'); ?>
        <label for="webguard-log-path">Cale fisier log:</label><?php $wg_help('Calea către fișierul de log Apache pe care îl citește pluginul. Lasă gol pentru detectarea automată în funcție de configurația ISPConfig. Fișierul trebuie să fie citibil de PHP, altfel importul nu funcționează.'); ?>
        <input type="text" id="webguard-log-path" name="log_path" class="large-text code"
               value="<?php echo esc_attr($settings['log_path'] ?? ''); ?>"
               placeholder="<?php echo esc_attr($wg_auto_path); ?>">
        <p class="description">Lasa gol pentru detectie automata (<?php echo esc_html($wg_auto_path); ?>).</p>
        <button type="submit" class="button">Salveaza calea</button>
    </form>
    <?php if (!$wg_log_ok) : ?>
        <div class="notice notice-warning inline"><p>
            PHP nu poate citi acest fisier. Cauza uzuala este <code>open_basedir</code>:
            <?php if ($wg_open_basedir !== '') : ?>
                <br>Curent: <code><?php echo esc_html($wg_open_basedir); ?></code>
            <?php else : ?>
                (neactivat)
            <?php endif; ?>
            <br>Daca fisierul nu e sub una dintre aceste cai, adauga directorul lui la
            <em>Site &rarr; <?php echo esc_html((string) wp_parse_url(home_url(), PHP_URL_HOST)); ?> &rarr; PHP &rarr; open_basedir</em> in ISPConfig.
        </p></div>
    <?php endif; ?>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <input type="hidden" name="action" value="webguard_ingest_log">
        <?php wp_nonce_field('webguard_ingest_log'); ?>
        <button type="submit" class="button">Importa acum din log</button>
    </form>

    <h2>Incercari de login esuate recente</h2>
    <?php if (empty($failed_data)) : ?>
        <div class="notice notice-info inline"><p>Nu exista incercari inregistrate in acest moment.</p></div>
    <?php else : ?>
        <table class="wp-list-table widefat fixed striped">
            <thead><tr><th>IP</th><th>Ban</th><th>Incercari</th><th>Ultima incercare</th><th>Actiune</th></tr></thead>
            <tbody>
                <?php $wg_ban_map = $this->get_ban_status_map(wp_list_pluck($failed_data, 'ip')); ?>
                <?php foreach ($failed_data as $row) : ?>
                    <tr>
                        <td><?php echo esc_html($row['ip']); ?></td>
                        <td><?php echo $this->ban_badge($row['ip'], $wg_ban_map); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                        <td><?php echo esc_html($row['attempts']); ?></td>
                        <td><?php echo esc_html(!empty($row['updated_at']) ? WebGuardAI::format_datetime($row['updated_at']) : '-'); ?></td>
                        <td>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="webguard_add_ip">
                                <input type="hidden" name="webguard_return" value="<?php echo esc_url(admin_url('admin.php?page=webguard-ai')); ?>">
                                <input type="hidden" name="webguard_ip" value="<?php echo esc_attr($row['ip']); ?>">
                                <input type="hidden" name="webguard_type" value="permanent">
                                <?php wp_nonce_field('webguard_add_ip', '_wpnonce', false); ?>
                                <button type="submit" class="button button-small">Ban permanent</button>
                                <label style="margin-left:6px;font-size:11px"><input type="checkbox" name="webguard_subnet" value="1"> /24</label>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>

    <h2>Zona periculoasa</h2>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"
          onsubmit="return confirm('Stergi toate regulile (whitelist + ban)? Actiunea nu poate fi anulata.');">
        <input type="hidden" name="action" value="webguard_clear_rules">
        <?php wp_nonce_field('webguard_clear_rules'); ?>
        <button type="submit" class="button button-link-delete">Sterge toate regulile</button>
    </form>
</div>

<style>
    .webguard-stats { display: flex; gap: 20px; flex-wrap: wrap; margin: 16px 0; }
    .webguard-stats .stat-box {
        background: #fff; border: 1px solid #ccd0d4; border-radius: 4px;
        padding: 16px 24px; min-width: 150px; text-align: center; box-shadow: 0 1px 1px rgba(0,0,0,.04);
    }
    .webguard-stats a.stat-link { text-decoration: none; color: inherit; }
    .webguard-stats a.stat-link:hover { border-color: #2271b1; }
    .webguard-stats .stat-box h3 { margin: 0 0 8px; font-size: 12px; color: #646970; }
    .webguard-stats .stat-number { font-size: 26px; font-weight: 600; color: #1d2327; display: block; }
    .webguard-stats .stat-sub { font-size: 11px; color: #646970; }
    .webguard-links { margin: 16px 0; }
    .webguard-dashboard form { margin-bottom: 8px; }
    .webguard-dashboard h3 { margin: 20px 0 0; }
    /* Iconita de ajutor cu tooltip */
    .wg-help { position: relative; display: inline-flex; align-items: center; margin-left: 6px; vertical-align: middle; }
    .wg-help-mark {
        display: inline-flex; align-items: center; justify-content: center;
        width: 16px; height: 16px; border-radius: 50%; background: #2271b1; color: #fff;
        font-size: 11px; font-weight: 700; line-height: 1; cursor: help; user-select: none;
    }
    .wg-help-mark:hover, .wg-help:focus .wg-help-mark { background: #135e96; }
    .wg-help-text {
        position: absolute; left: 50%; bottom: 135%; transform: translateX(-50%);
        width: 300px; max-width: 72vw; background: #1d2327; color: #fff;
        padding: 9px 11px; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,.25);
        font-size: 12px; font-weight: 400; line-height: 1.5; text-align: left;
        white-space: normal; opacity: 0; visibility: hidden; transition: opacity .15s ease; z-index: 100000;
    }
    .wg-help-text::after {
        content: ""; position: absolute; top: 100%; left: 50%; margin-left: -5px;
        border: 5px solid transparent; border-top-color: #1d2327;
    }
    .wg-help:hover .wg-help-text, .wg-help:focus .wg-help-text { opacity: 1; visibility: visible; }
</style>
