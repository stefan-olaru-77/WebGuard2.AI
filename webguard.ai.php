<?php
/**
 * Plugin Name: WebGuard.AI
 * Description: Firewall + detectie si raportare locala: ban pe login, auto-ban, si capturarea evenimentelor de tip file-injection, brute-force, scanner-probing si sql-injection. Doua tabele proprii, pagini separate per tip de problema, tabele live in admin.
 * Version: 2026.10.18-events
 * Author: Atelierul de IT
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Requires at least: 5.3
 * Requires PHP: 7.4
 *
 * Doua tabele proprii (base_prefix):
 *   - {base_prefix}webguard_ip     : stare IP (whitelist/ban/watch) + setari (rand rezervat)
 *   - {base_prefix}webguard_events : evenimente suspecte agregate
 *
 * Cloudflare-aware: foloseste IP-ul real al clientului (get_client_ip()).
 */

if (!defined('ABSPATH')) {
    exit;
}

class WebGuardAI {

    const TABLE_IP     = 'webguard_ip';
    const TABLE_EVENTS = 'webguard_events';

    const CONFIG_IP = '';
    const MENU_SLUG = 'webguard-ai';

    // Recognised event categories
    const CATEGORIES = array(
        'file_injection'  => 'File Injection (expunere fisiere)',
        'brute_force'     => 'Brute Force (autentificare)',
        'scanner_probing' => 'Scanner / Probing',
        'sql_injection'   => 'SQL Injection',
    );

    // Pagina de admin corespunzatoare fiecarei categorii (pentru redirect dupa actiuni).
    const CATEGORY_PAGE = array(
        'file_injection'  => 'webguard-events-file',
        'brute_force'     => 'webguard-events-brute',
        'scanner_probing' => 'webguard-events-scanner',
        'sql_injection'   => 'webguard-events-sqli',
    );

    /**
     * Cloudflare published proxy ranges (fallback only, kept in sync with
     * /etc/apache2/conf-enabled/remoteip-cloudflare.conf).
     */
    const CLOUDFLARE_RANGES = array(
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
        '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
        '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
        '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32',
        '2405:b500::/32', '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
    );

    /** Paths that must never be fetched over HTTP (file injection / disclosure). */
    const SENSITIVE_PATTERNS = array(
        '#(^|/)\.env(\.|$|/)#i',
        '#(^|/)\.git(/|$)#i',
        '#(^|/)\.svn(/|$)#i',
        '#(^|/)\.hg(/|$)#i',
        '#(^|/)\.bzr(/|$)#i',
        '#(^|/)\.aws(/|$)#i',
        '#(^|/)\.ssh(/|$)#i',
        '#(^|/)\.idea(/|$)#i',
        '#(^|/)\.vscode(/|$)#i',
        '#(^|/)\.DS_Store$#i',
        '#(^|/)\.htaccess$#i',
        '#(^|/)\.htpasswd$#i',
        '#(^|/)\.user\.ini$#i',
        '#(^|/)php\.ini$#i',
        '#(^|/)wp-config\.#i',
        '#(^|/)debug\.log$#i',
        '#(^|/)(error_log|error\.log)$#i',
        '#(^|/)phpinfo\.php$#i',
        '#(^|/)phpunit\.xml(\.dist)?$#i',
        '#(^|/)composer\.(json|lock)$#i',
        '#(^|/)id_rsa#i',
        '#(^|/)(id_dsa|\.pem|\.key|\.p12|\.pfx|\.netrc|\.npmrc|\.bash_history|\.zsh_history)$#i',
        '#(^|/)(docker-compose\.ya?ml|\.dockerignore|Dockerfile|\.gitlab-ci\.yml|Jenkinsfile)$#i',
        '#\.(sql|sql\.gz|bak|old|orig|save|swp|swo|tar|tgz)$#i',
        '#~$#',
        '#wp-content/uploads/.*\.(php|phtml|phar|php[0-9])$#i',
        // Any hidden path segment (except /.well-known) is treated as a probe.
        '#(^|/)\.(?!well-known(?:/|$))[A-Za-z0-9_\-\.]#i',
    );

    /** Path traversal in any input (path, query, body, cookie). */
    const TRAVERSAL_PATTERN = '#(^|/)\.\.(/|$)|\.\./|%2e%2e#i';

    /** Local/remote file inclusion wrappers and common target files. */
    const LFI_PATTERN = '#((php|data|expect|file|zip|phar|glob|compress\.[a-z0-9]+)://|(etc/passwd|proc/self/environ|windows/win\.ini))#i';

    /** User-Agent signatures of known scanners (intotdeauna suspecte). */
    const SCANNER_UA = array(
        '#zgrab#i', '#nmap#i', '#masscan#i', '#zmap#i', '#sqlmap#i', '#nikto#i',
        '#nuclei#i', '#wpscan#i', '#gobuster#i', '#dirbuster#i', '#wfuzz#i',
        '#dirsearch#i', '#feroxbuster#i', '#ffuf#i', '#dirb#i', '#w3af#i',
        '#arachni#i', '#whatweb#i', '#xray#i', '#hydra#i', '#ZmEu#i', '#Morfeus#i',
        '#netsparker#i', '#acunetix#i',
    );

    /**
     * Clienti HTTP generici: pot fi si integrari/monitorizare legitime, deci
     * sunt semnalati DOAR la cereri fara sesiune WordPress (neautentificat).
     */
    const SOFT_SCANNER_UA = array(
        '#python-requests#i', '#python-urllib#i', '#aiohttp#i',
        '#libwww-perl#i', '#go-http-client#i', '#httpx#i',
    );

    /** Paths commonly probed by automated scanners (whole-site surface). */
    const PROBE_PATHS = array(
        '#^/mcp(/|$)#i', '#^/owa/#i', '#^/phpmyadmin#i', '#^/pma#i', '#^/myadmin#i',
        '#^/cgi-bin/#i', '#/vendor/phpunit/#i', '#^/jenkins#i', '#^/actuator#i',
        '#^/console#i', '#^/solr/#i', '#^/geoserver#i', '#^/hudson#i',
        '#^/(administrator|joomla|typo3|drupal)#i',
        '#^/(server-status|server-info)#i', '#^/(manager/html|host-manager)#i',
        '#^/(install|setup)\.php$#i', '#^/wp-admin/install\.php$#i',
        '#^/wp-json/wp/v2/(?:users(?!/(?:me)(?:/|$|\?))|settings)#i', '#^/xmlrpc\.php$#i',
        '#^/wp-content/plugins/[^/]+/readme\.(txt|md|html?)$#i',
    );

    /** SQL injection signatures (applied to decoded query, body and cookies). */
    const SQLI_PATTERN = '#(union\s+select|select\s+[a-z0-9_,\*\s\.]{1,60}\s+from|insert\s+into|delete\s+from|update\s+[a-z0-9_]{1,40}\s+set|sleep\s*\(|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay|load_file\s*\(|into\s+outfile|into\s+dumpfile|extractvalue\s*\(|updatexml\s*\(|information_schema|@@version|or\s+1\s*=\s*1|or\s+true\b|"\s*or\s*"|\'\s*or\s*\')#i';

    private static $instance = null;

    private $settings = null;
    private $pending_event = null; // [category, detail] to log at shutdown
    private $tables_checked = false;

    public static function instance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        $this->init_hooks();
    }

    /* ---------------------------------------------------------------------
     * Table names / schema
     * ------------------------------------------------------------------- */

    public static function table_ip() {
        global $wpdb;
        return $wpdb->base_prefix . self::TABLE_IP;
    }

    public static function table_events() {
        global $wpdb;
        return $wpdb->base_prefix . self::TABLE_EVENTS;
    }

    /**
     * Create both tables and seed the settings row (idempotent)
     */
    public static function install() {
        global $wpdb;
        $charset = $wpdb->get_charset_collate();

        $ip_table = self::table_ip();
        $sql_ip = "CREATE TABLE {$ip_table} (
            ip varchar(45) NOT NULL DEFAULT '',
            status varchar(12) NOT NULL DEFAULT 'watch',
            attempts smallint(5) unsigned NOT NULL DEFAULT 0,
            window_start bigint(20) unsigned DEFAULT NULL,
            ban_until bigint(20) unsigned DEFAULT NULL,
            ban_permanent tinyint(1) NOT NULL DEFAULT 0,
            ban_count int(10) unsigned NOT NULL DEFAULT 0,
            source varchar(10) NOT NULL DEFAULT 'manual',
            config longtext NULL,
            updated_at bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (ip),
            KEY status (status),
            KEY ban_until (ban_until),
            KEY updated_at (updated_at)
        ) {$charset};";

        $ev_table = self::table_events();
        $sql_ev = "CREATE TABLE {$ev_table} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            sig char(32) NOT NULL DEFAULT '',
            category varchar(20) NOT NULL DEFAULT '',
            ip varchar(45) NOT NULL DEFAULT '',
            method varchar(10) NOT NULL DEFAULT '',
            uri varchar(500) NOT NULL DEFAULT '',
            user_agent varchar(255) NOT NULL DEFAULT '',
            status_code smallint(5) unsigned NOT NULL DEFAULT 0,
            detail varchar(190) NOT NULL DEFAULT '',
            hits int(10) unsigned NOT NULL DEFAULT 1,
            first_seen bigint(20) unsigned NOT NULL DEFAULT 0,
            last_seen bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY sig (sig),
            KEY category_last (category,last_seen),
            KEY ip (ip)
        ) {$charset};";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql_ip);
        dbDelta($sql_ev);

        $defaults = self::default_settings();
        $wpdb->query($wpdb->prepare(
            "INSERT IGNORE INTO {$ip_table} (ip, status, config, updated_at) VALUES (%s, 'config', %s, %d)",
            self::CONFIG_IP, wp_json_encode($defaults), time()
        ));
    }

    private function table_exists($table) {
        global $wpdb;
        return ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) === $table);
    }

    /**
     * Ensure both tables exist (checked at most once per request)
     */
    private function maybe_install() {
        if ($this->tables_checked) {
            return;
        }
        $this->tables_checked = true;

        if (!$this->table_exists(self::table_ip()) || !$this->table_exists(self::table_events())) {
            self::install();
        }
    }

    /* ---------------------------------------------------------------------
     * Settings
     * ------------------------------------------------------------------- */

    private static function default_settings() {
        return array(
            'auto_ban'        => 1,
            'threshold'       => 5,
            'ban_seconds'     => 3600,
            'window'          => 3600,
            'block_sensitive' => 1,
            'block_scanner'   => 0,
            'block_sqli'      => 0,
            'auto_ban_events' => 0,
            'retention_days'  => 30,
            'auto_refresh'    => 1,
            // Recidiva: durata ban-ului creste la fiecare recidiva, apoi permanent.
            'recidive'        => 1,
            'recidive_ladder' => '3600,21600,86400,604800', // 1h, 6h, 24h, 7 zile
            'permanent_after' => 3,                          // a N-a abatere => ban permanent
            // Ingestia log-ului Apache (prinde si cererile blocate la edge, inainte de PHP).
            'log_ingest'      => 1,
            'log_autoban'     => 0,
            // Suprafata site: inspecteaza si wp-admin / admin-ajax / REST, nu doar front-end.
            'scan_all_surfaces' => 1,
            // Niciodata sa nu blocheze/baneze un administrator autentificat (anti-lockout).
            'guard_admins'      => 1,
            // La fel si pentru editorii de continut (roluri cu edit_posts).
            'guard_editors'     => 1,
            // Scanner: ban automat abia dupa N evenimente de scanner (0 = niciodata).
            'scanner_ban_after' => 10,
            // Token secret pentru link-ul de bypass (cookie), util la IP dinamic.
            'bypass_token' => '',
            // Cale custom catre fisierul de log Apache (gol = detectie automata).
            'log_path' => '',
        );
    }

    private function settings() {
        if ($this->settings !== null) {
            return $this->settings;
        }

        global $wpdb;
        $defaults = self::default_settings();

        if (!$this->table_exists(self::table_ip())) {
            $this->settings = $defaults;
            return $this->settings;
        }

        $raw = $wpdb->get_var($wpdb->prepare(
            "SELECT config FROM " . self::table_ip() . " WHERE ip = %s LIMIT 1",
            self::CONFIG_IP
        ));

        $decoded = (is_string($raw) && $raw !== '') ? json_decode($raw, true) : null;
        $this->settings = is_array($decoded) ? array_merge($defaults, $decoded) : $defaults;

        return $this->settings;
    }

    /**
     * Utilizator de incredere (anti-lockout): administrator sau editor de continut.
     * Acestia nu sunt niciodata blocati/banati, doar inregistrati.
     */
    private function is_trusted_user() {
        if (!function_exists('is_user_logged_in') || !is_user_logged_in()) {
            return false;
        }
        $s = $this->settings();
        if (!empty($s['guard_admins']) && current_user_can('manage_options')) {
            return true;
        }
        if (!empty($s['guard_editors']) && current_user_can('edit_posts')) {
            return true;
        }
        return false;
    }

    /* ---------------------------------------------------------------------
     * Bypass pe IP dinamic (cookie secret / link magic)
     * ------------------------------------------------------------------- */

    /** Numele cookie-ului de bypass. */
    private function bypass_cookie_name() {
        return 'wg_pass';
    }

    /** Genereaza token-ul daca lipseste si il persista. Returneaza token-ul. */
    public function ensure_bypass_token() {
        $s = $this->settings();
        if (!empty($s['bypass_token'])) {
            return (string) $s['bypass_token'];
        }
        try {
            $s['bypass_token'] = bin2hex(random_bytes(16));
        } catch (Exception $e) {
            $s['bypass_token'] = wp_generate_password(32, false, false);
        }
        $this->save_config($s);
        return (string) $s['bypass_token'];
    }

    /** Persista configul (randul rezervat ip=''). */
    private function save_config($settings) {
        global $wpdb;
        $this->maybe_install();
        $wpdb->query($wpdb->prepare(
            "INSERT INTO " . self::table_ip() . " (ip, status, config, updated_at) VALUES (%s, 'config', %s, %d)
             ON DUPLICATE KEY UPDATE config = VALUES(config), updated_at = VALUES(updated_at)",
            self::CONFIG_IP, wp_json_encode($settings), time()
        ));
        $this->settings = array_merge(self::default_settings(), $settings);
    }

    /** True daca cererea are cookie-ul secret valid (independent de IP). */
    private function has_bypass() {
        $token = (string) ($this->settings()['bypass_token'] ?? '');
        if ($token === '') {
            return false;
        }
        $cookie = $this->bypass_cookie_name();
        if (empty($_COOKIE[$cookie])) {
            return false;
        }
        return hash_equals(hash('sha256', $token), (string) $_COOKIE[$cookie]);
    }

    /** Exceptat de la blocare/ban: bypass cookie SAU utilizator de incredere. */
    private function is_exempt() {
        return $this->has_bypass() || $this->is_trusted_user();
    }

    /**
     * Link magic: /?webguard_pass=TOKEN seteaza cookie-ul si redirectioneaza.
     * Ruleaza inaintea firewall-ului, deci functioneaza si cand IP-ul e banat.
     */
    public function maybe_handle_bypass_link() {
        if (empty($_GET['webguard_pass'])) {
            return;
        }
        $token = (string) ($this->settings()['bypass_token'] ?? '');
        $given = (string) wp_unslash($_GET['webguard_pass']);
        if ($token === '' || !hash_equals($token, $given)) {
            return;
        }
        if (!headers_sent()) {
            setcookie($this->bypass_cookie_name(), hash('sha256', $token), array(
                'expires'  => time() + YEAR_IN_SECONDS,
                'path'     => '/',
                'domain'   => '',
                'secure'   => is_ssl(),
                'httponly' => true,
                'samesite' => 'Lax',
            ));
            wp_safe_redirect(home_url('/'));
            exit;
        }
    }

    /* ---------------------------------------------------------------------
     * Client IP (Cloudflare-aware)
     * ------------------------------------------------------------------- */

    private function get_client_ip() {
        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim((string) $_SERVER['REMOTE_ADDR']) : '';
        if ($remote === '' || !filter_var($remote, FILTER_VALIDATE_IP)) {
            return '';
        }

        if (self::is_cloudflare_ip($remote)) {
            $forwarded = isset($_SERVER['HTTP_CF_CONNECTING_IP']) ? trim((string) $_SERVER['HTTP_CF_CONNECTING_IP']) : '';
            if (strpos($forwarded, ',') !== false) {
                $parts = explode(',', $forwarded);
                $forwarded = trim($parts[0]);
            }
            if (filter_var($forwarded, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return $forwarded;
            }
            return '';
        }

        return $remote;
    }

    private static function is_cloudflare_ip($ip) {
        foreach (self::CLOUDFLARE_RANGES as $cidr) {
            if (self::ip_in_cidr($ip, $cidr)) {
                return true;
            }
        }
        return false;
    }

    private static function ip_in_cidr($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return ($ip === $cidr);
        }
        list($subnet, $bits) = explode('/', $cidr, 2);
        $bits = (int) $bits;
        $ip_bin = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);
        if ($ip_bin === false || $subnet_bin === false || strlen($ip_bin) !== strlen($subnet_bin)) {
            return false;
        }
        $full = intdiv($bits, 8);
        $rem = $bits % 8;
        if ($full > 0 && substr($ip_bin, 0, $full) !== substr($subnet_bin, 0, $full)) {
            return false;
        }
        if ($rem === 0) {
            return true;
        }
        $mask = (0xFF << (8 - $rem)) & 0xFF;
        return ((ord($ip_bin[$full]) & $mask) === (ord($subnet_bin[$full]) & $mask));
    }

    /* ---------------------------------------------------------------------
     * Hooks
     * ------------------------------------------------------------------- */

    private function init_hooks() {
        add_action('wp_loaded', array($this, 'maybe_handle_bypass_link'), 0);
        add_action('wp_loaded', array($this, 'early_access_check'), 1);
        add_action('wp_loaded', array($this, 'inspect_request'), 5);
        add_action('shutdown', array($this, 'flush_pending_event'), 1);

        add_action('wp_login_failed', array($this, 'handle_failed_login'), 10, 2);
        // Site-level: esecuri de autentificare si prin Application Passwords (REST).
        add_action('application_password_failed_authentication', array($this, 'handle_rest_auth_failure'), 10, 1);

        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'admin_assets'));

        add_action('admin_post_webguard_save_settings', array($this, 'admin_post_save_settings'));
        add_action('admin_post_webguard_add_ip', array($this, 'admin_post_add_ip'));
        add_action('admin_post_webguard_remove_ip', array($this, 'admin_post_remove_ip'));
        add_action('admin_post_webguard_clear_rules', array($this, 'admin_post_clear_rules'));
        add_action('admin_post_webguard_clear_events', array($this, 'admin_post_clear_events'));
        add_action('admin_post_webguard_regen_bypass', array($this, 'admin_post_regen_bypass'));
        add_action('admin_post_webguard_save_log_path', array($this, 'admin_post_save_log_path'));

        add_action('wp_ajax_webguard_events', array($this, 'ajax_get_events'));

        // Ingestia log-ului Apache (cron la minut) + import manual.
        add_filter('cron_schedules', array($this, 'cron_schedules'));
        add_action('init', array($this, 'maybe_schedule_ingest'), 2);
        add_action('webguard_ingest_log', array($this, 'ingest_access_log'));
        add_action('admin_post_webguard_ingest_log', array($this, 'admin_post_ingest_log'));
    }

    public function cron_schedules($schedules) {
        if (!isset($schedules['webguard_minute'])) {
            $schedules['webguard_minute'] = array(
                'interval' => 60,
                'display'  => 'WebGuard: fiecare minut',
            );
        }
        return $schedules;
    }

    /**
     * Programeaza ingestia log-ului daca nu e deja programata (self-heal).
     */
    public function maybe_schedule_ingest() {
        if (!wp_next_scheduled('webguard_ingest_log')) {
            wp_schedule_event(time() + 60, 'webguard_minute', 'webguard_ingest_log');
        }
    }

    /* ---------------------------------------------------------------------
     * Ban firewall (aplicat pe TOT site-ul, nu doar la login)
     * ------------------------------------------------------------------- */

    public function early_access_check() {
        if (wp_doing_cron()) {
            return;
        }
        // Nu ne blocam propriul endpoint AJAX (dashboard-ul).
        if (function_exists('wp_doing_ajax') && wp_doing_ajax()) {
            $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
            if ($action === 'webguard_events' || $action === 'webguard_ingest_log') {
                return;
            }
        }
        // Anti-lockout / bypass: admin, editor sau cookie secret => nu blocam.
        if ($this->is_exempt()) {
            return;
        }
        $ip = $this->get_client_ip();
        if ($ip === '') {
            return;
        }
        $access = $this->check_ip_access($ip);
        if (empty($access['allowed'])) {
            $this->block_access($access['reason']);
        }
    }

    public function check_ip_access($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return array('allowed' => false, 'reason' => 'Invalid IP format');
        }
        global $wpdb;
        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT status, ban_until, ban_permanent FROM " . self::table_ip() . " WHERE ip = %s LIMIT 1",
            $ip
        ), ARRAY_A);

        if (!is_array($row) || empty($row['status'])) {
            return array('allowed' => true, 'reason' => 'No matching rule');
        }
        if ($row['status'] === 'whitelist') {
            return array('allowed' => true, 'reason' => 'Whitelisted');
        }
        if ($row['status'] !== 'ban') {
            return array('allowed' => true, 'reason' => 'Watching');
        }
        if (!empty($row['ban_permanent'])) {
            return array('allowed' => false, 'reason' => 'Permanently banned');
        }
        $ban_until = (int) $row['ban_until'];
        if ($ban_until > time()) {
            return array('allowed' => false, 'reason' => 'Banned until ' . self::format_datetime($ban_until));
        }
        return array('allowed' => true, 'reason' => 'Ban expired');
    }

    private function block_access($reason) {
        error_log('WebGuard.AI blocked access: IP ' . $this->get_client_ip() . ', Reason: ' . $reason);
        // Ban aplicat pe TOT site-ul => 403 (fara redirect, ca sa nu buclam pe home).
        $this->send_forbidden();
    }

    /* ---------------------------------------------------------------------
     * Request inspection (detect & optionally block)
     * ------------------------------------------------------------------- */

    public function inspect_request() {
        if (wp_doing_cron()) {
            return;
        }
        // Do not treat our own AJAX/admin endpoints as suspicious.
        if (function_exists('wp_doing_ajax') && wp_doing_ajax()) {
            $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
            if ($action === 'webguard_events' || $action === 'webguard_ingest_log') {
                return;
            }
        }

        $settings = $this->settings();
        $surface = $this->request_surface();
        if (!$this->should_scan_surface($surface, $settings)) {
            return;
        }

        $event = $this->classify_request();
        if ($event === null) {
            return;
        }

        // Anti-lockout / bypass: admin, editor sau cookie secret => nu blocam.
        $is_exempt = $this->is_exempt();

        if (!$is_exempt && $this->should_block($event[0])) {
            $this->log_event($event[0], $event[1], 403);
            $this->send_forbidden();
            // send_forbidden() exits
        }

        // Log at shutdown so the real status code is captured
        $this->pending_event = $event;
    }

    /**
     * Suprafata cererii curente: front | login | admin | ajax | rest.
     */
    private function request_surface() {
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $query = isset($_SERVER['QUERY_STRING']) ? (string) $_SERVER['QUERY_STRING'] : '';

        if ((defined('REST_REQUEST') && REST_REQUEST)
            || strpos($uri, '/wp-json') !== false
            || strpos($query, 'rest_route=') !== false) {
            return 'rest';
        }
        if (function_exists('wp_doing_ajax') && wp_doing_ajax()) {
            return 'ajax';
        }
        if (function_exists('is_admin') && is_admin()) {
            return 'admin';
        }
        $path = (string) parse_url($uri, PHP_URL_PATH);
        if (strpos($path, 'wp-login') !== false || strpos($path, 'xmlrpc.php') !== false) {
            return 'login';
        }
        return 'front';
    }

    private function should_scan_surface($surface, $settings) {
        if ($surface === 'front' || $surface === 'login' || $surface === 'rest') {
            return true;
        }
        // wp-admin si admin-ajax doar cand e activat scan_all_surfaces.
        return !empty($settings['scan_all_surfaces']);
    }

    public function flush_pending_event() {
        if ($this->pending_event === null) {
            return;
        }
        $event = $this->pending_event;
        $this->pending_event = null;

        $status = function_exists('http_response_code') ? (int) http_response_code() : 0;
        $this->log_event($event[0], $event[1], $status);
    }

    private function send_forbidden() {
        if (!headers_sent()) {
            status_header(403);
            nocache_headers();
            header('Content-Type: text/plain; charset=utf-8');
        }
        echo 'Forbidden';
        exit;
    }

    /**
     * Classify the current request
     * @return array|null  [category, detail]
     */
    private function classify_request() {
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string) $_SERVER['REQUEST_METHOD']) : 'GET';
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $path = (string) parse_url($uri, PHP_URL_PATH);
        if ($path === '') {
            $path = '/';
        }
        $path = rawurldecode($path);

        $query = isset($_SERVER['QUERY_STRING']) ? rawurldecode((string) $_SERVER['QUERY_STRING']) : '';
        $post = (!empty($_POST) && is_array($_POST)) ? $this->flatten_post($_POST, 0) : '';

        // Corp JSON (REST / admin-ajax) - $_POST e gol pentru application/json.
        $content_type = '';
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $content_type = (string) $_SERVER['CONTENT_TYPE'];
        } elseif (isset($_SERVER['HTTP_CONTENT_TYPE'])) {
            $content_type = (string) $_SERVER['HTTP_CONTENT_TYPE'];
        }
        if ($content_type !== '' && stripos($content_type, 'json') !== false
            && in_array($method, array('POST', 'PUT', 'PATCH', 'DELETE'), true)) {
            $raw = @file_get_contents('php://input', false, null, 0, 8192);
            if (is_string($raw) && $raw !== '') {
                $post .= ' ' . $raw;
            }
        }

        $cookies = (!empty($_COOKIE) && is_array($_COOKIE)) ? $this->flatten_post($_COOKIE, 0) : '';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

        $logged_in = function_exists('is_user_logged_in') && is_user_logged_in();
        return $this->classify_values($method, $path, $query, $post, $ua, $cookies, $logged_in);
    }

    /**
     * Classify from raw values (shared by the live request and the log ingestion).
     * @return array|null [category, detail]
     */
    private function classify_values($method, $path, $query, $post, $ua, $cookies = '', $logged_in = false) {
        $method = strtoupper((string) $method);
        $inputs = $query . ' ' . $post . ' ' . $cookies;

        // 0) path traversal / LFI in orice input
        if (preg_match(self::TRAVERSAL_PATTERN, $path) || preg_match(self::TRAVERSAL_PATTERN, $inputs)) {
            return array('file_injection', 'traversal');
        }
        if (preg_match(self::LFI_PATTERN, $path) || preg_match(self::LFI_PATTERN, $inputs)) {
            return array('file_injection', 'lfi');
        }

        // 1) file injection (cale)
        foreach (self::SENSITIVE_PATTERNS as $pattern) {
            if (preg_match($pattern, $path)) {
                return array('file_injection', $path);
            }
        }

        // 2) sql injection (query + body + cookie)
        if (preg_match(self::SQLI_PATTERN, $inputs)) {
            return array('sql_injection', 'input');
        }

        // 3) brute force (xmlrpc)
        if ($method === 'POST' && strpos(strtolower($path), 'xmlrpc.php') !== false) {
            return array('brute_force', 'xmlrpc');
        }

        // 4) scanner probing
        foreach (self::SCANNER_UA as $pattern) {
            if (preg_match($pattern, (string) $ua)) {
                return array('scanner_probing', 'ua');
            }
        }
        // Clienti HTTP generici: doar daca NU exista sesiune WordPress.
        if (!$logged_in) {
            foreach (self::SOFT_SCANNER_UA as $pattern) {
                if (preg_match($pattern, (string) $ua)) {
                    return array('scanner_probing', 'ua-generic');
                }
            }
        }
        foreach (self::PROBE_PATHS as $pattern) {
            if (preg_match($pattern, $path)) {
                return array('scanner_probing', $path);
            }
        }
        if ($query !== '' && preg_match('#(^|&)author=\d+#i', $query)) {
            return array('scanner_probing', 'author-enum');
        }
        // Enumerare useri prin REST, dar NU /wp/v2/users/me (endpoint propriu, legitim).
        if ($query !== '' && strpos($query, 'rest_route=') !== false
            && preg_match('#rest_route=/wp/v2/(?:users(?!/(?:me)(?:/|$|&))|settings)#i', $query)) {
            return array('scanner_probing', 'rest-enum');
        }
        if (preg_match('#/wp-json/wp/v2/(?:users(?!/(?:me)(?:/|$|\?))|settings)#i', $path)) {
            return array('scanner_probing', $path);
        }

        return null;
    }

    private function path_is_sensitive($path) {
        foreach (self::SENSITIVE_PATTERNS as $pattern) {
            if (preg_match($pattern, $path)) {
                return true;
            }
        }
        return false;
    }

    private function flatten_post($data, $depth) {
        if ($depth > 3) {
            return '';
        }
        $out = '';
        foreach ($data as $value) {
            if (is_array($value)) {
                $out .= ' ' . $this->flatten_post($value, $depth + 1);
            } elseif (is_scalar($value)) {
                $out .= ' ' . (string) $value;
            }
            if (strlen($out) > 4000) {
                break;
            }
        }
        return $out;
    }

    private function should_block($category) {
        $s = $this->settings();
        if ($category === 'file_injection') {
            return !empty($s['block_sensitive']);
        }
        if ($category === 'scanner_probing') {
            return !empty($s['block_scanner']);
        }
        if ($category === 'sql_injection') {
            return !empty($s['block_sqli']);
        }
        return false;
    }

    /* ---------------------------------------------------------------------
     * Event logging
     * ------------------------------------------------------------------- */

    public function log_event($category, $detail, $status_code = 0) {
        if (!isset(self::CATEGORIES[$category])) {
            return;
        }
        $ip = $this->get_client_ip();
        if ($ip === '') {
            return;
        }
        $method = isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : 'GET';
        $uri = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '';
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';

        $this->store_event($category, $ip, $method, $uri, $ua, (int) $status_code, $detail);

        if ($category !== 'brute_force') {
            if (!$this->is_exempt()) {
                $this->maybe_autoban_events($ip, $category);
            }
        }
    }

    /**
     * Upsert an aggregated event row (shared by live logging and log ingestion).
     */
    /** True pentru adrese de loopback (127.0.0.0/8 sau ::1). */
    private function is_loopback_ip($ip) {
        if ($ip === '::1') {
            return true;
        }
        return (strpos($ip, '127.') === 0);
    }

    private function store_event($category, $ip, $method, $uri, $ua, $status_code, $detail) {
        if (!isset(self::CATEGORIES[$category]) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            return;
        }
        // Zgomot local (cron, scanuri/teste de pe server): nu logam loopback.
        if ($this->is_loopback_ip($ip)) {
            return;
        }
        $this->maybe_install();

        global $wpdb;
        $now = time();
        $method = substr((string) $method, 0, 10);
        $uri = substr((string) $uri, 0, 500);
        $ua = substr((string) $ua, 0, 255);
        $detail = substr((string) $detail, 0, 190);
        $sig = md5($category . '|' . $ip . '|' . $method . '|' . $uri);

        $wpdb->query($wpdb->prepare(
            "INSERT INTO " . self::table_events() . "
                (sig, category, ip, method, uri, user_agent, status_code, detail, hits, first_seen, last_seen)
             VALUES (%s, %s, %s, %s, %s, %s, %d, %s, 1, %d, %d)
             ON DUPLICATE KEY UPDATE
                hits = hits + 1, last_seen = VALUES(last_seen),
                status_code = VALUES(status_code), user_agent = VALUES(user_agent), detail = VALUES(detail)",
            $sig, $category, $ip, $method, $uri, $ua, (int) $status_code, $detail, $now, $now
        ));
    }

    private function maybe_autoban_events($ip, $category = '') {
        $s = $this->settings();
        // Scanner: prag separat (mai mare) sau dezactivat (0) - nu banam la fel de repede.
        if ($category === 'scanner_probing') {
            $limit = (int) $s['scanner_ban_after'];
        } else {
            $limit = (int) $s['auto_ban_events'];
        }
        if ($limit <= 0) {
            return;
        }
        global $wpdb;
        $window = max(60, (int) $s['window']);
        // Separare: evenimentele de scanner nu contribuie la pragul normal si invers.
        $cat_filter = ($category === 'scanner_probing')
            ? "category = 'scanner_probing'"
            : "category <> 'scanner_probing'";
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- $cat_filter e constant, nu input.
        $total = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COALESCE(SUM(hits),0) FROM " . self::table_events() . " WHERE ip = %s AND {$cat_filter} AND last_seen > %d",
            $ip, time() - $window
        ));
        if ($total >= $limit) {
            $this->ban_ip($ip, (int) $s['ban_seconds'], 'auto', true);
        }
    }

    /* ---------------------------------------------------------------------
     * Failed login / auto-ban
     * ------------------------------------------------------------------- */

    public function handle_failed_login($username = '', $error = null) {
        $this->record_auth_failure(is_string($username) ? $username : '', 'wp-login', 200);
    }

    /**
     * Esec de autentificare prin Application Passwords (REST) - nivel de site.
     */
    public function handle_rest_auth_failure($error = null) {
        $this->record_auth_failure('', 'rest-auth', 401);
    }

    private function record_auth_failure($username, $detail, $status_code) {
        $ip = $this->get_client_ip();
        if ($ip === '') {
            return;
        }

        // Inregistreaza evenimentul brute-force (agregat pe IP).
        $this->log_event('brute_force', $detail, (int) $status_code);

        error_log('WebGuard.AI: Failed auth attempt - IP: ' . $ip . ', user: ' . sanitize_text_field((string) $username));

        $settings = $this->settings();
        if (empty($settings['auto_ban'])) {
            return;
        }
        // Anti-lockout / bypass: nu contoriza/bana un utilizator exceptat.
        if ($this->is_exempt()) {
            return;
        }

        global $wpdb;
        $status = $wpdb->get_var($wpdb->prepare(
            "SELECT status FROM " . self::table_ip() . " WHERE ip = %s LIMIT 1",
            $ip
        ));
        if ($status === 'whitelist') {
            return;
        }

        $this->register_failure($ip, $settings);
    }

    private function register_failure($ip, $settings) {
        global $wpdb;
        $table = self::table_ip();
        $now = time();
        $window = max(60, (int) $settings['window']);
        $threshold = max(1, (int) $settings['threshold']);
        $window_start = $now - $window;

        $wpdb->query($wpdb->prepare(
            "INSERT INTO {$table} (ip, status, attempts, window_start, updated_at)
             VALUES (%s, 'watch', 1, %d, %d)
             ON DUPLICATE KEY UPDATE
               attempts = IF(status = 'watch', IF(window_start IS NULL OR window_start < %d, 1, attempts + 1), attempts),
               window_start = IF(status = 'watch' AND (window_start IS NULL OR window_start < %d), %d, window_start),
               updated_at = %d",
            $ip, $now, $now, $window_start, $window_start, $now, $now
        ));

        $attempts = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT attempts FROM {$table} WHERE ip = %s LIMIT 1",
            $ip
        ));
        if ($attempts >= $threshold) {
            $this->ban_ip($ip, max(0, (int) $settings['ban_seconds']), 'auto', true);
        }
    }

    /* ---------------------------------------------------------------------
     * Manual mutations
     * ------------------------------------------------------------------- */

    private function whitelist_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "INSERT INTO " . self::table_ip() . " (ip, status, ban_until, ban_permanent, updated_at)
             VALUES (%s, 'whitelist', NULL, 0, %d)
             ON DUPLICATE KEY UPDATE
               status = 'whitelist', ban_until = NULL, ban_permanent = 0,
               attempts = 0, window_start = NULL, updated_at = VALUES(updated_at)",
            $ip, time()
        ));
        return true;
    }

    /**
     * Baneaza un IP. $source = 'auto' | 'manual'. $recidive escaladeaza durata si
     * transforma in ban permanent dupa 'permanent_after' abateri.
     */
    private function ban_ip($ip, $seconds, $source = 'manual', $recidive = false) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        $source = ($source === 'auto') ? 'auto' : 'manual';
        global $wpdb;
        $table = self::table_ip();
        $now = time();

        $row = $wpdb->get_row($wpdb->prepare(
            "SELECT status, ban_until, ban_permanent, ban_count FROM {$table} WHERE ip = %s LIMIT 1",
            $ip
        ), ARRAY_A);

        if (is_array($row)) {
            if ($row['status'] === 'whitelist') {
                return false;
            }
            // Deja banat activ => nu re-bana si nu incrementa recidiva.
            if ($row['status'] === 'ban') {
                if (!empty($row['ban_permanent']) || (int) $row['ban_until'] > $now) {
                    return false;
                }
            }
        }

        $ban_count = (is_array($row) && isset($row['ban_count'])) ? (int) $row['ban_count'] : 0;
        $permanent = ((int) $seconds <= 0);

        if (!$permanent && $recidive) {
            $seconds = $this->recidive_duration($ban_count);
        }
        $permanent = ((int) $seconds <= 0);

        if ($permanent) {
            $wpdb->query($wpdb->prepare(
                "INSERT INTO {$table} (ip, status, ban_until, ban_permanent, ban_count, source, attempts, window_start, updated_at)
                 VALUES (%s, 'ban', NULL, 1, 1, %s, 0, NULL, %d)
                 ON DUPLICATE KEY UPDATE
                   status = 'ban', ban_until = NULL, ban_permanent = 1, ban_count = ban_count + 1,
                   source = VALUES(source), attempts = 0, window_start = NULL, updated_at = VALUES(updated_at)",
                $ip, $source, $now
            ));
        } else {
            $wpdb->query($wpdb->prepare(
                "INSERT INTO {$table} (ip, status, ban_until, ban_permanent, ban_count, source, attempts, window_start, updated_at)
                 VALUES (%s, 'ban', %d, 0, 1, %s, 0, NULL, %d)
                 ON DUPLICATE KEY UPDATE
                   status = 'ban', ban_until = VALUES(ban_until), ban_permanent = 0, ban_count = ban_count + 1,
                   source = VALUES(source), attempts = 0, window_start = NULL, updated_at = VALUES(updated_at)",
                $ip, $now + (int) $seconds, $source, $now
            ));
        }
        return true;
    }

    /**
     * Durata pentru recidiva (secunde); 0 = ban permanent.
     */
    private function recidive_duration($prior_bans) {
        $s = $this->settings();
        $permanent_after = max(1, (int) $s['permanent_after']);
        if (($prior_bans + 1) >= $permanent_after) {
            return 0;
        }
        $ladder = array();
        foreach (explode(',', (string) $s['recidive_ladder']) as $part) {
            $v = (int) trim($part);
            if ($v > 0) {
                $ladder[] = $v;
            }
        }
        if (empty($ladder)) {
            return max(60, (int) $s['ban_seconds']);
        }
        $idx = min($prior_bans, count($ladder) - 1);
        return $ladder[$idx];
    }

    private function remove_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "DELETE FROM " . self::table_ip() . " WHERE ip = %s AND ip <> %s",
            $ip, self::CONFIG_IP
        ));
        return true;
    }

    private function cleanup() {
        global $wpdb;
        $now = time();
        $settings = $this->settings();
        $window = max(60, (int) $settings['window']);

        // Ban expirat => status 'expired' (pastram ban_count pentru recidiva).
        $wpdb->query($wpdb->prepare(
            "UPDATE " . self::table_ip() . " SET status = 'expired' WHERE status = 'ban' AND ban_permanent = 0 AND ban_until IS NOT NULL AND ban_until < %d",
            $now
        ));
        $wpdb->query($wpdb->prepare(
            "DELETE FROM " . self::table_ip() . " WHERE status = 'watch' AND updated_at < %d",
            $now - ($window * 4)
        ));

        $days = max(1, (int) $settings['retention_days']);
        $wpdb->query($wpdb->prepare(
            "DELETE FROM " . self::table_events() . " WHERE last_seen < %d",
            $now - ($days * DAY_IN_SECONDS)
        ));
        // Curata istoricul de ban-uri expirate foarte vechi.
        $wpdb->query($wpdb->prepare(
            "DELETE FROM " . self::table_ip() . " WHERE status = 'expired' AND updated_at < %d",
            $now - ($days * DAY_IN_SECONDS)
        ));
    }

    /* ---------------------------------------------------------------------
     * Apache access-log ingestion
     * (prinde cererile oprite la edge, inainte de PHP: *.php inexistente,
     *  fisiere ascunse reale, wp-config/xmlrpc/readme respinse de Apache)
     * ------------------------------------------------------------------- */

    private function log_path() {
        $s = $this->settings();
        $custom = isset($s['log_path']) ? trim((string) $s['log_path']) : '';
        if ($custom !== '') {
            return $custom;
        }
        return $this->auto_log_path();
    }

    /**
     * Calea detectata automat (ISPConfig / Apache), cand nu e setata manual.
     */
    private function auto_log_path() {
        $host = wp_parse_url(home_url(), PHP_URL_HOST);
        $host = preg_replace('/^www\./', '', (string) $host);
        $path = '/var/log/ispconfig/httpd/' . $host . '/access.log';
        if (!file_exists($path)) {
            $alt = '/var/log/apache2/' . $host . '-access.log';
            if (file_exists($alt)) {
                $path = $alt;
            }
        }
        return (string) apply_filters('webguard_access_log_path', $path);
    }

    private function get_log_state() {
        global $wpdb;
        $raw = $wpdb->get_var($wpdb->prepare(
            "SELECT config FROM " . self::table_ip() . " WHERE ip = %s LIMIT 1", self::CONFIG_IP
        ));
        $cfg = (is_string($raw) && $raw !== '') ? json_decode($raw, true) : array();
        if (!is_array($cfg)) {
            $cfg = array();
        }
        return array(
            'file'   => isset($cfg['log_file']) ? (string) $cfg['log_file'] : '',
            'offset' => isset($cfg['log_offset']) ? (int) $cfg['log_offset'] : 0,
        );
    }

    private function set_log_state($file, $offset) {
        global $wpdb;
        $raw = $wpdb->get_var($wpdb->prepare(
            "SELECT config FROM " . self::table_ip() . " WHERE ip = %s LIMIT 1", self::CONFIG_IP
        ));
        $cfg = (is_string($raw) && $raw !== '') ? json_decode($raw, true) : array();
        if (!is_array($cfg)) {
            $cfg = array();
        }
        $cfg['log_file'] = (string) $file;
        $cfg['log_offset'] = (int) $offset;
        $wpdb->query($wpdb->prepare(
            "UPDATE " . self::table_ip() . " SET config = %s, updated_at = %d WHERE ip = %s",
            wp_json_encode($cfg), time(), self::CONFIG_IP
        ));
    }

    /**
     * Citeste liniile noi din log si le transforma in evenimente.
     * @return int numar de evenimente ingerate
     */
    public function ingest_access_log($force = false) {
        $s = $this->settings();
        if (!$force && empty($s['log_ingest'])) {
            return 0;
        }
        $this->maybe_install();

        $path = $this->log_path();
        if ($path === '' || !file_exists($path) || !is_readable($path)) {
            return 0;
        }
        $real = realpath($path);
        if ($real === false) {
            return 0;
        }

        $size = (int) filesize($real);
        $state = $this->get_log_state();
        $offset = ($state['file'] === $real) ? (int) $state['offset'] : 0;
        if ($offset < 0 || $offset > $size) {
            $offset = 0; // rotatie / trunchiere
        }

        $fh = fopen($real, 'r');
        if (!$fh) {
            return 0;
        }
        fseek($fh, $offset);
        $pos = $offset;
        $imported = 0;
        $lines = 0;
        $autoban = !empty($s['log_autoban']);

        while (($line = fgets($fh)) !== false) {
            if (substr($line, -1) !== "\n") {
                break; // linie incompleta (scriere in curs) - o reluam data viitoare
            }
            $pos += strlen($line);
            $lines++;
            $imported += $this->ingest_log_line($line, $autoban);
            if ($lines > 20000) {
                break; // plafon de siguranta
            }
        }
        fclose($fh);

        $this->set_log_state($real, $pos);
        return $imported;
    }

    private function ingest_log_line($line, $autoban) {
        if (!preg_match('#^(\S+) \S+ \S+ \[[^\]]+\] "([A-Z]+) (\S+)(?: [^"]*)?" (\d{3}) \S+(?: "[^"]*" )?"([^"]*)"#', $line, $m)) {
            return 0;
        }
        $ip = $m[1];
        $method = $m[2];
        $uri = $m[3];
        $status = (int) $m[4];
        $ua = $m[5];

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return 0;
        }

        $path = (string) parse_url($uri, PHP_URL_PATH);
        if ($path === '') {
            $path = '/';
        }
        $path = rawurldecode($path);

        // Doar cereri care NU au ajuns la PHP (altfel le prinde logarea live).
        if (!$this->log_line_is_edge($path, $status)) {
            return 0;
        }

        $query = rawurldecode((string) parse_url($uri, PHP_URL_QUERY));
        $event = $this->classify_values($method, $path, $query, '', $ua);
        if ($event === null) {
            return 0;
        }

        $this->store_event($event[0], $ip, $method, $uri, $ua, $status, $event[1]);
        if ($autoban && $event[0] !== 'brute_force') {
            $this->maybe_autoban_events($ip, $event[0]);
        }
        return 1;
    }

    /**
     * True daca cererea a fost oprita de Apache (nu a ajuns la PHP),
     * deci nu e prinsa de logarea live.
     */
    private function log_line_is_edge($path, $status) {
        if ($path === '' || $path === '/') {
            return false;
        }
        $docroot = rtrim(defined('ABSPATH') ? ABSPATH : '', '/');
        $full = $docroot . $path;
        $exists = ($docroot !== '' && (file_exists($full) || is_dir($full)));

        if ($exists) {
            // fisier sensibil existent respins la edge (wp-config, xmlrpc, readme, .htaccess)
            if ((int) $status === 403 && $this->path_is_sensitive($path)) {
                return true;
            }
            return false;
        }
        if (substr($path, -4) === '.php') {
            return true;
        }
        if (preg_match('#^/(wp-content|wp-admin|wp-includes)/#i', $path) && pathinfo($path, PATHINFO_EXTENSION) !== '') {
            return true;
        }
        return false;
    }

    /* ---------------------------------------------------------------------
     * Data accessors
     * ------------------------------------------------------------------- */

    public function get_whitelist_data() {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT ip, updated_at FROM " . self::table_ip() . " WHERE status = 'whitelist' AND ip <> %s ORDER BY updated_at DESC",
            self::CONFIG_IP
        ), ARRAY_A);
        return is_array($rows) ? $rows : array();
    }

    public function get_banlist_data() {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT ip, ban_until, ban_permanent, ban_count, source, updated_at FROM " . self::table_ip() . " WHERE status = 'ban' AND ip <> %s ORDER BY updated_at DESC",
            self::CONFIG_IP
        ), ARRAY_A);
        return is_array($rows) ? $rows : array();
    }

    public function get_failed_data() {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT ip, attempts, updated_at FROM " . self::table_ip() . " WHERE status = 'watch' AND ip <> %s ORDER BY updated_at DESC LIMIT 50",
            self::CONFIG_IP
        ), ARRAY_A);
        return is_array($rows) ? $rows : array();
    }

    private function get_events($category, $limit = 200) {
        global $wpdb;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT ip, method, uri, user_agent, status_code, detail, hits, first_seen, last_seen
             FROM " . self::table_events() . "
             WHERE category = %s ORDER BY last_seen DESC LIMIT %d",
            $category, $limit
        ), ARRAY_A);
        return is_array($rows) ? $rows : array();
    }

    /**
     * Event totals per category (all time + last 24h) in one query
     */
    private function get_event_counts() {
        global $wpdb;
        $since = time() - DAY_IN_SECONDS;
        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT category, COUNT(*) AS total, SUM(last_seen >= %d) AS recent
             FROM " . self::table_events() . " GROUP BY category",
            $since
        ), ARRAY_A);

        $counts = array();
        foreach (array_keys(self::CATEGORIES) as $cat) {
            $counts[$cat] = array('total' => 0, 'recent' => 0);
        }
        if (is_array($rows)) {
            foreach ($rows as $row) {
                if (isset($counts[$row['category']])) {
                    $counts[$row['category']] = array('total' => (int) $row['total'], 'recent' => (int) $row['recent']);
                }
            }
        }
        return $counts;
    }

    /* ---------------------------------------------------------------------
     * Admin menu
     * ------------------------------------------------------------------- */

    public function add_admin_menu() {
        if (!current_user_can('manage_options')) {
            return;
        }
        add_menu_page('WebGuard.AI', 'WebGuard.AI', 'manage_options', self::MENU_SLUG, array($this, 'admin_dashboard'), 'dashicons-shield', 30);
        add_submenu_page(self::MENU_SLUG, 'Dashboard', 'Dashboard', 'manage_options', self::MENU_SLUG, array($this, 'admin_dashboard'));
        add_submenu_page(self::MENU_SLUG, 'Whitelist', 'Whitelist', 'manage_options', 'webguard-whitelist', array($this, 'whitelist_report'));
        add_submenu_page(self::MENU_SLUG, 'Ban List', 'Ban List', 'manage_options', 'webguard-banlist', array($this, 'banlist_report'));
        add_submenu_page(self::MENU_SLUG, 'File Injection', 'File Injection', 'manage_options', 'webguard-events-file', array($this, 'events_file_injection'));
        add_submenu_page(self::MENU_SLUG, 'Brute Force', 'Brute Force', 'manage_options', 'webguard-events-brute', array($this, 'events_brute_force'));
        add_submenu_page(self::MENU_SLUG, 'Scanner / Probing', 'Scanner / Probing', 'manage_options', 'webguard-events-scanner', array($this, 'events_scanner'));
        add_submenu_page(self::MENU_SLUG, 'SQL Injection', 'SQL Injection', 'manage_options', 'webguard-events-sqli', array($this, 'events_sqli'));
    }

    public function admin_assets($hook) {
        if (strpos((string) $hook, 'webguard') === false) {
            return;
        }
        wp_enqueue_script(
            'webguard-admin',
            plugins_url('assets/admin.js', __FILE__),
            array(),
            '2026.10.18',
            true
        );
        wp_localize_script('webguard-admin', 'WebGuardAdmin', array(
            'ajaxUrl'  => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('webguard_events'),
            'interval' => 10000,
        ));
    }

    /* ---------------------------------------------------------------------
     * Admin pages
     * ------------------------------------------------------------------- */

    public function admin_dashboard() {
        if (!current_user_can('manage_options')) {
            wp_die('Access denied', 403);
        }
        $this->maybe_install();
        $this->cleanup();
        $this->ensure_bypass_token();

        $whitelist = $this->get_whitelist_data();
        $banlist = $this->get_banlist_data();

        $stats = array(
            'total_rules' => count($whitelist) + count($banlist),
            'whitelisted' => count($whitelist),
            'banned'      => count($banlist),
            'auto_banned' => 0,
        );
        foreach ($banlist as $rule) {
            if (($rule['source'] ?? '') === 'auto') {
                $stats['auto_banned']++;
            }
        }

        $settings = $this->settings();
        $failed_data = $this->get_failed_data();
        $event_counts = $this->get_event_counts();
        $categories = self::CATEGORIES;

        include plugin_dir_path(__FILE__) . 'templates/dashboard.php';
    }

    public function whitelist_report() {
        if (!current_user_can('manage_options')) {
            wp_die('Access denied', 403);
        }
        $this->maybe_install();
        $whitelist_data = $this->get_whitelist_data();
        include plugin_dir_path(__FILE__) . 'templates/whitelist.php';
    }

    public function banlist_report() {
        if (!current_user_can('manage_options')) {
            wp_die('Access denied', 403);
        }
        $this->maybe_install();
        $this->cleanup();
        $banlist_data = $this->get_banlist_data();
        $current_time = time();
        include plugin_dir_path(__FILE__) . 'templates/banlist.php';
    }

    public function events_file_injection() { $this->render_events_page('file_injection'); }
    public function events_brute_force()    { $this->render_events_page('brute_force'); }
    public function events_scanner()        { $this->render_events_page('scanner_probing'); }
    public function events_sqli()           { $this->render_events_page('sql_injection'); }

    private function render_events_page($category) {
        if (!current_user_can('manage_options')) {
            wp_die('Access denied', 403);
        }
        if (!isset(self::CATEGORIES[$category])) {
            wp_die('Unknown category', 404);
        }

        $this->maybe_install();
        $this->cleanup();

        $rows = $this->get_events($category);
        $category_label = self::CATEGORIES[$category];
        $settings = $this->settings();
        $counts = $this->get_event_counts();

        include plugin_dir_path(__FILE__) . 'templates/events.php';
    }

    /**
     * Render the <tr> rows of an event table (shared by page + AJAX)
     * @param array $rows
     * @return string
     */
    private function render_event_rows($rows, $category = '') {
        $out = '';
        foreach ($rows as $row) {
            $out .= '<tr>';
            $out .= '<td>' . esc_html(self::format_datetime($row['last_seen'])) . '</td>';
            $out .= '<td>' . esc_html($row['ip']) . '</td>';
            $out .= '<td>' . esc_html($row['hits']) . '</td>';
            $out .= '<td>' . esc_html($row['method']) . '</td>';
            $out .= '<td class="wg-uri">' . esc_html($row['uri']) . '</td>';
            $out .= '<td>' . esc_html($row['status_code']) . '</td>';
            $out .= '<td class="wg-ua">' . esc_html($row['user_agent']) . '</td>';
            $out .= '<td>' . esc_html($row['detail']) . '</td>';
            $out .= '<td>' . $this->ban_button($row['ip'], $category) . '</td>';
            $out .= '</tr>';
        }
        if ($out === '') {
            $out = '<tr><td colspan="9"><em>Niciun eveniment inregistrat.</em></td></tr>';
        }
        return $out;
    }

    private function ban_button($ip, $category = '') {
        $url    = esc_url(admin_url('admin-post.php'));
        $return = $this->category_page_url($category);
        // NU folosi _wp_http_referer automat: randurile sunt regenerate si prin
        // admin-ajax.php, iar referer-ul de acolo ar redirectiona pagina spre
        // admin-ajax.php (care raspunde "0"). Trimitem un URL de intoarcere explicit.
        $nonce = wp_nonce_field('webguard_add_ip', '_wpnonce', false, false);
        $temp_seconds = max(0, (int) ($this->settings()['ban_seconds'] ?? 3600));
        $temp_label = 'Ban ' . self::human_duration($temp_seconds);
        return '<form method="post" action="' . $url . '" style="margin:0">'
            . '<input type="hidden" name="action" value="webguard_add_ip">'
            . '<input type="hidden" name="webguard_return" value="' . esc_attr($return) . '">'
            . '<input type="hidden" name="webguard_ip" value="' . esc_attr($ip) . '">'
            . $nonce
            . '<button type="submit" name="webguard_type" value="temporary" class="button button-small">' . esc_html($temp_label) . '</button> '
            . '<button type="submit" name="webguard_type" value="permanent" class="button button-small">Permanent</button>'
            . '</form>';
    }

    /** URL-ul paginii de admin pentru o categorie de evenimente. */
    private function category_page_url($category) {
        $page = isset(self::CATEGORY_PAGE[$category]) ? self::CATEGORY_PAGE[$category] : self::MENU_SLUG;
        return admin_url('admin.php?page=' . $page);
    }

    /** Durata in format scurt ("1h", "6h", "7z", "permanent"). */
    public static function human_duration($seconds) {
        $seconds = (int) $seconds;
        if ($seconds <= 0) {
            return 'permanent';
        }
        if ($seconds >= DAY_IN_SECONDS && $seconds % DAY_IN_SECONDS === 0) {
            return ($seconds / DAY_IN_SECONDS) . 'z';
        }
        if ($seconds >= HOUR_IN_SECONDS && $seconds % HOUR_IN_SECONDS === 0) {
            return ($seconds / HOUR_IN_SECONDS) . 'h';
        }
        if ($seconds >= MINUTE_IN_SECONDS && $seconds % MINUTE_IN_SECONDS === 0) {
            return ($seconds / MINUTE_IN_SECONDS) . 'min';
        }
        return $seconds . 's';
    }

    /* ---------------------------------------------------------------------
     * AJAX: live event tables
     * ------------------------------------------------------------------- */

    public function ajax_get_events() {
        check_ajax_referer('webguard_events', 'nonce');
        if (!current_user_can('manage_options')) {
            wp_send_json_error('forbidden', 403);
        }
        $category = isset($_POST['category']) ? sanitize_key(wp_unslash($_POST['category'])) : '';
        if (!isset(self::CATEGORIES[$category])) {
            wp_send_json_error('bad_category', 400);
        }

        $rows = $this->get_events($category);
        wp_send_json_success(array(
            'html'  => $this->render_event_rows($rows, $category),
            'count' => count($rows),
        ));
    }

    /* ---------------------------------------------------------------------
     * Admin actions
     * ------------------------------------------------------------------- */

    private function verify_admin_request($action) {
        if (!current_user_can('manage_options')) {
            wp_die('Access denied', 403);
        }
        check_admin_referer($action);
    }

    private function sanitize_ladder($value) {
        $out = array();
        foreach (explode(',', (string) wp_unslash($value)) as $part) {
            $v = absint(trim($part));
            if ($v > 0) {
                $out[] = $v;
            }
        }
        return empty($out) ? '3600,21600,86400,604800' : implode(',', $out);
    }

    /**
     * Redirectioneaza inapoi cu un mesaj.
     *
     * @param string $message          Cod de mesaj (vezi message_text()).
     * @param string $explicit_target  URL explicit de intoarcere (validat).
     * @param array  $extra            Argumente suplimentare adaugate in URL.
     */
    private function redirect_back($message, $explicit_target = '', $extra = array()) {
        $target = '';
        if ($explicit_target !== '') {
            $target = wp_validate_redirect($explicit_target, '');
        }
        if ($target === '') {
            $target = wp_get_referer();
            // Rândurile reîncărcate live trimit referer-ul către admin-ajax.php,
            // care ar afișa pagina "0". Îl ignorăm.
            if (!$target || strpos($target, 'admin-ajax.php') !== false) {
                $target = '';
            }
        }
        if (!$target) {
            $target = admin_url('admin.php?page=' . self::MENU_SLUG);
        }
        $target = remove_query_arg(array('wg_msg', 'wg_ip', 'wg_dur'), $target);
        $target = add_query_arg('wg_msg', $message, $target);
        foreach ((array) $extra as $key => $value) {
            $target = add_query_arg($key, $value, $target);
        }
        wp_safe_redirect($target);
        exit;
    }

    public function admin_post_save_settings() {
        $this->verify_admin_request('webguard_save_settings');

        $settings = array(
            'auto_ban'        => isset($_POST['auto_ban']) ? 1 : 0,
            'threshold'       => isset($_POST['threshold']) ? max(1, absint($_POST['threshold'])) : 5,
            'ban_seconds'     => isset($_POST['ban_seconds']) ? max(60, absint($_POST['ban_seconds'])) : 3600,
            'window'          => isset($_POST['window']) ? max(60, absint($_POST['window'])) : 3600,
            'block_sensitive' => isset($_POST['block_sensitive']) ? 1 : 0,
            'block_scanner'   => isset($_POST['block_scanner']) ? 1 : 0,
            'block_sqli'      => isset($_POST['block_sqli']) ? 1 : 0,
            'auto_ban_events' => isset($_POST['auto_ban_events']) ? max(0, absint($_POST['auto_ban_events'])) : 0,
            'retention_days'  => isset($_POST['retention_days']) ? max(1, absint($_POST['retention_days'])) : 30,
            'auto_refresh'    => isset($_POST['auto_refresh']) ? 1 : 0,
            'recidive'        => isset($_POST['recidive']) ? 1 : 0,
            'recidive_ladder' => isset($_POST['recidive_ladder']) ? $this->sanitize_ladder($_POST['recidive_ladder']) : '3600,21600,86400,604800',
            'permanent_after' => isset($_POST['permanent_after']) ? max(1, absint($_POST['permanent_after'])) : 3,
            'log_ingest'      => isset($_POST['log_ingest']) ? 1 : 0,
            'log_autoban'     => isset($_POST['log_autoban']) ? 1 : 0,
            'scan_all_surfaces' => isset($_POST['scan_all_surfaces']) ? 1 : 0,
            'guard_admins'      => isset($_POST['guard_admins']) ? 1 : 0,
            'guard_editors'     => isset($_POST['guard_editors']) ? 1 : 0,
            'scanner_ban_after' => isset($_POST['scanner_ban_after']) ? max(0, absint($_POST['scanner_ban_after'])) : 10,
            // Pastreaza token-ul de bypass existent (nu e in formular).
            'bypass_token'      => (string) ($this->settings()['bypass_token'] ?? ''),
            // Pastreaza calea de log setata separat (nu e in formularul principal).
            'log_path'          => (string) ($this->settings()['log_path'] ?? ''),
        );

        global $wpdb;
        $this->maybe_install();
        $wpdb->query($wpdb->prepare(
            "INSERT INTO " . self::table_ip() . " (ip, status, config, updated_at) VALUES (%s, 'config', %s, %d)
             ON DUPLICATE KEY UPDATE config = VALUES(config), updated_at = VALUES(updated_at)",
            self::CONFIG_IP, wp_json_encode($settings), time()
        ));

        $this->settings = array_merge(self::default_settings(), $settings);
        $this->redirect_back('settings_saved');
    }

    /**
     * Regenereaza token-ul de bypass (invalideaza cookie-urile vechi).
     */
    public function admin_post_regen_bypass() {
        $this->verify_admin_request('webguard_regen_bypass');
        $s = $this->settings();
        try {
            $s['bypass_token'] = bin2hex(random_bytes(16));
        } catch (Exception $e) {
            $s['bypass_token'] = wp_generate_password(32, false, false);
        }
        $this->save_config($s);
        $this->redirect_back('bypass_regenerated');
    }

    /**
     * Salveaza calea custom catre fisierul de log Apache.
     */
    public function admin_post_save_log_path() {
        $this->verify_admin_request('webguard_save_log_path');
        $path = isset($_POST['log_path']) ? trim(sanitize_text_field(wp_unslash($_POST['log_path']))) : '';
        $s = $this->settings();
        $s['log_path'] = $path;
        $this->save_config($s);
        $this->redirect_back('log_path_saved');
    }

    public function admin_post_add_ip() {
        $this->verify_admin_request('webguard_add_ip');

        $ip     = isset($_POST['webguard_ip']) ? sanitize_text_field(wp_unslash($_POST['webguard_ip'])) : '';
        $type   = isset($_POST['webguard_type']) ? sanitize_key(wp_unslash($_POST['webguard_type'])) : 'temporary';
        $return = isset($_POST['webguard_return']) ? esc_url_raw(wp_unslash($_POST['webguard_return'])) : '';
        $default_seconds = max(60, (int) ($this->settings()['ban_seconds'] ?? 3600));
        $seconds = isset($_POST['webguard_seconds']) ? absint($_POST['webguard_seconds']) : $default_seconds;

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->redirect_back('invalid_ip', $return);
        }
        $this->maybe_install();

        if ($type === 'whitelist') {
            $this->whitelist_ip($ip);
            $this->redirect_back('ip_whitelisted', $return, array('wg_ip' => $ip));
        } elseif ($type === 'permanent') {
            $this->ban_ip($ip, 0);
            $this->redirect_back('ip_banned_perm', $return, array('wg_ip' => $ip));
        } else {
            $seconds = ($seconds > 0) ? $seconds : 3600;
            $this->ban_ip($ip, $seconds);
            $this->redirect_back('ip_banned_temp', $return, array('wg_ip' => $ip, 'wg_dur' => self::human_duration($seconds)));
        }
    }

    public function admin_post_remove_ip() {
        $this->verify_admin_request('webguard_remove_ip');
        $ip = isset($_POST['webguard_ip']) ? sanitize_text_field(wp_unslash($_POST['webguard_ip'])) : '';
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $this->remove_ip($ip);
        }
        $this->redirect_back('ip_removed');
    }

    public function admin_post_clear_rules() {
        $this->verify_admin_request('webguard_clear_rules');
        global $wpdb;
        $wpdb->query($wpdb->prepare("DELETE FROM " . self::table_ip() . " WHERE ip <> %s", self::CONFIG_IP));
        $this->redirect_back('rules_cleared');
    }

    public function admin_post_clear_events() {
        $this->verify_admin_request('webguard_clear_events');
        global $wpdb;
        $category = isset($_POST['category']) ? sanitize_key(wp_unslash($_POST['category'])) : '';
        if (isset(self::CATEGORIES[$category])) {
            $wpdb->query($wpdb->prepare("DELETE FROM " . self::table_events() . " WHERE category = %s", $category));
        } else {
            $wpdb->query("DELETE FROM " . self::table_events());
        }
        $this->redirect_back('events_cleared');
    }

    public function admin_post_ingest_log() {
        $this->verify_admin_request('webguard_ingest_log');
        $this->ingest_access_log(true);
        $this->redirect_back('log_imported');
    }

    /* ---------------------------------------------------------------------
     * Admin notices
     * ------------------------------------------------------------------- */

    /**
     * Formateaza un timestamp Unix (UTC) in ora locala a site-ului.
     * Format: "18 oct 2026 19:40:01".
     */
    public static function format_datetime($timestamp) {
        $timestamp = (int) $timestamp;
        if ($timestamp <= 0) {
            return '-';
        }
        $months = array(1 => 'ian', 'feb', 'mar', 'apr', 'mai', 'iun', 'iul', 'aug', 'sep', 'oct', 'noi', 'dec');
        $day = (int) wp_date('j', $timestamp);
        $month = (int) wp_date('n', $timestamp);
        if ($day < 1 || $month < 1 || $month > 12) {
            return '-';
        }
        return $day . ' ' . $months[$month] . ' ' . wp_date('Y H:i:s', $timestamp);
    }

    public static function message_text($code, $ip = '', $dur = '') {
        $ip_html = ($ip !== '') ? '<code>' . esc_html($ip) . '</code>' : 'Adresa IP';
        $map = array(
            'settings_saved' => array('success', 'Setarile au fost salvate.'),
            'ip_added'       => array('success', 'Adresa IP a fost adaugata.'),
            'ip_removed'     => array('success', 'Adresa IP a fost stearsa.'),
            'rules_cleared'  => array('success', 'Toate regulile au fost sterse.'),
            'events_cleared' => array('success', 'Evenimentele au fost sterse.'),
            'log_imported'   => array('success', 'Log-ul Apache a fost importat.'),
            'bypass_regenerated' => array('success', 'Token-ul de bypass a fost regenerat. Cookie-urile vechi nu mai sunt valabile.'),
            'log_path_saved' => array('success', 'Calea catre fisierul de log a fost salvata.'),
            'invalid_ip'     => array('error', 'Adresa IP nu este valida.'),
            'ip_banned_temp' => array('success', sprintf(
                'Ban aplicat: %s este blocata pentru %s. Banul expira automat.',
                $ip_html,
                esc_html($dur !== '' ? $dur : 'durata configurata')
            )),
            'ip_banned_perm' => array('success', sprintf(
                'Ban aplicat: %s este blocata permanent. Nu expira automat; se ridica manual din Ban List.',
                $ip_html
            )),
            'ip_whitelisted' => array('success', sprintf(
                '%s a fost adaugata in whitelist (nu va fi blocata).',
                $ip_html
            )),
        );
        return isset($map[$code]) ? $map[$code] : null;
    }

    public static function render_notice() {
        if (empty($_GET['wg_msg'])) {
            return;
        }
        $code = sanitize_key(wp_unslash($_GET['wg_msg']));
        $ip   = isset($_GET['wg_ip']) ? sanitize_text_field(wp_unslash($_GET['wg_ip'])) : '';
        $dur  = isset($_GET['wg_dur']) ? sanitize_text_field(wp_unslash($_GET['wg_dur'])) : '';
        $message = self::message_text($code, $ip, $dur);
        if ($message === null) {
            return;
        }
        echo '<div class="notice notice-' . esc_attr($message[0]) . ' is-dismissible"><p>'
            . wp_kses_post($message[1]) . '</p></div>';
    }
}

function webguard_ai_activate() {
    if (version_compare(get_bloginfo('version'), '5.0', '<')) {
        deactivate_plugins(plugin_basename(__FILE__));
        wp_die('WebGuard.AI requires WordPress 5.0 or higher.');
    }
    WebGuardAI::install();
    WebGuardAI::instance()->ensure_bypass_token();
}

register_activation_hook(__FILE__, 'webguard_ai_activate');

if (defined('ABSPATH')) {
    WebGuardAI::instance();
}
