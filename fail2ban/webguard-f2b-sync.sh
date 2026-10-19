#!/bin/bash
#
# webguard-f2b-sync.sh
# Sincronizeaza jail-ul fail2ban "webguard-ai" cu baza de date a pluginului
# WordPress WebGuard2.AI. Rulat de cron (root) la fiecare minut.
#
# De ce este nevoie: PHP ruleaza ca utilizatorul web si NU poate apela
# fail2ban-client (necesita root). Pluginul scrie banurile intr-un log
# (filtru fail2ban = ban la nivel de kernel), insa ridicarea banului
# (expirare / stergere manuala / whitelist) trebuie facuta de root.
# Acest script aduce fail2ban in acord cu pluginul in ambele directii.
#
# Sursa de adevar: tabelul wp_webguard_ip (status='ban', inca activ).
# Seteaza mai jos calea corecta daca se schimba pluginul / prefixul.

set -u

WP_CONFIG="/var/www/clients/client0/web1/web/wp-config.php"
JAIL="webguard-ai"
F2B="$(command -v fail2ban-client || echo /usr/bin/fail2ban-client)"

[ -r "$WP_CONFIG" ] || { echo "webguard-f2b-sync: nu pot citi $WP_CONFIG" >&2; exit 1; }

# --- extrage credențialele DB din wp-config.php (fara sa incarcam WordPress) ---
dbval() {
    grep -E "define\(\s*['\"]$1['\"]" "$WP_CONFIG" | head -1 \
        | sed -E "s/.*['\"]$1['\"]\s*,\s*['\"]([^'\"]*)['\"].*/\1/"
}

DB_NAME="$(dbval DB_NAME)"
DB_USER="$(dbval DB_USER)"
DB_PASS="$(dbval DB_PASSWORD)"
DB_HOST="$(dbval DB_HOST)"
PREFIX="$(grep -E '^\s*\$table_prefix' "$WP_CONFIG" | head -1 | sed -E "s/.*=\s*['\"]([^'\"]*)['\"].*/\1/")"
PREFIX="${PREFIX:-wp_}"

[ -n "$DB_NAME" ] && [ -n "$DB_USER" ] || { echo "webguard-f2b-sync: lipsesc credențiale DB" >&2; exit 1; }
# localhost -> socket local; elimina portul daca exista
DB_HOST="${DB_HOST%%:*}"

# --- IP-uri banate activ in plugin ---
# status='ban' si (permanent SAU ban_until inca in viitor)
SQL="SELECT ip FROM ${PREFIX}webguard_ip WHERE status='ban' AND (ban_permanent=1 OR ban_until > UNIX_TIMESTAMP());"
PLUGIN_BANS="$(MYSQL_PWD="$DB_PASS" mysql -h "$DB_HOST" -u "$DB_USER" "$DB_NAME" -N -B -e "$SQL" 2>/dev/null)"
MYSQL_RC=$?
if [ $MYSQL_RC -ne 0 ]; then
    echo "webguard-f2b-sync: interogarea MySQL a eșuat (rc=$MYSQL_RC)" >&2
    exit 1
fi

# --- IP-uri banate in fail2ban (parseaza linia "Banned IP list:" din status) ---
F2B_BANS="$($F2B status "$JAIL" 2>/dev/null \
    | sed -n 's/.*Banned IP list:[[:space:]]*//p' \
    | tr ' \t' '\n')"

# Normalizeaza la liste sortate, fara spatii/goale
norm() { printf '%s\n' "$1" | tr -d ' \r' | sed '/^$/d' | sort -u; }
P_NORM="$(norm "$PLUGIN_BANS")"
F_NORM="$(norm "$F2B_BANS")"

changed=0

# 1) Adauga in fail2ban banurile active din plugin care lipsesc
while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    # Subnetele (CIDR) nu pot fi aplicate de setul nftables implicit al
    # fail2ban (lipseste flag-ul interval) -> raman blocate la nivel PHP.
    case "$ip" in */*) continue;; esac
    if ! printf '%s\n' "$F_NORM" | grep -qxF "$ip"; then
        if $F2B set "$JAIL" banip "$ip" >/dev/null 2>&1; then
            echo "webguard-f2b-sync: banat $ip"
            changed=1
        else
            echo "webguard-f2b-sync: nu pot bana $ip in fail2ban, sar" >&2
        fi
    fi
done <<< "$P_NORM"

# 2) Ridica din fail2ban banurile care nu mai sunt active in plugin
while IFS= read -r ip; do
    [ -n "$ip" ] || continue
    if ! printf '%s\n' "$P_NORM" | grep -qxF "$ip"; then
        if $F2B set "$JAIL" unbanip "$ip" >/dev/null 2>&1; then
            echo "webguard-f2b-sync: debanat $ip"
            changed=1
        fi
    fi
done <<< "$F_NORM"

[ $changed -eq 0 ] && exit 0
exit 0
