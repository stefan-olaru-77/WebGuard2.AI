<?php
/**
 * WebGuard.AI - Whitelist
 *
 * Expected variables (set by WebGuardAI::whitelist_report()):
 * @var array $whitelist_data  rows with ip, updated_at
 */
if (!defined('ABSPATH')) {
    exit;
}

$whitelist_data = isset($whitelist_data) && is_array($whitelist_data) ? $whitelist_data : array();

?>

<div class="wrap">
    <h1>WebGuard.AI - Whitelist</h1>

    <?php WebGuardAI::render_notice(); ?>

    <div class="webguard-report">
        <div class="report-header">
            <p>Total IP-uri in whitelist: <strong><?php echo esc_html(count($whitelist_data)); ?></strong></p>
            <a href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=webguard_export&what=whitelist'), 'webguard_export')); ?>" class="button">Export CSV</a>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webguard-ai')); ?>" class="button">&larr; Inapoi la Dashboard</a>
        </div>

        <h2>Adauga un IP in whitelist</h2>
        <p class="description">IP-urile din whitelist nu sunt niciodata banate (nici manual, nici automat).</p>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="webguard_add_ip">
            <input type="hidden" name="webguard_return" value="<?php echo esc_url(admin_url('admin.php?page=webguard-whitelist')); ?>">
            <input type="hidden" name="webguard_type" value="whitelist">
            <?php wp_nonce_field('webguard_add_ip', '_wpnonce', false); ?>
            <input type="text" name="webguard_ip" class="regular-text" placeholder="ex: 203.0.113.10" required>
            <button type="submit" class="button button-primary">Adauga in whitelist</button>
        </form>

        <hr>

        <?php if (empty($whitelist_data)) : ?>
            <div class="notice notice-info"><p>Nu exista IP-uri in whitelist.</p></div>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Adresa IP</th>
                        <th>Ban</th>
                        <th>Adaugat la</th>
                        <th>Stare</th>
                        <th>Actiune</th>
                    </tr>
                </thead>
                <tbody>
                <?php $wg_ban_map = $this->get_ban_status_map(wp_list_pluck($whitelist_data, 'ip')); ?>
                <?php foreach ($whitelist_data as $entry) : ?>
                    <tr>
                        <td><?php echo esc_html($entry['ip']); ?></td>
                        <td><?php echo $this->ban_badge($entry['ip'], $wg_ban_map); // phpcs:ignore WordPress.Security.EscapeOutput ?></td>
                        <td><?php echo esc_html(!empty($entry['updated_at']) ? WebGuardAI::format_datetime($entry['updated_at']) : '-'); ?></td>
                        <td><span class="status-whitelist">Whitelisted</span></td>
                        <td>
                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                                <input type="hidden" name="action" value="webguard_remove_ip">
                                <input type="hidden" name="webguard_ip" value="<?php echo esc_attr($entry['ip']); ?>">
                                <?php wp_nonce_field('webguard_remove_ip'); ?>
                                <button type="submit" class="button button-small">Sterge</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</div>

<style>
    .webguard-report { margin-top: 20px; }
    .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .status-whitelist { color: #007cba; font-weight: bold; }
    .webguard-report form { display: inline-block; }
</style>
