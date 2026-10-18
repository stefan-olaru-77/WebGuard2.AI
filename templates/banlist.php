<?php
/**
 * WebGuard.AI - Ban List
 *
 * Expected variables (set by WebGuardAI::banlist_report()):
 * @var array $banlist_data  rows with ip, ban_until, ban_permanent, ban_count, source, updated_at
 * @var int   $current_time
 */
if (!defined('ABSPATH')) {
    exit;
}

$banlist_data = isset($banlist_data) && is_array($banlist_data) ? $banlist_data : array();
$current_time = isset($current_time) ? (int) $current_time : time();

?>

<div class="wrap">
    <h1>WebGuard.AI - Ban List</h1>

    <?php WebGuardAI::render_notice(); ?>

    <div class="webguard-report">
        <div class="report-header">
            <p>Total IP-uri banate: <strong><?php echo esc_html(count($banlist_data)); ?></strong></p>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webguard-ai')); ?>" class="button">&larr; Inapoi la Dashboard</a>
        </div>

        <h2>Adauga un ban manual</h2>
        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
            <input type="hidden" name="action" value="webguard_add_ip">
            <input type="hidden" name="webguard_return" value="<?php echo esc_url(admin_url('admin.php?page=webguard-banlist')); ?>">
            <?php wp_nonce_field('webguard_add_ip', '_wpnonce', false); ?>
            <input type="text" name="webguard_ip" class="regular-text" placeholder="ex: 203.0.113.10" required>
            <select name="webguard_type">
                <option value="temporary">Temporar</option>
                <option value="permanent">Permanent</option>
            </select>
            <input type="number" min="60" step="60" name="webguard_seconds" value="3600" class="small-text">
            <span class="description">secunde</span>
            <button type="submit" class="button button-primary">Adauga ban</button>
        </form>

        <hr>

        <?php if (empty($banlist_data)) : ?>
            <div class="notice notice-info"><p>Nu exista IP-uri banate.</p></div>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th>Adresa IP</th>
                        <th>Tip</th>
                        <th>Sursa</th>
                        <th>Expira</th>
                        <th>Stare</th>
                        <th>Nr. ban-uri</th>
                        <th>Actiune</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($banlist_data as $entry) : ?>
                        <?php
                        $permanent = !empty($entry['ban_permanent']);
                        $ban_until = isset($entry['ban_until']) ? (int) $entry['ban_until'] : 0;

                        if ($permanent) {
                            $end_display = 'Niciodata';
                            $status = 'Activ';
                            $status_class = 'status-banned';
                        } else {
                            if ($ban_until > 0) {
                                $end_display = WebGuardAI::format_datetime($ban_until);
                                if ($current_time >= $ban_until) {
                                    $status = 'Expirat';
                                    $status_class = 'status-expired';
                                } else {
                                    $status = 'Activ';
                                    $status_class = 'status-banned';
                                }
                            } else {
                                $end_display = 'Nesetat';
                                $status = 'Activ';
                                $status_class = 'status-banned';
                            }
                        }

                        $source = (isset($entry['source']) && $entry['source'] === 'auto') ? 'Automat' : 'Manual';
                        $ban_count = isset($entry['ban_count']) ? (int) $entry['ban_count'] : 0;
                        ?>
                        <tr>
                            <td><?php echo esc_html($entry['ip']); ?></td>
                            <td><?php echo esc_html($permanent ? 'Permanent' : 'Temporar'); ?></td>
                            <td><?php echo esc_html($source); ?></td>
                            <td><?php echo esc_html($end_display); ?></td>
                            <td><span class="<?php echo esc_attr($status_class); ?>"><?php echo esc_html($status); ?></span></td>
                            <td><?php echo esc_html($ban_count); ?></td>
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
    .status-banned { color: #d63384; font-weight: bold; }
    .status-expired { color: #6c757d; font-weight: bold; }
    .webguard-report form { display: inline-block; }
</style>
