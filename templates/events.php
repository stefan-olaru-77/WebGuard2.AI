<?php
/**
 * WebGuard.AI - Events page (one per category)
 *
 * Variables (set by WebGuardAI::render_events_page(), where $this is the plugin):
 * @var string $category
 * @var string $category_label
 * @var array  $rows
 * @var array  $settings
 * @var array  $counts
 */
if (!defined('ABSPATH')) {
    exit;
}

$rows = isset($rows) && is_array($rows) ? $rows : array();
$counts = isset($counts) && is_array($counts) ? $counts : array();
$total = isset($counts[$category]['total']) ? (int) $counts[$category]['total'] : count($rows);
$recent = isset($counts[$category]['recent']) ? (int) $counts[$category]['recent'] : 0;
$auto_refresh = !empty($settings['auto_refresh']);

?>

<div class="wrap">
    <h1><?php echo esc_html($category_label); ?></h1>

    <?php WebGuardAI::render_notice(); ?>

    <div class="webguard-report">
        <div class="report-header">
            <p>
                Total semnaturi: <strong><?php echo esc_html($total); ?></strong>
                &nbsp;|&nbsp; In ultimele 24h: <strong><?php echo esc_html($recent); ?></strong>
                &nbsp;|&nbsp; Randuri afisate: <strong data-count><?php echo esc_html(count($rows)); ?></strong>
                <?php if ($auto_refresh) : ?><span class="wg-live">&#9679; live</span><?php endif; ?>
            </p>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webguard-ai')); ?>" class="button">&larr; Inapoi la Dashboard</a>
        </div>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"
              onsubmit="return confirm('Stergi toate evenimentele din aceasta categorie?');" style="margin-bottom:12px">
            <input type="hidden" name="action" value="webguard_clear_events">
            <input type="hidden" name="category" value="<?php echo esc_attr($category); ?>">
            <?php wp_nonce_field('webguard_clear_events'); ?>
            <button type="submit" class="button button-link-delete">Sterge evenimentele acestei categorii</button>
        </form>

        <table class="wp-list-table widefat fixed striped webguard-events" data-category="<?php echo esc_attr($category); ?>">
            <thead>
                <tr>
                    <th style="width:160px">Ultima</th>
                    <th style="width:130px">IP</th>
                    <th style="width:60px">Hits</th>
                    <th style="width:60px">Metoda</th>
                    <th>URI</th>
                    <th style="width:60px">Cod</th>
                    <th>User-Agent</th>
                    <th>Detaliu</th>
                    <th style="width:70px">Actiune</th>
                </tr>
            </thead>
            <tbody>
                <?php echo $this->render_event_rows($rows, $category); // phpcs:ignore WordPress.Security.EscapeOutput ?>
            </tbody>
        </table>
    </div>
</div>

<style>
    .webguard-report { margin-top: 20px; }
    .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .webguard-events .wg-uri { word-break: break-all; font-family: monospace; font-size: 12px; }
    .webguard-events .wg-ua { word-break: break-all; font-size: 12px; color: #646970; }
    .wg-live { color: #00a32a; font-weight: 600; font-size: 12px; }
</style>
