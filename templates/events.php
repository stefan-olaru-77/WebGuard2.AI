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
 * @var string $search
 * @var string $filter
 * @var int    $pages
 * @var int    $paged
 * @var int    $filtered_total
 */
if (!defined('ABSPATH')) {
    exit;
}

$rows = isset($rows) && is_array($rows) ? $rows : array();
$counts = isset($counts) && is_array($counts) ? $counts : array();
$total = isset($counts[$category]['total']) ? (int) $counts[$category]['total'] : count($rows);
$recent = isset($counts[$category]['recent']) ? (int) $counts[$category]['recent'] : 0;
$auto_refresh = !empty($settings['auto_refresh']);

$search = isset($search) ? (string) $search : '';
$filter = isset($filter) ? (string) $filter : '';
$pages  = isset($pages) ? (int) $pages : 1;
$paged  = isset($paged) && (int) $paged > 0 ? (int) $paged : 1;
$filtered_total = isset($filtered_total) ? (int) $filtered_total : $total;

$category_page = isset(WebGuardAI::CATEGORY_PAGE[$category]) ? WebGuardAI::CATEGORY_PAGE[$category] : 'webguard-ai';
$base_url = admin_url('admin.php?page=' . $category_page);

$list_args = array();
if ($search !== '') {
    $list_args['wg_q'] = $search;
}
if ($filter !== '') {
    $list_args['wg_f'] = $filter;
}
$list_url = $list_args ? add_query_arg($list_args, $base_url) : $base_url;
$export_url = add_query_arg(
    array('action' => 'webguard_export', 'what' => 'events', 'category' => $category, 'wg_q' => $search, 'wg_f' => $filter),
    admin_url('admin-post.php')
);
$export_url = wp_nonce_url($export_url, 'webguard_export');

$active_filter = ($search !== '' || $filter !== '');
?>
<div class="wrap">
    <h1><?php echo esc_html($category_label); ?></h1>

    <?php WebGuardAI::render_notice(); ?>

    <div class="webguard-report">
        <div class="report-header">
            <p>
                Total semnaturi: <strong><?php echo esc_html($total); ?></strong>
                &nbsp;|&nbsp; In ultimele 24h: <strong><?php echo esc_html($recent); ?></strong>
                &nbsp;|&nbsp; Rezultate: <strong><?php echo esc_html($filtered_total); ?></strong>
                &nbsp;|&nbsp; Afisate: <strong data-count><?php echo esc_html(count($rows)); ?></strong>
                <?php if ($auto_refresh) : ?><span class="wg-live">&#9679; live</span><?php endif; ?>
            </p>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webguard-ai')); ?>" class="button">&larr; Inapoi la Dashboard</a>
        </div>

        <form method="get" action="<?php echo esc_url(admin_url('admin.php')); ?>" class="wg-toolbar">
            <input type="hidden" name="page" value="<?php echo esc_attr($category_page); ?>">
            <input type="search" name="wg_q" value="<?php echo esc_attr($search); ?>" class="regular-text"
                   placeholder="Cauta dupa IP, URI, User-Agent sau detaliu">
            <select name="wg_f">
                <option value="" <?php selected($filter, ''); ?>>Toate</option>
                <option value="banned" <?php selected($filter, 'banned'); ?>>Doar IP-uri banate</option>
            </select>
            <button type="submit" class="button">Cauta</button>
            <?php if ($active_filter) : ?>
                <a href="<?php echo esc_url($base_url); ?>" class="button">Reseteaza</a>
            <?php endif; ?>
            <a href="<?php echo esc_url($export_url); ?>" class="button">Export CSV</a>
        </form>

        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>"
              onsubmit="return confirm('Stergi toate evenimentele din aceasta categorie?');" style="margin-bottom:12px">
            <input type="hidden" name="action" value="webguard_clear_events">
            <input type="hidden" name="category" value="<?php echo esc_attr($category); ?>">
            <?php wp_nonce_field('webguard_clear_events'); ?>
            <button type="submit" class="button button-link-delete">Sterge evenimentele acestei categorii</button>
        </form>

        <table class="wp-list-table widefat fixed striped webguard-events"
               data-category="<?php echo esc_attr($category); ?>"
               data-search="<?php echo esc_attr($search); ?>"
               data-filter="<?php echo esc_attr($filter); ?>"
               data-paged="<?php echo esc_attr($paged); ?>">
            <thead>
                <tr>
                    <th style="width:160px">Ultima</th>
                    <th style="width:130px">IP</th>
                    <th style="width:110px">Ban</th>
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

        <?php if ($pages > 1) : ?>
            <div class="tablenav"><div class="tablenav-pages">
                <?php
                $wg_links = array();
                if ($paged > 1) {
                    $wg_links[] = '<a class="button" href="' . esc_url(add_query_arg('wg_p', $paged - 1, $list_url)) . '">&laquo;</a>';
                }
                $wg_start = max(1, $paged - 2);
                $wg_end = min($pages, $wg_start + 4);
                for ($wg_i = $wg_start; $wg_i <= $wg_end; $wg_i++) {
                    if ($wg_i === $paged) {
                        $wg_links[] = '<span class="button button-primary" aria-current="page">' . (int) $wg_i . '</span>';
                    } else {
                        $wg_links[] = '<a class="button" href="' . esc_url(add_query_arg('wg_p', $wg_i, $list_url)) . '">' . (int) $wg_i . '</a>';
                    }
                }
                if ($paged < $pages) {
                    $wg_links[] = '<a class="button" href="' . esc_url(add_query_arg('wg_p', $paged + 1, $list_url)) . '">&raquo;</a>';
                }
                echo implode(' ', $wg_links); // phpcs:ignore WordPress.Security.EscapeOutput -- HTML construit local.
                ?>
            </div></div>
        <?php endif; ?>
    </div>
</div>

<style>
    .webguard-report { margin-top: 20px; }
    .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
    .wg-toolbar { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
    .webguard-events .wg-uri { word-break: break-all; font-family: monospace; font-size: 12px; }
    .webguard-events .wg-ua { word-break: break-all; font-size: 12px; color: #646970; }
    .wg-live { color: #00a32a; font-weight: 600; font-size: 12px; }
</style>
