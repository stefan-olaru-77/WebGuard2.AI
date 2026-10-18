/* WebGuard.AI - live refresh for the event tables (admin). */
(function () {
    if (!window.WebGuardAdmin || !window.fetch) {
        return;
    }

    var cfg = window.WebGuardAdmin;
    var tables = document.querySelectorAll('table.webguard-events[data-category]');
    if (!tables.length) {
        return;
    }

    function refresh(table) {
        var category = table.getAttribute('data-category');
        if (!category) {
            return;
        }

        var search = table.getAttribute('data-search') || '';
        var filter = table.getAttribute('data-filter') || '';
        var paged = table.getAttribute('data-paged') || '1';

        var body = 'action=webguard_events'
            + '&nonce=' + encodeURIComponent(cfg.nonce)
            + '&category=' + encodeURIComponent(category)
            + '&search=' + encodeURIComponent(search)
            + '&filter=' + encodeURIComponent(filter)
            + '&paged=' + encodeURIComponent(paged);

        window.fetch(cfg.ajaxUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
        }).then(function (response) {
            return response.json();
        }).then(function (result) {
            if (!result || !result.success || !result.data || typeof result.data.html !== 'string') {
                return;
            }
            var tbody = table.querySelector('tbody');
            if (tbody) {
                tbody.innerHTML = result.data.html;
            }
            var counter = document.querySelector('[data-count]');
            if (counter && typeof result.data.count !== 'undefined') {
                counter.textContent = result.data.count;
            }
        }).catch(function () {
            /* ignore transient errors */
        });
    }

    var interval = parseInt(cfg.interval, 10);
    if (isNaN(interval) || interval < 3000) {
        interval = 10000;
    }

    tables.forEach(function (table) {
        window.setInterval(function () {
            refresh(table);
        }, interval);
    });
})();
