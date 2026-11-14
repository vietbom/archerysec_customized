(function () {
    'use strict';
    var tabs = Array.from(document.querySelectorAll('.scan-tabs [role="tab"]'));
    function selectTab(tab) {
        tabs.forEach(function (item) {
            var selected = item === tab;
            item.setAttribute('aria-selected', String(selected));
            item.tabIndex = selected ? 0 : -1;
            document.getElementById(item.getAttribute('aria-controls')).hidden = !selected;
        });
    }
    tabs.forEach(function (tab, index) {
        tab.addEventListener('click', function () { selectTab(tab); });
        tab.addEventListener('keydown', function (event) {
            var next;
            if (event.key === 'ArrowRight') next = tabs[(index + 1) % tabs.length];
            if (event.key === 'ArrowLeft') next = tabs[(index + tabs.length - 1) % tabs.length];
            if (event.key === 'Home') next = tabs[0];
            if (event.key === 'End') next = tabs[tabs.length - 1];
            if (next) { event.preventDefault(); selectTab(next); next.focus(); }
        });
    });
    if (tabs.length) selectTab(tabs[0]);
    document.querySelectorAll('.scan-panel table').forEach(function (table) {
        if (table.querySelector('tbody tr')) return;
        var row = table.tBodies[0].insertRow();
        var cell = row.insertCell();
        cell.colSpan = table.tHead.rows[0].cells.length;
        cell.className = 'dashboard-empty';
        cell.textContent = 'No scans yet. Upload a report to see results here.';
    });
}());
