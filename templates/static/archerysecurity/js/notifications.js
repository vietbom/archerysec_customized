(function () {
    'use strict';
    var inbox = document.querySelector('.notification-inbox');
    if (!inbox) return;
    var badge = inbox.querySelector('.notification-count');
    var items = inbox.querySelector('.notification-items');
    var error = inbox.querySelector('.notification-error');
    var refreshing = false;
    function refresh() {
        if (refreshing) return Promise.resolve();
        refreshing = true;
        return fetch(inbox.dataset.feedUrl, {credentials: 'same-origin', headers: {'Accept': 'application/json'}})
            .then(function (response) {
                if (!response.ok) throw new Error('Could not load notifications.');
                return response.json();
            }).then(function (data) {
                badge.textContent = data.count > 99 ? '99+' : String(data.count);
                badge.hidden = data.count === 0;
                inbox.querySelector('.notification-clear-button').disabled = data.count === 0;
                items.replaceChildren();
                if (!data.results.length) {
                    var empty = document.createElement('p');
                    empty.className = 'notification-empty';
                    empty.textContent = 'You’re all caught up. No unread notifications.';
                    items.appendChild(empty);
                }
                data.results.forEach(function (item) {
                    var row = document.createElement('div');
                    row.className = 'notification-item';
                    row.setAttribute('role', 'listitem');
                    var content = document.createElement('div');
                    var title = document.createElement('p');
                    title.textContent = item.verb;
                    var time = document.createElement('time');
                    time.dateTime = item.timestamp;
                    time.textContent = new Date(item.timestamp).toLocaleString();
                    content.append(title, time);
                    var form = inbox.querySelector('.notification-dismiss-template').cloneNode(true);
                    form.hidden = false;
                    form.className = 'notification-form';
                    form.querySelector('[name="notify_id"]').value = item.id;
                    var dismiss = document.createElement('button');
                    dismiss.type = 'submit';
                    dismiss.className = 'notification-dismiss';
                    dismiss.setAttribute('aria-label', 'Mark notification as read');
                    dismiss.textContent = '×';
                    form.appendChild(dismiss);
                    row.append(content, form);
                    items.appendChild(row);
                });
                error.hidden = true;
            }).catch(function () {
                error.textContent = 'Notifications are unavailable. Open the bell to retry.';
                error.hidden = false;
            }).finally(function () { refreshing = false; });
    }
    inbox.addEventListener('submit', function (event) {
        var form = event.target;
        if (!form.classList.contains('notification-form')) return;
        event.preventDefault();
        event.stopPropagation();
        var button = form.querySelector('button');
        button.disabled = true;
        fetch(form.action, {method: 'POST', credentials: 'same-origin', body: new FormData(form),
            headers: {'X-Requested-With': 'XMLHttpRequest'}})
            .then(function (response) {
                if (!response.ok) throw new Error('Could not update notifications.');
                return refresh();
            }).catch(function () {
                error.textContent = 'Could not mark notification as read. Please retry.';
                error.hidden = false;
            }).finally(function () { button.disabled = false; });
    });
    inbox.querySelector('.notification-toggle').addEventListener('click', refresh);
    refresh();
    window.setInterval(function () { if (!document.hidden) refresh(); }, 30000);
}());
