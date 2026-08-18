/* MK-Monitoring shared frontend helpers. */

// Attach the CSRF token to all AJAX requests automatically.
(function attachCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta && window.axios) {
        axios.defaults.headers.common['X-CSRF-Token'] = meta.content;
    }
})();

// Auto-dismiss flash alerts after a few seconds (dismissable ones only).
document.addEventListener('DOMContentLoaded', function () {
    document.querySelectorAll('.alert[data-auto-dismiss]').forEach(function (alert) {
        setTimeout(function () {
            const instance = bootstrap.Alert.getOrCreateInstance(alert);
            instance.close();
        }, 5000);
    });
});
