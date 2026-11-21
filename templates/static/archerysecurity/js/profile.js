(function () {
    "use strict";
    var form = document.getElementById("profile-password-form");
    if (!form) return;
    var toggle = form.querySelector("[data-password-visibility]");
    if (!toggle) return;
    var fields = form.querySelectorAll('input[type="password"]');
    toggle.hidden = false;
    toggle.addEventListener("click", function () {
        var show = toggle.getAttribute("aria-pressed") !== "true";
        fields.forEach(function (field) { field.type = show ? "text" : "password"; });
        toggle.setAttribute("aria-pressed", String(show));
        toggle.querySelector("span").textContent = show ? "Hide passwords" : "Show passwords";
        toggle.querySelector("i").className = show ? "fas fa-eye-slash" : "fas fa-eye";
    });
    form.querySelectorAll(".profile-field--error input").forEach(function (field) {
        field.setAttribute("aria-invalid", "true");
    });
    var firstError = form.querySelector('[aria-invalid="true"]');
    if (firstError) firstError.focus();
    // Always mask fields again before sending or restoring a cached page.
    function mask() {
        fields.forEach(function (field) { field.type = "password"; });
        toggle.setAttribute("aria-pressed", "false");
        toggle.querySelector("span").textContent = "Show passwords";
        toggle.querySelector("i").className = "fas fa-eye";
    }
    form.addEventListener("submit", mask);
    window.addEventListener("pageshow", mask);
}());
