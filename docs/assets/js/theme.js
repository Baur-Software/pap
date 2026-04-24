/* PAP Docs — theme toggle (button wiring only)
   FOUC prevention is handled by an inline <script> in each page's <head>
   that runs synchronously before the first paint. This file wires the
   toggle button after DOMContentLoaded. */
(function () {
  var STORAGE_KEY = 'pap-theme';
  var html = document.documentElement;

  document.addEventListener('DOMContentLoaded', function () {
    var btn = document.querySelector('.nav-theme-toggle');
    if (!btn) return;

    btn.addEventListener('click', function () {
      var current = html.dataset.theme ||
        (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
      var next = current === 'light' ? 'dark' : 'light';
      html.dataset.theme = next;
      localStorage.setItem(STORAGE_KEY, next);
    });
  });
}());
