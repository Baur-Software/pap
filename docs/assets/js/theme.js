/* PAP Docs — theme toggle
   Applies saved or system preference immediately (inline in <head> is ideal,
   but as a deferred script this prevents FOUC on all except very first load). */
(function () {
  var STORAGE_KEY = 'pap-theme';
  var html = document.documentElement;

  // Apply saved preference before first paint
  var saved = localStorage.getItem(STORAGE_KEY);
  if (saved) html.dataset.theme = saved;

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
