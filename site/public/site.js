// Tabs for the three product views. Arrow keys move between tabs (WAI-ARIA tabs pattern).
(function () {
  "use strict";
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]'));
  function select(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute("aria-selected", String(on));
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
    if (focus) tab.focus();
  }
  tabs.forEach(function (t, i) {
    t.tabIndex = i === 0 ? 0 : -1;
    t.addEventListener("click", function () { select(t, false); });
    t.addEventListener("keydown", function (e) {
      var n = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!n) return;
      e.preventDefault();
      select(tabs[(i + n + tabs.length) % tabs.length], true);
    });
  });
  // Nav links to a section inside a tab open that tab first.
  var map = { "#pc": "t-pc", "#money": "t-money", "#guide": "t-guide" };
  function fromHash() { var id = map[location.hash]; if (id) select(document.getElementById(id), false); }
  window.addEventListener("hashchange", fromHash);
  fromHash();
})();
