// Guide: step tracker and letter builder. Runs in the browser only, nothing is sent.
(function () {
  "use strict";
  var KEY = "hideout-guide-steps";
  var steps = document.querySelectorAll(".guide-step");
  if (!steps.length) return;
  var done = {};
  try { done = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch (e) { done = {}; }
  function paint() {
    steps.forEach(function (b) {
      var on = !!done[b.getAttribute("data-step")];
      b.textContent = on ? "Done ✓" : "Mark done";
      b.setAttribute("aria-pressed", String(on));
    });
  }
  steps.forEach(function (b) {
    b.addEventListener("click", function () {
      var s = b.getAttribute("data-step");
      if (done[s]) { delete done[s]; } else { done[s] = true; }
      try { localStorage.setItem(KEY, JSON.stringify(done)); } catch (e) {}
      paint();
    });
  });
  var clear = document.getElementById("guide-clear");
  if (clear) clear.addEventListener("click", function () {
    done = {};
    try { localStorage.removeItem(KEY); } catch (e) {}
    paint();
  });
  var build = document.getElementById("guide-build");
  var out = document.getElementById("guide-letter");
  if (build && out) build.addEventListener("click", function () {
    var who = document.getElementById("guide-who").value.trim() || "[Company name]";
    var amt = document.getElementById("guide-amt").value.trim() || "[$ amount]";
    var date = document.getElementById("guide-date").value.trim() || "[Date]";
    out.textContent = "To " + who + ":\n\nI am disputing a charge of " + amt + " on " + date + ". [Confirm: this charge was taken after I cancelled, or was not authorised by me.]\n\nPlease reverse this charge and block further charges from this merchant.\n\n[Your name] · [Last 4 digits of card] · [Phone number]";
  });
  var copy = document.getElementById("guide-copy");
  if (copy && out) copy.addEventListener("click", function () {
    if (navigator.clipboard) { navigator.clipboard.writeText(out.textContent); }
  });
  paint();
})();

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
