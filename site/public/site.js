// The Hideout site's behaviour. Everything here runs in the browser and sends nothing anywhere:
// there is no network code in this file or in guide-core.js, and the page's content security
// policy (see _headers) would refuse a connection if there were.
import { STEPS, CHECKS, LETTER_KINDS, createStore, buildLetter, checkStatus } from "./guide-core.js";

// ---- The guide: six steps, the letter writer and the deeper checks -------------------------------
(function () {
  "use strict";
  var stepButtons = document.querySelectorAll(".guide-step");
  if (!stepButtons.length) return;

  var storage = null;
  try { storage = window.localStorage; } catch (e) { storage = null; }
  // No storage (a private window, or storage blocked): the guide still works, ticks just aren't kept.
  var store = createStore(storage || { getItem: function () { return null; }, setItem: function () {}, removeItem: function () {} });

  var saved = document.getElementById("guide-saved");
  function paintSaved() {
    if (!saved) return;
    saved.textContent = storage
      ? (store.anySaved() ? "Your ticks are saved in this browser only." : "")
      : "This browser isn't keeping ticks, so they'll reset when you leave.";
  }

  function paintSteps() {
    stepButtons.forEach(function (b) {
      var on = store.stepDone(Number(b.getAttribute("data-step")));
      b.textContent = on ? "Done ✓" : "Mark done";
      b.setAttribute("aria-pressed", String(on));
    });
    paintSaved();
  }
  stepButtons.forEach(function (b) {
    b.addEventListener("click", function () {
      store.toggleStep(Number(b.getAttribute("data-step")));
      paintSteps();
    });
  });

  // The deeper checks, each a short list the person ticks off themselves.
  var host = document.getElementById("guide-checks");
  function paintChecks() {
    if (!host) return;
    CHECKS.forEach(function (c, ci) {
      var status = document.getElementById("check-status-" + ci);
      if (status) status.textContent = checkStatus(store.checkedIn(ci), c.items.length);
      c.items.forEach(function (_, ii) {
        var box = document.getElementById("check-" + ci + "-" + ii);
        if (box) box.checked = store.checkDone(ci, ii);
      });
    });
    paintSaved();
  }
  if (host) {
    CHECKS.forEach(function (c, ci) {
      var fs = document.createElement("fieldset");
      fs.className = "check";
      var lg = document.createElement("legend");
      lg.textContent = c.title;
      fs.appendChild(lg);
      var st = document.createElement("p");
      st.className = "fine check-status";
      st.id = "check-status-" + ci;
      fs.appendChild(st);
      c.items.forEach(function (text, ii) {
        var label = document.createElement("label");
        label.className = "check-item";
        var box = document.createElement("input");
        box.type = "checkbox";
        box.id = "check-" + ci + "-" + ii;
        box.addEventListener("change", function () { store.toggleCheck(ci, ii); paintChecks(); });
        label.appendChild(box);
        label.appendChild(document.createTextNode(" " + text));
        fs.appendChild(label);
      });
      var adv = document.createElement("p");
      adv.className = "advice";
      adv.textContent = c.advice;
      fs.appendChild(adv);
      host.appendChild(fs);
    });
  }

  var clear = document.getElementById("guide-clear");
  if (clear) clear.addEventListener("click", function () { store.clearAll(); paintSteps(); paintChecks(); });

  // The letter writer. What the person types is never stored, and never sent.
  var kind = document.getElementById("guide-kind");
  var out = document.getElementById("guide-letter");
  var made = false;
  if (kind) LETTER_KINDS.forEach(function (k) {
    var o = document.createElement("option");
    o.value = k.id; o.textContent = k.label;
    kind.appendChild(o);
  });
  var build = document.getElementById("guide-build");
  if (build && out) build.addEventListener("click", function () {
    out.textContent = buildLetter(kind ? kind.value : "bank_dispute", {
      who: document.getElementById("guide-who").value,
      amount: document.getElementById("guide-amt").value,
      date: document.getElementById("guide-date").value,
    });
    made = true;
  });
  var copy = document.getElementById("guide-copy");
  var copied = document.getElementById("guide-copied");
  if (copy && out) copy.addEventListener("click", function () {
    if (!made) { if (copied) copied.textContent = "Build a letter first."; return; }
    var text = out.textContent;
    var ok = function () { if (copied) copied.textContent = "Copied."; };
    var no = function () { if (copied) copied.textContent = "Couldn't copy. Select the letter and copy it yourself."; };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(ok, no); else no();
  });

  // The page's own six steps and the module's must be the same six.
  if (stepButtons.length !== STEPS.length) console.warn("guide: step count differs from guide-core.js");
  paintSteps();
  paintChecks();
})();

// ---- Tabs for the three product views. Arrow keys move between tabs (WAI-ARIA tabs pattern). ----
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
