"use strict";
// NetBooty web page: renders /api/state and changes things through the JSON API.
// The DOM is built with createElement/textContent only: no data ever goes through innerHTML.

const POLL_MS = 5000;
const DIRTY_MS = 60000; // a card with unsaved edits is left alone this long

let state = null;
const $ = (id) => document.getElementById(id);

// --- helpers -----------------------------------------------------------------

/** h("button", {class: "x", onclick: fn}, "text", child, …): attributes, listeners and children. */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c != null && c !== false && c !== "") el.append(c);
  }
  return el;
}

function ago(ts) {
  if (!ts) return "never";
  const d = Math.max(0, Math.floor(state.now - ts));
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}

const splitTargets = (s) => s.split(/[\s,]+/).filter(Boolean);

function toast(msg, error) {
  const t = h("div", { class: error ? "toast error" : "toast", role: error ? "alert" : "status" }, msg);
  t.addEventListener("click", () => t.remove());
  $("toasts").append(t);
  setTimeout(() => t.remove(), error ? 8000 : 3000);
}

async function api(method, path, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  let r;
  try {
    r = await fetch("/api" + path, opts);
  } catch {
    throw Object.assign(new Error("Can't reach the NetBooty server."), { offline: true });
  }
  if (r.status === 401) {
    location.href = "/login";
    throw new Error("Logged out");
  }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || `${r.status} ${r.statusText}`);
  return data;
}

/** Run an API call for a control, report the outcome, then refresh. */
async function act(ctrl, method, path, body, done) {
  const card = ctrl.closest("[data-key]");
  ctrl.disabled = true;
  try {
    await api(method, path, body);
    if (card) {
      delete card.dataset.dirty;
      card.dataset.force = "1";
    }
    if (done) toast(done);
  } catch (e) {
    toast(e.message, true);
    // A select that saves on change should show the server's value again; typed text stays.
    if (card && ctrl.tagName === "SELECT") card.dataset.force = "1";
  }
  ctrl.disabled = false;
  await refresh();
}

// --- keyed rendering ---------------------------------------------------------

/** Is the user in the middle of something in this card? */
function busy(el) {
  if (el.dataset.dirty && Date.now() - Number(el.dataset.dirty) < DIRTY_MS) return true;
  const a = document.activeElement;
  return el.contains(a) && a.matches("input:not([readonly]), select");
}

/** Replace `container`'s children by `nodes` (each with data-key), keeping
 *  unchanged and busy ones, the open state of <details> and the focus. */
function patch(container, nodes) {
  const old = new Map();
  for (const c of container.children) if (c.dataset.key) old.set(c.dataset.key, c);
  const focusKey = document.activeElement?.dataset?.k;
  const out = nodes.map((n) => {
    const html = n.outerHTML;
    n.dataset.html = html;
    const prev = old.get(n.dataset.key);
    if (!prev) return n;
    if (!prev.dataset.force && (prev.dataset.html === html || busy(prev))) return prev;
    for (const d of prev.querySelectorAll("details[data-k]")) {
      const nd = n.querySelector(`details[data-k="${CSS.escape(d.dataset.k)}"]`);
      if (nd) nd.open = d.open;
    }
    return n;
  });
  const same = out.length === container.children.length && out.every((n, i) => container.children[i] === n);
  if (!same) container.replaceChildren(...out);
  if (focusKey && (!document.activeElement || document.activeElement === document.body)) {
    container.querySelector(`[data-k="${CSS.escape(focusKey)}"]`)?.focus();
  }
}

// Typing in a field marked data-dirty holds back refreshes of its card.
document.addEventListener("input", (e) => {
  if (!e.target.matches("[data-dirty]")) return;
  const card = e.target.closest("[data-key]");
  if (card) card.dataset.dirty = String(Date.now());
});

// --- PCs tab -----------------------------------------------------------------

const PILLS = {
  on: ["on", "● On"],
  off: ["off", "○ Off"],
  waking: ["warn", "◌ Waking…"],
  unknown: ["off", "? Unknown"],
  unavailable: ["off", "? Unavailable"],
};

function subline(pc) {
  const p = pc.power;
  const out = [];
  switch (p.state) {
    case "on":
      if (p.running === null) out.push("running: unknown (did not ask the server this boot)");
      else out.push(`probably running ${p.running || "its own default"} (booted ${ago(p.asked_at)})`);
      if (p.os_hint) out.push(`replies like ${p.os_hint}`);
      break;
    case "off":
      out.push(`off since ${ago(p.since)}`);
      break;
    case "waking":
      out.push(`wake-up sent ${ago(p.since)}`);
      break;
    case "unknown":
      out.push("power unknown until it has asked the server once");
      break;
    case "unavailable":
      out.push(`power status unavailable: ${p.error}`);
      break;
    default:
      out.push("checking power…");
  }
  return out.join(" · ");
}

function field(label, ...controls) {
  return h("div", { class: "field" }, h("span", { class: "label" }, label), ...controls);
}

function pcCard(pc) {
  const id = pc.id;
  const path = `/pcs/${encodeURIComponent(id)}`;
  const k = (s) => `${id}:${s}`;
  const opts = (selected, first) => [
    h("option", { value: "" }, first),
    ...pc.targets.map((t) => h("option", { value: t, selected: t === selected }, t)),
  ];
  const [pillClass, pillText] = PILLS[pc.power.state] || ["off", "… Checking"];

  const boots = h("select", {
    "data-k": k("boots"), "aria-label": `What ${pc.name} boots`,
    onchange: (e) => act(e.target, "POST", `${path}/choice`, { target: e.target.value || null },
      `${pc.name} boots ${e.target.value || "its own default"}`),
  }, opts(pc.choice, "its own default"));

  const once = h("select", {
    "data-k": k("once"), "aria-label": `What ${pc.name} boots next time only`, class: pc.once ? "pending" : null,
    onchange: (e) => act(e.target, "POST", `${path}/once`, { target: e.target.value || null },
      e.target.value ? `${pc.name} boots ${e.target.value} next time` : "One-time choice cancelled"),
  }, opts(pc.once, "no one-time choice"));

  const wakeTarget = h("select", { "data-k": k("wake-target"), "data-dirty": true, "aria-label": "Wake into" },
    opts(null, "its usual choice"));
  const wake = h("button", {
    "data-k": k("wake"),
    onclick: (e) => act(e.target, "POST", `${path}/wake`, { target: wakeTarget.value || null },
      `Wake-up packet sent to ${pc.name}`),
  }, "Wake");

  // Settings
  const name = h("input", { "data-k": k("name"), "data-dirty": true, value: pc.name, required: true, maxlength: 63,
    "aria-label": "Name" });
  const targets = h("input", { "data-k": k("targets"), "data-dirty": true, value: pc.targets.join(", "),
    placeholder: "e.g. windows, linux", "aria-label": "Targets" });
  const saveEdit = h("button", { "data-k": k("save") }, "Save");
  const mac = h("input", { "data-k": k("mac"), "data-dirty": true, value: pc.mac || "", class: "code",
    placeholder: "learned when seen on", autocomplete: "off", spellcheck: "false", "aria-label": "MAC address" });
  const saveMac = h("button", { "data-k": k("save-mac") }, "Save");
  const seen = pc.last_seen
    ? `Last asked ${ago(pc.last_seen)} from ${pc.from}, answered ${pc.last_answer || "no preference"}.`
    : "Has not asked the server yet.";

  return h("article", { class: "card", "data-key": "pc:" + id },
    h("div", { class: "card-head" },
      h("span", { class: "name" }, pc.name),
      h("span", { class: `pill ${pillClass}`, title: pc.power.summary }, pillText)),
    h("div", { class: "sub" }, subline(pc)),
    pc.power.wake_failed && h("div", { class: "warn" },
      "Did not wake: check Wake-on-LAN in the BIOS (ErP off) and the OS's network card settings."),
    h("div", { class: "controls" },
      field("Boots", boots),
      field("Next boot only", once),
      field("Wake into", h("div", { class: "inline" }, wakeTarget, wake))),
    h("details", { "data-k": k("settings") },
      h("summary", null, "Settings"),
      h("div", { class: "controls" },
        h("form", {
          class: "field",
          onsubmit: (e) => {
            e.preventDefault();
            act(saveEdit, "POST", path, { name: name.value.trim(), targets: splitTargets(targets.value) }, "Saved");
          },
        }, h("span", { class: "label" }, "Name"), name,
          h("span", { class: "label" }, "Targets"), h("div", { class: "inline" }, targets, saveEdit)),
        h("form", {
          class: "field",
          onsubmit: (e) => {
            e.preventDefault();
            act(saveMac, "POST", `${path}/mac`, { mac: mac.value.trim() || null }, "MAC address saved");
          },
        }, h("span", { class: "label" }, "MAC address (for Wake)"), h("div", { class: "inline" }, mac, saveMac))),
      h("div", { class: "meta" },
        h("span", null, seen, " ", h("span", { title: id }, `Client ${id.slice(0, 12)}…`)),
        h("button", {
          class: "danger", "data-k": k("remove"),
          onclick: (e) => {
            if (confirm(`Remove ${pc.name}? It gets no answer from the server until it is approved again.`)) {
              act(e.target, "DELETE", path, undefined, `${pc.name} removed`);
            }
          },
        }, "Remove"))));
}

function renderPcs() {
  const n = state.requests.length;
  const nodes = [];
  if (n) {
    nodes.push(h("a", { class: "banner", href: "#/pair", "data-key": "waiting" },
      `${n} new PC${n > 1 ? "s" : ""} waiting for approval →`));
  }
  if (!state.pcs.length) {
    nodes.push(h("p", { class: "muted", "data-key": "empty" },
      "No PCs yet. ", h("a", { href: "#/pair" }, "Pair one"), ", then approve it."));
  }
  nodes.push(...state.pcs.map(pcCard));
  patch($("view-pcs"), nodes);
}

// --- Pair tab ----------------------------------------------------------------

function requestCard(r) {
  const k = (s) => `req:${r.id}:${s}`;
  const name = h("input", { "data-k": k("name"), "data-dirty": true, value: r.hostname || "", required: true,
    maxlength: 63, placeholder: "PC name", "aria-label": "Name" });
  const targets = h("input", { "data-k": k("targets"), "data-dirty": true, value: (r.targets || []).join(", "),
    placeholder: "e.g. windows, linux", "aria-label": "Targets" });
  const approve = h("button", { class: "primary", "data-k": k("approve") }, "Approve");
  const from = [r.from && `from ${r.from}`, `last seen ${ago(r.last_seen)}`].filter(Boolean).join(" · ");
  return h("article", { class: "card", "data-key": "req:" + r.id },
    h("div", { class: "card-head" },
      h("span", { class: "name" }, r.hostname || "Unnamed PC"),
      h("span", { class: "sub" }, from)),
    h("form", {
      class: "controls",
      onsubmit: (e) => {
        e.preventDefault();
        const n = name.value.trim();
        act(approve, "POST", `/requests/${encodeURIComponent(r.id)}/approve`,
          { name: n, targets: splitTargets(targets.value) }, `${n} approved: it's on the PCs tab`);
      },
    },
      field("Name", name),
      field("Targets", targets),
      field(" ", h("div", { class: "inline" }, approve,
        h("button", {
          type: "button", "data-k": k("dismiss"),
          onclick: (e) => act(e.target, "POST", `/requests/${encodeURIComponent(r.id)}/dismiss`, undefined, "Dismissed"),
        }, "Dismiss")))),
    h("div", { class: "meta" }, h("span", { title: r.id }, `Client ${r.id.slice(0, 12)}…`)));
}

async function copy(input) {
  try {
    await navigator.clipboard.writeText(input.value);
  } catch {
    // navigator.clipboard needs https (or localhost); plain http on the LAN falls back to this.
    input.focus();
    input.select();
    if (!document.execCommand("copy")) {
      toast("Copy failed: select the command and copy it yourself.", true);
      return;
    }
  }
  toast("Copied");
}

function pairCard(pairing) {
  if (!pairing.code) {
    return h("article", { class: "card", "data-key": "pair" },
      h("p", { class: "err" }, "The responder has not published a key yet. Is it running?"));
  }
  const cmd = h("input", { class: "code", readonly: true, value: `sudo netbooty-setup pair '${pairing.code}'`,
    "data-k": "pair:cmd", "aria-label": "Pairing command", onfocus: (e) => e.target.select() });
  return h("article", { class: "card", "data-key": "pair" },
    h("p", null, "On the PC, run this (or paste the code into ", h("code", null, "sudo netbooty-setup"), "):"),
    h("p", { class: "inline" }, cmd,
      h("button", { type: "button", onclick: () => copy(cmd) }, "Copy"),
      h("a", { class: "button", href: "/pairing.txt", download: "netbooty-pairing.txt" }, "Download")),
    h("p", { class: "muted" }, "Key fingerprint: ", h("code", null, pairing.fingerprints.join(" / ")),
      ". The PC shows the same when pairing: check that they match."),
    h("p", { class: "muted" }, "Or let the PC find this server itself: ",
      h("code", null, "sudo netbooty-setup pair --discover"), ", then check that it shows this fingerprint."));
}

function renderPair() {
  const reqs = state.requests;
  const news = [h("h2", { "data-key": "h-new" }, "New PCs")];
  if (reqs.length) news.push(...reqs.map(requestCard));
  else {
    news.push(h("p", { class: "muted", "data-key": "no-new" }, "None. A paired PC appears here when it boots ",
      "NetBooty or runs ", h("code", null, "netbooty-setup announce"), "."));
  }
  const pair = [h("h2", { "data-key": "h-pair" }, "Pair a PC"), pairCard(state.pairing)];
  // Waiting PCs need a decision, so they go first.
  patch($("view-pair"), reqs.length ? [...news, ...pair] : [...pair, ...news]);
}

// --- shell -------------------------------------------------------------------

function route() {
  const pair = location.hash === "#/pair";
  $("view-pcs").hidden = pair;
  $("view-pair").hidden = !pair;
  for (const [tab, on] of [["tab-pcs", !pair], ["tab-pair", pair]]) {
    if (on) $(tab).setAttribute("aria-current", "page");
    else $(tab).removeAttribute("aria-current");
  }
}

function render() {
  const n = state.requests.length;
  $("badge").hidden = !n;
  $("badge").textContent = String(n);
  document.title = n ? `(${n}) NetBooty` : "NetBooty";
  renderPcs();
  renderPair();
}

async function load() {
  try {
    state = await api("GET", "/state");
    $("offline").hidden = true;
    render();
  } catch (e) {
    if (e.offline) $("offline").hidden = false;
  }
}

// One fetch at a time; a refresh asked for during one runs again after it.
let refreshing = null;
let again = false;
function refresh() {
  if (refreshing) {
    again = true;
    return refreshing;
  }
  refreshing = (async () => {
    do {
      again = false;
      await load();
    } while (again);
  })().finally(() => {
    refreshing = null;
  });
  return refreshing;
}

window.addEventListener("hashchange", route);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh();
});
setInterval(() => {
  if (!document.hidden) refresh();
}, POLL_MS);
route();
refresh();
