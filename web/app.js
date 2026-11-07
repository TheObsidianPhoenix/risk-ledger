// Risk Ledger web page. Plain JavaScript, no libraries: it talks to Supabase's
// Auth and REST APIs directly with the publishable key and the signed-in user's
// token. The database's Row Level Security decides what each user sees, so this
// page never has to be trusted with access decisions; it only shows what comes back.
// All text is inserted with textContent, never as HTML.
"use strict";
(() => {
  const CFG = window.RISK_LEDGER_CONFIG;
  const SESSION_KEY = "risk-ledger-session";   // sessionStorage: cleared when the tab closes
  const THEME_KEY = "risk-ledger-theme";
  const app = document.getElementById("app");
  const state = { session: null, user: null, profile: null, view: "dashboard", skippedMfa: false };

  // ---------------------------------------------------------------- DOM helper
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === false || v === null || v === undefined) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const svg = (tag, attrs, ...children) => {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
    for (const c of children.flat()) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return el;
  };
  const fmtDate = (v) => v ? new Date(v).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }) : "—";
  const fmtTime = (v) => v ? new Date(v).toLocaleString(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" }) : "—";
  const ago = (v) => {
    if (!v) return "never";
    const s = Math.round((Date.now() - new Date(v)) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return Math.round(s / 60) + " min ago";
    if (s < 86400) return Math.round(s / 3600) + " h ago";
    return Math.round(s / 86400) + " d ago";
  };

  function toast(message, bad) {
    document.querySelectorAll(".toast").forEach((x) => x.remove());
    const t = h("div", { class: "toast" + (bad ? " bad" : ""), role: "status" }, message);
    document.body.append(t);
    setTimeout(() => t.remove(), bad ? 7000 : 3500);
  }

  // ---------------------------------------------------------------- session storage
  function saveSession(s) {
    state.session = s;
    try { s ? sessionStorage.setItem(SESSION_KEY, JSON.stringify(s)) : sessionStorage.removeItem(SESSION_KEY); } catch (_) { /* private mode */ }
  }
  function loadSession() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null"); } catch (_) { return null; }
  }
  function claims() {
    try {
      const part = state.session.access_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
      return JSON.parse(atob(part));
    } catch (_) { return {}; }
  }

  // ---------------------------------------------------------------- HTTP
  async function http(path, { method = "GET", body, prefer, retried } = {}) {
    const headers = { apikey: CFG.publishableKey, "Content-Type": "application/json" };
    if (state.session) headers.Authorization = "Bearer " + state.session.access_token;
    if (prefer) headers.Prefer = prefer;
    const res = await fetch(CFG.supabaseUrl + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    if (res.status === 401 && state.session && state.session.refresh_token && !retried && !path.startsWith("/auth/v1/token")) {
      if (await refresh()) return http(path, { method, body, prefer, retried: true });
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    if (!res.ok) {
      const msg = (data && (data.message || data.msg || data.error_description || data.error)) || res.statusText;
      const err = new Error(msg);
      err.status = res.status;
      throw err;
    }
    return data;
  }
  async function refresh() {
    try {
      const s = await http("/auth/v1/token?grant_type=refresh_token", { method: "POST", body: { refresh_token: state.session.refresh_token }, retried: true });
      saveSession(s);
      return true;
    } catch (_) {
      saveSession(null);
      render();
      return false;
    }
  }
  const db = {
    select: (table, query) => http(`/rest/v1/${table}?${query || "select=*"}`),
    rpc: (fn, args) => http(`/rest/v1/rpc/${fn}`, { method: "POST", body: args || {} }),
    async update(table, filter, values) {
      const rows = await http(`/rest/v1/${table}?${filter}`, { method: "PATCH", body: values, prefer: "return=representation" });
      if (!rows || rows.length === 0) throw new Error("Not allowed: the database refused this change for your role.");
      return rows;
    },
  };

  // ---------------------------------------------------------------- auth
  async function signIn(email, password) {
    saveSession(await http("/auth/v1/token?grant_type=password", { method: "POST", body: { email, password } }));
    state.skippedMfa = false;
  }
  async function signOut() {
    try { await http("/auth/v1/logout", { method: "POST" }); } catch (_) { /* already gone */ }
    saveSession(null);
    Object.assign(state, { user: null, profile: null, view: "dashboard", skippedMfa: false });
    render();
  }
  const verifiedFactors = () => ((state.user && state.user.factors) || []).filter((f) => f.status === "verified" && f.factor_type === "totp");

  // ---------------------------------------------------------------- routing
  const can = {
    run: () => state.profile && state.profile.role === "grc_analyst",
    audit: () => state.profile && ["grc_analyst", "auditor"].includes(state.profile.role),
  };
  const ROLE_NAMES = { grc_analyst: "GRC analyst", control_owner: "Control owner", auditor: "Auditor", pending: "No access yet" };
  const NAV = [
    ["dashboard", "Dashboard"], ["controls", "Controls"], ["evidence", "Evidence"],
    ["remediation", "Remediation"], ["risks", "Risk register"], ["audit", "Audit history"],
  ];

  async function render() {
    app.replaceChildren();
    if (!state.session) { state.session = loadSession(); }
    if (!state.session) return app.append(signInView());
    try {
      state.user = await http("/auth/v1/user");
    } catch (_) {
      saveSession(null);
      return app.append(signInView("Your session ended. Please sign in again."));
    }
    if (claims().aal !== "aal2") {
      if (verifiedFactors().length) return app.append(mfaChallengeView());
      if (!state.skippedMfa) return app.append(await mfaEnrollView());
    }
    const rows = await db.select("profiles", "select=id,display_name,role&id=eq." + state.user.id);
    state.profile = rows[0] || { role: "pending", display_name: state.user.email };
    if (state.profile.role === "pending") return app.append(pendingView());
    app.append(await shell());
  }
  function go(view) { state.view = view; render(); }

  // ---------------------------------------------------------------- sign-in and MFA
  function authLayout(...formChildren) {
    return h("div", { class: "auth" },
      h("aside", { class: "auth-side" },
        h("div", { class: "brand" }, h("div", { class: "brand-mark" }, "RL"), h("div", {}, "Risk Ledger", h("small", {}, "Obsidian Phoenix Labs (demo)"))),
        h("div", {},
          h("h1", {}, "Evidence, not screenshots."),
          h("p", {}, "Continuous control monitoring on Supabase. Tests pull evidence from source systems, failures open remediation work, and the risk register shrinks only when evidence proves a fix."),
          h("div", { class: "auth-points" },
            h("div", {}, "Every control states how it lowers risk"),
            h("div", {}, "Only passing evidence can close a remediation item"),
            h("div", {}, "Row Level Security on every table, checked live"),
            h("div", {}, "A hash-chained audit log nobody can edit"))),
        h("p", { class: "faint" }, "Built by Jasmine Alexander. Source data is mock except the Supabase project's own live checks.")),
      h("main", { class: "auth-form" }, h("div", { class: "card" }, ...formChildren)));
  }

  function signInView(message) {
    const err = h("div", { class: message ? "notice" : "error", hidden: !message }, message || "");
    const email = h("input", { type: "email", id: "email", autocomplete: "username", required: true });
    const password = h("input", { type: "password", id: "password", autocomplete: "current-password", required: true });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Sign in");
    const form = h("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        btn.disabled = true;
        try { await signIn(email.value.trim(), password.value); render(); }
        catch (x) { err.className = "error"; err.hidden = false; err.textContent = x.status === 400 ? "Email or password is incorrect." : x.message; btn.disabled = false; }
      },
    },
      h("h2", {}, "Sign in"), h("p", { class: "sub" }, "Use the account your GRC team created for you."),
      err,
      h("div", { class: "field" }, h("label", { for: "email" }, "Email"), email),
      h("div", { class: "field" }, h("label", { for: "password" }, "Password"), password),
      btn);
    return authLayout(form);
  }

  // Supabase returns the QR code as an SVG data URL with the markup unencoded. Characters
  // such as "#" in it end the URL early and the image breaks, so encode the markup.
  function qrSrc(raw) {
    const m = /^data:image\/svg\+xml;(?:utf-?8|charset=utf-?8),/i.exec(raw || "");
    if (!m) return raw;
    let body = raw.slice(m[0].length);
    try { if (!body.includes("<")) body = decodeURIComponent(body); } catch (_) { /* leave as is */ }
    return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(body);
  }

  async function mfaEnrollView() {
    let factor;
    try {
      // Clear any half-finished enrollment, then start a new one
      for (const f of (state.user.factors || []).filter((x) => x.status !== "verified")) {
        await http(`/auth/v1/factors/${f.id}`, { method: "DELETE" }).catch(() => {});
      }
      factor = await http("/auth/v1/factors", { method: "POST", body: { factor_type: "totp", friendly_name: "Risk Ledger " + new Date().toISOString().slice(0, 16) } });
    } catch (x) {
      return authLayout(h("h2", {}, "Set up MFA"), h("div", { class: "error" }, x.message),
        h("button", { class: "btn", onclick: () => { state.skippedMfa = true; render(); } }, "Continue without MFA"));
    }
    const err = h("div", { class: "error", hidden: true });
    const code = h("input", { id: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, required: true, pattern: "[0-9]{6}" });
    const form = h("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        try {
          const ch = await http(`/auth/v1/factors/${factor.id}/challenge`, { method: "POST", body: {} });
          saveSession(await http(`/auth/v1/factors/${factor.id}/verify`, { method: "POST", body: { challenge_id: ch.id, code: code.value.trim() } }));
          toast("MFA is on. Run the tests again to see SB-03 pass.");
          render();
        } catch (x) { err.hidden = false; err.textContent = "That code didn't work: " + x.message; }
      },
    },
      h("h2", {}, "Set up MFA"),
      h("p", { class: "sub" }, "Scan this with an authenticator app (Google Authenticator, 1Password, Authy), then enter the 6-digit code."),
      err,
      h("img", { class: "qr", src: qrSrc(factor.totp.qr_code), alt: "QR code for your authenticator app" }),
      factor.totp.uri ? h("p", { class: "center" }, h("a", { href: factor.totp.uri }, "On this phone? Tap here to add it to your authenticator app")) : null,
      h("p", { class: "faint center" }, "Can't scan? In your app choose \u201cEnter a setup key\u201d and type this key:"),
      h("p", { class: "secret mono" }, (factor.totp.secret || "").replace(/(.{4})/g, "$1 ").trim()),
      h("div", { class: "field" }, h("label", { for: "code" }, "6-digit code"), code),
      h("div", { class: "actions" },
        h("button", { class: "btn primary", type: "submit" }, "Turn on MFA"),
        h("button", { class: "btn", type: "button", onclick: () => { state.skippedMfa = true; render(); } }, "Not now")),
      h("p", { class: "faint small-note" }, "Skipping is allowed for the demo, but control SB-03 fails while any GRC analyst has no MFA."));
    return authLayout(form);
  }

  function mfaChallengeView() {
    const factor = verifiedFactors()[0];
    const err = h("div", { class: "error", hidden: true });
    const code = h("input", { id: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: 6, required: true, pattern: "[0-9]{6}" });
    const form = h("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        try {
          const ch = await http(`/auth/v1/factors/${factor.id}/challenge`, { method: "POST", body: {} });
          saveSession(await http(`/auth/v1/factors/${factor.id}/verify`, { method: "POST", body: { challenge_id: ch.id, code: code.value.trim() } }));
          render();
        } catch (x) { err.hidden = false; err.textContent = "That code didn't work: " + x.message; }
      },
    },
      h("h2", {}, "Two-step verification"),
      h("p", { class: "sub" }, "Enter the 6-digit code from your authenticator app."),
      err,
      h("div", { class: "field" }, h("label", { for: "code" }, "6-digit code"), code),
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Verify"), h("button", { class: "btn", type: "button", onclick: signOut }, "Cancel")));
    return authLayout(form);
  }

  function pendingView() {
    return authLayout(
      h("h2", {}, "You're signed in, but you have no access yet"),
      h("p", { class: "sub" }, "New accounts start with no access. A GRC administrator assigns your role. This is least privilege by default: signing up alone shows you nothing."),
      h("button", { class: "btn", onclick: signOut }, "Sign out"));
  }

  // ---------------------------------------------------------------- app shell
  async function shell() {
    const [status, remediation] = await Promise.all([
      db.select("control_status", "select=*&order=id"),
      db.select("remediation", "select=id,status&status=in.(open,in_progress)"),
    ]);
    const failing = status.filter((c) => c.status === "active" && c.last_result && c.last_result !== "pass").length;
    const nav = h("nav", { class: "sidebar", "aria-label": "Main" },
      h("div", { class: "brand" }, h("div", { class: "brand-mark" }, "RL"), h("div", {}, "Risk Ledger", h("small", {}, "Obsidian Phoenix Labs"))),
      NAV.filter(([v]) => v !== "audit" || can.audit()).map(([v, label]) =>
        h("button", { class: "nav-item", "aria-current": state.view === v ? "page" : false, onclick: () => go(v) }, label,
          v === "controls" && failing ? h("span", { class: "nav-count" }, failing) : null,
          v === "remediation" && remediation.length ? h("span", { class: "nav-count" }, remediation.length) : null)),
      h("div", { class: "sidebar-foot" },
        h("div", {}, h("div", { class: "user-name" }, state.profile.display_name), ROLE_NAMES[state.profile.role],
          claims().aal === "aal2" ? h("span", { class: "badge pass gap-left" }, "MFA") : h("span", { class: "badge warn gap-left" }, "No MFA")),
        h("div", { class: "actions" },
          h("button", { class: "btn small", onclick: toggleTheme }, document.documentElement.dataset.theme === "light" ? "Dark mode" : "Light mode"),
          h("button", { class: "btn small", onclick: signOut }, "Sign out"))));
    const main = h("main", { class: "main" });
    const views = { dashboard: dashboardView, controls: controlsView, evidence: evidenceView, remediation: remediationView, risks: risksView, audit: auditView };
    try {
      main.append(await (views[state.view] || dashboardView)(status));
    } catch (x) {
      main.append(h("div", { class: "error" }, x.message));
    }
    return h("div", { class: "shell" }, nav, main);
  }

  function head(title, text, ...actions) {
    return h("div", { class: "page-head" }, h("div", {}, h("h1", {}, title), text ? h("p", {}, text) : null), h("div", { class: "actions" }, actions));
  }
  function resultBadge(r) {
    if (!r) return h("span", { class: "badge" }, "Not tested");
    return h("span", { class: "badge " + ({ pass: "pass", fail: "fail", error: "warn" }[r] || "") }, { pass: "Pass", fail: "Fail", error: "Error" }[r] || r);
  }
  function statusBadge(s) {
    const map = { open: ["fail", "Open"], in_progress: ["warn", "In progress"], evidenced: ["pass", "Fixed (evidenced)"], risk_accepted: ["info", "Risk accepted"],
                  mitigating: ["warn", "Mitigating"], ready_to_close: ["pass", "Ready to close"], accepted: ["info", "Accepted"], closed: ["", "Closed"],
                  draft: ["warn", "Draft"], active: ["pass", "Active"], retired: ["", "Retired"] };
    const [cls, label] = map[s] || ["", s];
    return h("span", { class: "badge " + cls }, label);
  }
  const sourceCell = (c) => h("td", { class: "nowrap" }, c.source_name || c.source_system, " ", c.source_live ? h("span", { class: "live-dot" }, "live") : h("span", { class: "faint" }, "mock"));
  const runButton = () => can.run() ? h("button", {
    class: "btn primary",
    onclick: async (e) => {
      e.target.disabled = true;
      try { await db.rpc("run_control_tests"); toast("Test run complete. Evidence recorded."); render(); }
      catch (x) { toast(x.message, true); e.target.disabled = false; }
    },
  }, "Run tests now") : null;

  // ---------------------------------------------------------------- dashboard
  async function dashboardView(status) {
    const [risks, trend, runs, remediation] = await Promise.all([
      db.select("risks", "select=id,title,status,score,sample_history&order=score.desc"),
      db.select("risk_trend", "select=*&order=day"),
      db.select("test_runs", "select=*&order=started_at.desc&limit=1"),
      db.select("remediation", "select=*&status=in.(open,in_progress)&order=due_date"),
    ]);
    const active = status.filter((c) => c.status === "active");
    const passing = active.filter((c) => c.last_result === "pass").length;
    const openRisks = risks.filter((r) => !["closed"].includes(r.status));
    const ready = risks.filter((r) => r.status === "ready_to_close").length;
    const overdue = remediation.filter((m) => new Date(m.due_date) < new Date(new Date().toDateString())).length;
    const lastRun = runs[0];
    const attention = active.filter((c) => c.last_result && c.last_result !== "pass");
    return h("div", {},
      head("Control health", "Every result below comes from a test, not a screenshot. Failures open remediation work; risks close only when evidence passes.", runButton()),
      h("div", { class: "grid tiles" },
        tile("Controls passing", `${passing}/${active.length}`, lastRun ? "Last run " + ago(lastRun.started_at) : "Not run yet"),
        tile("Open remediation", remediation.length, overdue ? overdue + " overdue" : "None overdue"),
        tile("Open risks", openRisks.length, ready ? ready + " ready to close" : "Closing needs passing evidence"),
        tile("Live checks", active.filter((c) => c.source_live).length, "Read from this Supabase project")),
      h("div", { class: "grid two" },
        h("section", { class: "card" },
          h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Needs attention"), h("p", {}, "Controls whose latest evidence didn't pass"))),
          attention.length ? h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, attention.map((c) =>
            h("tr", { class: "clickable", onclick: () => openControl(c) },
              h("td", {}, h("div", { class: "cell-title" }, c.id + " · " + c.title), h("div", { class: "cell-sub" }, c.last_detail)),
              h("td", { class: "nowrap" }, resultBadge(c.last_result))))))) : h("div", { class: "empty" }, "Everything passes. Nice.")),
        h("section", { class: "card" },
          h("div", { class: "card-head" }, h("div", {}, h("h2", {}, "Risk register, last 30 days"), h("p", {}, "Open risks per day. Includes fictional sample history."))),
          h("div", { class: "card-body" }, trendChart(trend)))));
  }
  const tile = (label, value, sub) => h("div", { class: "card tile" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value), h("div", { class: "sub" }, sub));

  function trendChart(rows) {
    const W = 600, H = 120, max = Math.max(1, ...rows.map((r) => r.open_risks));
    const bw = W / Math.max(1, rows.length);
    const chart = svg("svg", { class: "trend", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Open risks per day over the last 30 days" },
      rows.map((r, i) => {
        const bh = Math.max(2, (r.open_risks / max) * (H - 8));
        return svg("rect", { class: "bar" + (i === rows.length - 1 ? " today" : ""), x: i * bw + 1, y: H - bh, width: Math.max(2, bw - 3), height: bh, rx: 2 },
          svg("title", {}, `${r.day}: ${r.open_risks} open`));
      }));
    const last = rows[rows.length - 1];
    return h("div", {}, chart,
      h("div", { class: "trend-labels" }, h("span", {}, rows.length ? fmtDate(rows[0].day) : ""), h("span", {}, last ? `Today: ${last.open_risks} open` : "")));
  }

  // ---------------------------------------------------------------- controls
  async function controlsView(status) {
    return h("div", {},
      head("Controls", "Each control is a test with an owner, a frequency and a stated risk reduction. Tests are declarative rules, or live checks of this database.", runButton()),
      h("section", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Control", "Source", "Owner", "Frameworks", "Last tested", "Next due", "Result"].map((t) => h("th", {}, t)))),
        h("tbody", {}, status.map((c) => h("tr", { class: "clickable", onclick: () => openControl(c) },
          h("td", {}, h("div", { class: "cell-title" }, c.id + " · " + c.title), h("div", { class: "cell-sub" }, c.risk_reduced),
            c.status !== "active" ? statusBadge(c.status) : null),
          sourceCell(c),
          h("td", { class: "nowrap" }, c.owner_name || "—"),
          h("td", {}, (c.soc2 || []).map((s) => h("span", { class: "tag" }, "SOC 2 " + s)), (c.iso27001 || []).map((s) => h("span", { class: "tag" }, "ISO " + s))),
          h("td", { class: "nowrap muted" }, ago(c.last_tested)),
          h("td", { class: "nowrap muted" }, fmtDate(c.next_test_due)),
          h("td", {}, resultBadge(c.last_result)))))))));
  }

  async function openControl(c) {
    const evidence = await db.select("evidence", `select=*&control_id=eq.${encodeURIComponent(c.id)}&order=tested_at.desc&limit=10`).catch(() => []);
    drawer(h("div", {},
      h("div", { class: "drawer-head" }, h("div", {}, h("div", { class: "faint mono" }, c.id), h("h1", {}, c.title)), resultBadge(c.last_result)),
      h("p", { class: "quote" }, c.risk_reduced),
      h("dl", { class: "kv" },
        h("dt", {}, "Test"), h("dd", {}, c.test_logic),
        h("dt", {}, "Source"), h("dd", {}, c.source_name, " ", c.source_live ? h("span", { class: "live-dot" }, "live") : h("span", { class: "faint" }, "mock")),
        h("dt", {}, "Linked risk"), h("dd", {}, c.risk_id || "—"),
        h("dt", {}, "Severity"), h("dd", {}, c.severity),
        h("dt", {}, "Owner"), h("dd", {}, c.owner_name || "—"),
        h("dt", {}, "Runs every"), h("dd", {}, c.frequency_days + (c.frequency_days === 1 ? " day" : " days")),
        h("dt", {}, "Approved"), h("dd", {}, c.approved_at ? `${c.approved_by_name} · ${fmtDate(c.approved_at)}` : "Not yet (draft)"),
        h("dt", {}, "Drafted by"), h("dd", {}, c.drafted_by === "ai" ? "AI, reviewed and approved by a person" : "A person")),
      h("h2", {}, "Evidence history"),
      evidence.length ? h("div", { class: "timeline" }, evidence.map(evidenceCard)) : h("p", { class: "muted gap-top" }, "No evidence visible to your role yet.")));
  }

  function evidenceCard(e) {
    return h("div", { class: "timeline-item" },
      h("div", { class: "row-between" }, h("div", { class: "cell-title" }, e.detail), resultBadge(e.result)),
      h("div", { class: "cell-sub" }, `Tested ${fmtTime(e.tested_at)} · evidence collected ${fmtTime(e.collected_at)} · ${e.source_system} · evidence #${e.id}`),
      e.failing && e.failing.length ? h("div", { class: "gap-top" }, h("span", { class: "muted" }, "Failing: "), e.failing.map((f) => h("span", { class: "tag" }, typeof f === "string" ? f : JSON.stringify(f)))) : null,
      e.rule ? h("pre", {}, JSON.stringify(e.rule, null, 2)) : null);
  }

  // ---------------------------------------------------------------- evidence
  async function evidenceView() {
    const rows = await db.select("evidence", "select=*&order=tested_at.desc,id.desc&limit=60");
    return h("div", {},
      head("Evidence", "Permanent, timestamped records written by the test engine. Nobody can edit or delete them, including the database owner."),
      h("section", { class: "card" }, rows.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["#", "Control", "Source", "Result", "Detail", "Tested"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows.map((e) => h("tr", { class: "clickable", onclick: () => drawer(h("div", {}, h("div", { class: "drawer-head" }, h("h1", {}, "Evidence #" + e.id), resultBadge(e.result)),
            h("dl", { class: "kv" }, h("dt", {}, "Control"), h("dd", {}, e.control_id), h("dt", {}, "Test logic"), h("dd", {}, e.test_logic || "—"),
              h("dt", {}, "Source system"), h("dd", {}, e.source_system), h("dt", {}, "Snapshot"), h("dd", {}, e.snapshot_id ? "#" + e.snapshot_id : "—"),
              h("dt", {}, "Collected"), h("dd", {}, fmtTime(e.collected_at)), h("dt", {}, "Tested"), h("dd", {}, fmtTime(e.tested_at)),
              h("dt", {}, "Test run"), h("dd", {}, "#" + e.test_run_id)),
            evidenceCard(e))) },
          h("td", { class: "mono faint" }, e.id), h("td", { class: "nowrap" }, e.control_id), h("td", {}, e.source_system),
          h("td", {}, resultBadge(e.result)), h("td", {}, e.detail), h("td", { class: "nowrap muted" }, fmtTime(e.tested_at)))))))
        : h("div", { class: "empty" }, "No evidence visible to your role yet.")));
  }

  // ---------------------------------------------------------------- remediation
  async function remediationView() {
    const rows = await db.select("remediation", "select=*&order=status,due_date");
    const role = state.profile.role;
    return h("div", {},
      head("Remediation", role === "control_owner" ? "Work assigned to you. Update progress here; the item closes itself when the next test run passes."
        : "Opened automatically by failed tests. Only passing evidence closes an item: nobody can mark a fix done by hand."),
      h("section", { class: "card" }, rows.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Control", "Failure", "Severity", "Owner", "Due", "Status", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows.map((m) => {
          const overdue = ["open", "in_progress"].includes(m.status) && new Date(m.due_date) < new Date(new Date().toDateString());
          return h("tr", {},
            h("td", { class: "nowrap cell-title" }, m.control_id), h("td", {}, m.failure_reason, m.owner_note ? h("div", { class: "cell-sub" }, "Note: " + m.owner_note) : null),
            h("td", {}, m.severity), h("td", { class: "nowrap" }, m.owner_name || "—"),
            h("td", { class: "nowrap" + (overdue ? "" : " muted") }, overdue ? h("span", { class: "badge fail" }, "Overdue " + fmtDate(m.due_date)) : fmtDate(m.due_date)),
            h("td", {}, statusBadge(m.status), m.status === "risk_accepted" ? h("div", { class: "cell-sub" }, "Until " + fmtDate(m.accepted_until)) : null),
            h("td", { class: "nowrap" }, remediationActions(m)));
        })))) : h("div", { class: "empty" }, "No remediation items visible to your role.")));
  }

  function remediationActions(m) {
    const role = state.profile.role;
    if (!["open", "in_progress"].includes(m.status) || !["grc_analyst", "control_owner"].includes(role)) return null;
    return h("button", { class: "btn small", onclick: () => remediationForm(m) }, role === "grc_analyst" ? "Update" : "Update progress");
  }

  function remediationForm(m) {
    const err = h("div", { class: "error", hidden: true });
    const isGrc = state.profile.role === "grc_analyst";
    const status = h("select", { id: "rstatus" },
      h("option", { value: "open", selected: m.status === "open" }, "Open"),
      h("option", { value: "in_progress", selected: m.status === "in_progress" }, "In progress"),
      isGrc ? h("option", { value: "risk_accepted" }, "Accept the risk (time-limited)") : null);
    const until = h("input", { type: "date", id: "runtil", min: new Date().toISOString().slice(0, 10) });
    const untilField = h("div", { class: "field", hidden: true }, h("label", { for: "runtil" }, "Accepted until (180 days at most)"), until);
    status.addEventListener("change", () => { untilField.hidden = status.value !== "risk_accepted"; });
    const note = h("textarea", { id: "rnote", rows: 3, maxlength: 1000 }, m.owner_note || "");
    drawer(h("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        const values = { status: status.value, owner_note: note.value.trim() };
        if (status.value === "risk_accepted") values.accepted_until = until.value || null;
        try { await db.update("remediation", "id=eq." + m.id, values); closeDrawer(); toast("Saved and recorded in the audit log."); render(); }
        catch (x) { err.hidden = false; err.textContent = x.message; }
      },
    },
      h("div", { class: "drawer-head" }, h("div", {}, h("div", { class: "faint mono" }, m.control_id), h("h1", {}, "Update remediation")), statusBadge(m.status)),
      h("p", { class: "muted gap-bottom" }, m.failure_reason),
      err,
      h("div", { class: "field" }, h("label", { for: "rstatus" }, "Status"), status,
        h("span", { class: "hint" }, "There's no \"fixed\" option on purpose: the item closes when a test run proves the fix.")),
      untilField,
      h("div", { class: "field" }, h("label", { for: "rnote" }, isGrc ? "Note (required to accept a risk)" : "Progress note"), note),
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Save"), h("button", { class: "btn", type: "button", onclick: closeDrawer }, "Cancel"))));
  }

  // ---------------------------------------------------------------- risks
  async function risksView() {
    const [risks, trend] = await Promise.all([
      db.select("risks", "select=*&order=status,score.desc"),
      db.select("risk_trend", "select=*&order=day"),
    ]);
    const live = risks.filter((r) => !r.sample_history);
    const history = risks.filter((r) => r.sample_history);
    return h("div", {},
      head("Risk register", "Each risk is linked to the controls that reduce it. A risk becomes ready to close only when every linked control's latest evidence passes, and a GRC analyst closes it with a note."),
      h("section", { class: "card gap-bottom" }, h("div", { class: "card-body" }, trendChart(trend))),
      h("section", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Risk", "Score", "Owner", "Treatment", "Status", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, [...live, ...history].map((r) => h("tr", {},
          h("td", {}, h("div", { class: "cell-title" }, r.id + " · " + r.title), h("div", { class: "cell-sub" }, r.sample_history ? "Sample history (fictional)" : r.description),
            r.close_note ? h("div", { class: "cell-sub" }, "Closed: " + r.close_note) : null),
          h("td", { class: "nowrap" }, h("span", { class: "badge plain " + (r.score >= 15 ? "fail" : r.score >= 8 ? "warn" : "") }, r.score), h("div", { class: "cell-sub" }, `L${r.likelihood} × I${r.impact}`)),
          h("td", { class: "nowrap" }, r.owner_name),
          h("td", { class: "muted" }, r.treatment),
          h("td", { class: "nowrap" }, statusBadge(r.status)),
          h("td", { class: "nowrap" }, r.status === "ready_to_close" && can.run() ? h("button", { class: "btn small primary", onclick: () => closeRiskForm(r) }, "Close risk") : null))))))));
  }

  function closeRiskForm(r) {
    const err = h("div", { class: "error", hidden: true });
    const note = h("textarea", { id: "cnote", rows: 3, required: true, minlength: 10 });
    drawer(h("form", {
      onsubmit: async (e) => {
        e.preventDefault();
        try { await db.rpc("close_risk", { p_id: r.id, p_note: note.value.trim() }); closeDrawer(); toast(r.id + " closed. The register just shrank."); render(); }
        catch (x) { err.hidden = false; err.textContent = x.message; }
      },
    },
      h("div", { class: "drawer-head" }, h("div", {}, h("div", { class: "faint mono" }, r.id), h("h1", {}, "Close risk")), statusBadge(r.status)),
      h("p", { class: "muted gap-bottom" }, r.title),
      h("div", { class: "notice" }, "Every control linked to this risk passed its latest test. Closing is still a human decision."),
      err,
      h("div", { class: "field" }, h("label", { for: "cnote" }, "Closing note"), note, h("span", { class: "hint" }, "What evidence convinced you? Recorded in the audit log.")),
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "submit" }, "Close risk"), h("button", { class: "btn", type: "button", onclick: closeDrawer }, "Cancel"))));
  }

  // ---------------------------------------------------------------- audit
  async function auditView() {
    const rows = await db.select("audit_log", "select=*&order=id.desc&limit=100");
    const result = h("span", {});
    const verify = h("button", {
      class: "btn",
      onclick: async () => {
        result.replaceChildren("Checking…");
        try {
          const out = await db.rpc("verify_audit_chain");
          const r = Array.isArray(out) ? out[0] : out;
          result.replaceChildren(r.first_broken_id ? h("span", { class: "badge fail" }, "Broken at row " + r.first_broken_id)
            : h("span", { class: "badge pass" }, `Intact: ${r.rows_checked} rows verified`));
        } catch (x) { result.replaceChildren(h("span", { class: "badge fail" }, x.message)); }
      },
    }, "Verify the hash chain");
    return h("div", {},
      head("Audit history", "Every change, by whom and when. Append-only: updates, deletes and truncation are blocked, and each row carries a hash of the one before it.", result, verify),
      h("section", { class: "card" }, h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["#", "When", "Who", "Action", "Record", "Change"].map((t) => h("th", {}, t)))),
        h("tbody", {}, rows.map((a) => h("tr", {},
          h("td", { class: "mono faint" }, a.id), h("td", { class: "nowrap muted" }, fmtTime(a.at)),
          h("td", { class: "nowrap" }, a.actor_role), h("td", {}, a.action),
          h("td", { class: "nowrap" }, a.table_name + " " + a.row_id),
          h("td", { class: "mono clip" }, summarizeChange(a)))))))));
  }
  function summarizeChange(a) {
    if (a.action !== "update") return a.action === "insert" ? "created" : "removed";
    return Object.entries(a.changes || {}).map(([k, v]) => `${k}: ${JSON.stringify(v.from)} → ${JSON.stringify(v.to)}`).join("; ");
  }

  // ---------------------------------------------------------------- drawer and theme
  function drawer(content) {
    closeDrawer();
    const back = h("div", { class: "backdrop", id: "drawer", onclick: (e) => { if (e.target === back) closeDrawer(); } },
      h("aside", { class: "drawer", role: "dialog", "aria-modal": "true" },
        h("div", { class: "row-end" }, h("button", { class: "btn small", onclick: closeDrawer, "aria-label": "Close" }, "Close")),
        content));
    document.body.append(back);
  }
  function closeDrawer() { const d = document.getElementById("drawer"); if (d) d.remove(); }
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });

  // Light (the pastel phoenix) is the default; dark is an option a viewer can switch to
  function applyTheme(t) { if (t === "dark") delete document.documentElement.dataset.theme; else document.documentElement.dataset.theme = "light"; }
  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    applyTheme(next);
    try { localStorage.setItem(THEME_KEY, next); } catch (_) { /* fine */ }
    render();
  }
  applyTheme("light");
  try { applyTheme(localStorage.getItem(THEME_KEY)); } catch (_) { /* default light */ }

  render().catch((x) => app.replaceChildren(h("div", { class: "main" }, h("div", { class: "error" }, x.message))));
})();
