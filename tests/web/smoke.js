// Browser smoke test for the web page. Serves web/ locally and answers Supabase
// calls from fixtures dumped from the tested database (tests/web/fixtures), so it
// runs with no network and no real account. It signs in, sets up MFA, visits every
// view, closes a risk, updates remediation and verifies the audit chain, failing on
// any page error, console error or Content-Security-Policy violation.
//   node tests/web/smoke.js [screenshot-dir]
"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");

const WEB = path.join(__dirname, "..", "..", "web");
const FIX = path.join(__dirname, "fixtures");
const shots = process.argv[2];
const fixture = (n) => JSON.parse(fs.readFileSync(path.join(FIX, n + ".json"), "utf8"));
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (aal) => `${b64({ alg: "none" })}.${b64({ sub: "00000000-0000-0000-0000-0000000000a1", aal, exp: 9999999999 })}.sig`;
// Shaped like Supabase's real response: unencoded SVG markup containing "#" colours
const QR = 'data:image/svg+xml;utf-8,<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 10 10"><rect width="10" height="10" fill="#ffffff"/><rect x="2" y="2" width="6" height="6" fill="#000000"/></svg>';

function serve() {
  const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".webp": "image/webp" };
  const server = http.createServer((req, res) => {
    const file = path.join(WEB, req.url === "/" ? "index.html" : path.normalize(req.url).replace(/^\/+/, ""));
    if (!file.startsWith(WEB) || !fs.existsSync(file)) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "Content-Type": types[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => ok(server)));
}

(async () => {
  const server = await serve();
  const base = `http://127.0.0.1:${server.address().port}/`;
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1360, height: 860 } });
  const problems = [];
  const calls = [];
  page.on("pageerror", (e) => problems.push("page error: " + e.message));
  page.on("console", (m) => { if (m.type() === "error" && !expectedErrors(m.text())) problems.push("console: " + m.text()); });

  // The wrong-password and wrong-code steps make these on purpose
  let allowed = 2;
  function expectedErrors(t) { return /status of (400|422)/.test(t) && allowed-- > 0; }

  let verified = false;
  const risks = fixture("risks");
  const complianceReminders = fixture("compliance_reminders");
  await page.route("https://*.supabase.co/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const p = url.pathname;
    const body = req.postDataJSON ? (() => { try { return req.postDataJSON(); } catch (_) { return null; } })() : null;
    calls.push(`${req.method()} ${p}${url.search}`);
    if (req.headers()["apikey"] !== "sb_publishable_3yFcZZN7rVwG4KB10wqQfw_jrWTC9-U") problems.push("missing apikey on " + p);
    const json = (data, status = 200) => route.fulfill({ status, contentType: "application/json", body: JSON.stringify(data) });

    if (p === "/auth/v1/token") {
      if (body && body.password !== "correct horse") return json({ error_description: "Invalid login credentials" }, 400);
      return json({ access_token: jwt("aal1"), refresh_token: "r1", token_type: "bearer" });
    }
    if (p === "/auth/v1/user") return json({ id: "00000000-0000-0000-0000-0000000000a1", email: "grc@example.test",
      factors: verified ? [{ id: "f1", factor_type: "totp", status: "verified" }] : [] });
    if (p === "/auth/v1/factors") return json({ id: "f1", type: "totp", totp: { qr_code: QR, secret: "JBSWY3DPEHPK3PXP", uri: "otpauth://totp/Risk%20Ledger:grc@example.test?secret=JBSWY3DPEHPK3PXP" } });
    if (p === "/auth/v1/factors/f1/challenge") return json({ id: "c1" });
    if (p === "/auth/v1/factors/f1/verify") {
      if (body.code !== "123456") return json({ msg: "Invalid TOTP code entered" }, 422);
      verified = true;
      return json({ access_token: jwt("aal2"), refresh_token: "r2" });
    }
    if (p === "/auth/v1/logout") return route.fulfill({ status: 204 });

    if (p.startsWith("/rest/v1/rpc/")) {
      const fn = p.slice("/rest/v1/rpc/".length);
      if (fn === "run_control_tests") return json(3);
      if (fn === "verify_audit_chain") return json(fixture("verify_audit_chain"));
      if (fn === "verify_activity_chain") return json(fixture("verify_activity_chain"));
      if (fn === "log_activity") return json(null);
      if (fn === "scan_compliance_lapses") return json(0);   // fixture already has the drafts pre-scanned
      if (fn === "edit_compliance_reminder") {
        const r = complianceReminders.find((x) => x.id === body.p_id);
        Object.assign(r, { subject: body.p_subject, body: body.p_body, status: "edited" });
        return json(null);
      }
      if (fn === "send_compliance_reminder") {
        const r = complianceReminders.find((x) => x.id === body.p_id);
        Object.assign(r, { status: "sent", sent_at: new Date().toISOString() });
        return json(null);
      }
      if (fn === "dismiss_compliance_reminder") {
        const r = complianceReminders.find((x) => x.id === body.p_id);
        Object.assign(r, { status: "dismissed" });
        return json(null);
      }
      if (fn === "close_risk") {
        const r = risks.find((x) => x.id === body.p_id);
        Object.assign(r, { status: "closed", close_note: body.p_note, closed_at: new Date().toISOString() });
        return json(null);
      }
      return json({ message: "unknown function" }, 404);
    }
    const table = p.slice("/rest/v1/".length);
    if (req.method() === "PATCH") {
      const id = Number(url.searchParams.get("id").replace("eq.", ""));
      const row = fixture("remediation").find((r) => r.id === id);
      return json([{ ...row, ...body }]);
    }
    let rows = table === "risks" ? risks : table === "compliance_reminders" ? complianceReminders : fixture(table);
    for (const [k, v] of url.searchParams) {
      if (["select", "order", "limit"].includes(k)) continue;
      if (v.startsWith("eq.")) rows = rows.filter((r) => String(r[k]) === v.slice(3));
      if (v.startsWith("in.(")) { const set = v.slice(4, -1).split(","); rows = rows.filter((r) => set.includes(String(r[k]))); }
    }
    const order = (url.searchParams.get("order") || "").split(",")[0];
    if (order.endsWith(".desc")) { const k = order.slice(0, -5); rows = [...rows].sort((a, b) => (a[k] < b[k] ? 1 : a[k] > b[k] ? -1 : 0)); }
    if (url.searchParams.get("limit")) rows = rows.slice(0, Number(url.searchParams.get("limit")));
    return json(rows);
  });

  const step = async (name, fn) => {
    try { await fn(); console.log("PASS  " + name); }
    catch (e) { problems.push(`${name}: ${e.message.split("\n")[0]}`); console.log("FAIL  " + name); }
    if (shots) await page.screenshot({ path: path.join(shots, name.replace(/\W+/g, "-").toLowerCase() + ".png") });
  };
  const see = (text) => page.getByText(text, { exact: false }).first().waitFor({ timeout: 4000 });

  await page.goto(base);
  await step("sign-in screen", () => see("Evidence, not screenshots."));
  await step("wrong password is refused", async () => {
    await page.fill("#email", "grc@example.test"); await page.fill("#password", "nope");
    await page.click("button[type=submit]"); await see("Email or password is incorrect.");
  });
  await step("MFA setup shows a QR code", async () => {
    await page.fill("#password", "correct horse"); await page.click("button[type=submit]");
    await see("Set up MFA"); await page.locator("img.qr").waitFor();
    const ok = await page.locator("img.qr").evaluate((img) => img.complete && img.naturalWidth > 0);
    if (!ok) throw new Error("QR code image did not load");
  });
  await step("wrong MFA code is refused", async () => {
    await page.fill("#code", "000000"); await page.click("button[type=submit]"); await see("That code didn't work");
  });
  await step("dashboard after MFA", async () => {
    await page.fill("#code", "123456"); await page.click("button[type=submit]");
    await see("Control health"); await see("Controls passing"); await see("8/12");
  });
  await step("Corvus panel greets with drafts", async () => {
    await see("Corvus"); await see("Morgan Reyes"); await see("Diego Fernandez");
  });
  await step("Corvus: edit and send a draft", async () => {
    await page.locator(".compliance-item", { hasText: "Diego Fernandez" }).getByText("Review / edit").click();
    await see("Save & send now");
    await page.fill("#csubject", "Edited: policy ack due soon");
    await page.click("text=Save & send now (simulated)");
    await see("Sent (simulated)");
  });
  await step("Corvus: dismiss the remaining draft", async () => {
    await page.locator(".compliance-item", { hasText: "Morgan Reyes" }).getByText("Dismiss").click();
    await see("All clear");
    await page.getByRole("button", { name: "Minimize" }).click();
  });
  await step("run tests", async () => { await page.click("text=Run tests now"); await see("Test run complete"); });
  await step("controls table", async () => { await page.click("nav >> text=Controls"); await see("SB-04"); await see("SOC 2"); });
  await step("control evidence drawer", async () => {
    await page.click("text=SB-03 · "); await see("Evidence history"); await see("Runs every");
    await page.keyboard.press("Escape");
  });
  await step("evidence list", async () => { await page.click("nav >> text=Evidence"); await see("Permanent, timestamped"); await page.click("tbody tr >> nth=0"); await see("Test run"); await page.keyboard.press("Escape"); });
  await step("remediation update", async () => {
    await page.click("nav >> text=Remediation"); await see("Only passing evidence closes an item");
    await page.click("text=Update >> nth=0"); await page.selectOption("#rstatus", "in_progress");
    await page.fill("#rnote", "Bucket policy change in review"); await page.click("text=Save"); await see("Saved and recorded");
  });
  await step("remediation: cross-team demo is clearly labeled", async () => {
    await page.click("text=Needs: HR"); await see("Cross-team request"); await see("demo of what could be automated");
    await page.getByRole("button", { name: "Simulate send" }).click(); await see("Simulated");
  });
  await step("risk register and close a risk", async () => {
    await page.click("nav >> text=Risk register"); await see("Sample history (fictional)");
    await page.click("text=Close risk >> nth=0"); await page.fill("#cnote", "SB-03 passed after MFA enrollment; evidence reviewed.");
    await page.click("form button[type=submit]"); await see("closed. The register just shrank.");
  });
  await step("audit history verifies the chain", async () => {
    await page.click("nav >> text=Audit history"); await page.click("text=Verify the hash chain"); await see("Intact: 64 rows verified");
    if (await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1)) throw new Error("audit page scrolls sideways");
  });
  await step("activity log verifies the chain", async () => {
    await page.click("nav >> text=Activity log"); await see("Signed in"); await see("dashboard");
    await page.click("text=Verify the hash chain"); await see("Intact: 6 rows verified");
  });
  await step("dark mode", async () => {
    await page.click("text=Dark mode"); await page.waitForFunction(() => document.documentElement.dataset.theme !== "light");
    await page.click("nav >> text=Dashboard"); await see("Control health");
  });
  await step("phone width has no sideways scroll", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    const wide = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
    if (wide) throw new Error("page scrolls sideways at 390px");
    await page.setViewportSize({ width: 1360, height: 860 });
  });
  await step("sign out", async () => { await page.click("text=Sign out"); await page.locator("#email").waitFor(); if (await page.evaluate(() => sessionStorage.length)) throw new Error("session left in storage"); });

  if (!calls.some((c) => c.startsWith("POST /rest/v1/rpc/close_risk"))) problems.push("close_risk was never called");
  await browser.close();
  server.close();
  if (problems.length) { console.log("\nProblems:\n- " + problems.join("\n- ")); process.exit(1); }
  console.log("\nAll steps passed with no page errors or security-policy violations.");
})();
