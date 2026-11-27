// End-to-end in real Chromium: extension -> native messaging -> 99p-bridge
// -> Unix socket -> fake app -> fill back into the page.
// Usage: cargo build -p p99-bridge && node extension/e2e/run.js
"use strict";
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const assert = require("node:assert");
const { chromium } = require("playwright");
const { startFakeApp } = require("./fake-app.js");

const ROOT = path.resolve(__dirname, "../..");
const BRIDGE = path.join(ROOT, "target/debug/99p-bridge");
const EXT_ID = "bjppeeoihhidakjbpmbpmhcddcebiieg"; // fixed by the test key below

const PAGES = {
  "/login": `<form><input name="login" autocomplete="username"><input type="password" name="pw"></form>`,
  "/signup": `<form><input type="email" autocomplete="email"><input type="password" autocomplete="new-password"><input type="password" autocomplete="new-password"></form>`,
  "/otp": `<form><input autocomplete="one-time-code"></form>`,
  "/join": `<h1>Create your account</h1><form><input type="email" name="email"><input type="password" name="pw"><button>Create account</button></form>`,
  "/start": `<form><input type="email" name="email"><input type="password" name="pw"><button>Continue</button></form>`,
  "/address": `<form><input name="fullname" autocomplete="name"><input type="email" name="mail">` +
    `<textarea name="address"></textarea><input name="zip"><select name="country"><option value="">-</option>` +
    `<option value="FR">France</option><option value="GB">United Kingdom</option></select></form>`,
};

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "p99-e2e-"));
  const sock = path.join(tmp, "bridge.sock");

  // Copy the extension with a fixed key (stable id) and host access for the test.
  const ext = path.join(tmp, "ext");
  fs.mkdirSync(ext);
  fs.cpSync(path.join(ROOT, "extension"), ext, { recursive: true, filter: f => !/\/(e2e|test)$/.test(f) });
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, "extension/manifest.json")));
  manifest.key = fs.readFileSync(path.join(__dirname, "test-key.txt"), "utf8").trim();
  manifest.host_permissions = ["http://127.0.0.1/*"];
  fs.writeFileSync(path.join(ext, "manifest.json"), JSON.stringify(manifest));

  // Native messaging host manifest; on Linux Chromium reads it from the profile.
  const profile = path.join(tmp, "profile");
  fs.mkdirSync(path.join(profile, "NativeMessagingHosts"), { recursive: true });
  const wrapper = path.join(tmp, "bridge.sh");
  fs.writeFileSync(wrapper, `#!/bin/sh\nP99_BRIDGE_SOCK='${sock}' exec '${BRIDGE}' "$@"\n`, { mode: 0o755 });
  fs.writeFileSync(path.join(profile, "NativeMessagingHosts/app.99passwords.bridge.json"), JSON.stringify({
    name: "app.99passwords.bridge", description: "99passwords bridge", path: wrapper, type: "stdio",
    allowed_origins: [`chrome-extension://${EXT_ID}/`],
  }));

  let locked = false;
  const app = await startFakeApp(sock, m => {
    if (m.type === "hello") return { v: 1, type: "hello", app_version: "test", locked: false };
    if (m.type === "has_match" && locked) return { v: 1, type: "has_match", req_id: m.req_id, match: false, locked: true, logins: [] };
    if (m.type === "has_match") {
      return { v: 1, type: "has_match", req_id: m.req_id, match: true, locked: false,
        logins: [{ id: "7", name: "Personal", username: "alice" }, { id: "9", name: "Work", username: "alice@work.example" }] };
    }
    if (m.type !== "fill_request") return null;
    const base = { v: 1, type: "fill", req_id: m.req_id, host: m.host };
    if (m.mode === "login" && m.entry_id === "9") return { ...base, username: "alice@work.example", password: "work-pw" };
    if (m.mode === "login") return { ...base, username: "alice", password: "hunter2" };
    if (m.mode === "signup") return { ...base, username: m.username || "new@example.com", password: m.password || "Gen-erated-1" };
    if (m.mode === "identity") {
      return { ...base, identity: { first_name: "Ada", last_name: "Lovelace", email: "ada@example.com",
        street: "1 Analytical Way\nFlat 2", postcode: "N1 9GU", country: "GB" } };
    }
    return { ...base, totp: "123456" };
  });

  const web = http.createServer((q, r) => r.end(`<!doctype html><body>${PAGES[q.url] || ""}</body>`));
  await new Promise(r => web.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${web.address().port}`;

  const ctx = await chromium.launchPersistentContext(profile, {
    headless: true, channel: "chromium",
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  try {
    let [sw] = ctx.serviceWorkers();
    if (!sw) sw = await ctx.waitForEvent("serviceworker");
    assert.ok(sw.url().startsWith(`chrome-extension://${EXT_ID}/`), sw.url());
    const page = await ctx.newPage();
    const fill = async url => {
      await page.goto(base + url);
      await sw.evaluate(async u => {
        const [tab] = await chrome.tabs.query({ url: u });
        await startFill(tab);
      }, base + url);
    };

    await fill("/login");
    assert.strictEqual(await page.inputValue("input[name=login]"), "alice");
    assert.strictEqual(await page.inputValue("input[name=pw]"), "hunter2");

    await fill("/signup");
    const pws = await page.$$eval("input[type=password]", els => els.map(e => e.value));
    assert.deepStrictEqual(pws, ["Gen-erated-1", "Gen-erated-1"]);
    assert.strictEqual(await page.inputValue("input[type=email]"), "new@example.com");

    await fill("/otp");
    assert.strictEqual(await page.inputValue("input"), "123456");

    await fill("/address");
    assert.strictEqual(await page.inputValue("input[name=fullname]"), "Ada Lovelace");
    assert.strictEqual(await page.inputValue("input[name=mail]"), "ada@example.com");
    assert.strictEqual(await page.inputValue("textarea"), "1 Analytical Way, Flat 2");
    assert.strictEqual(await page.inputValue("input[name=zip]"), "N1 9GU");
    assert.strictEqual(await page.inputValue("select"), "GB");

    // Inline: focusing a field shows the icon at its right edge; clicking it
    // opens the menu (logins, Generate, Save new login, Open 99passwords).
    const clickIcon = async (url, sel, keys, before) => {
      await page.goto(base + url);
      await page.waitForTimeout(300); // content script at document_idle
      if (before) await before();
      await page.focus(sel);
      const r = await page.$eval(sel, el => { const b = el.getBoundingClientRect(); return { x: b.right - 15, y: b.top + b.height / 2 }; });
      await page.mouse.click(r.x, r.y);
      await page.waitForTimeout(300);
      for (const k of keys) await page.keyboard.press(k);
    };
    await clickIcon("/login", "input[name=pw]", ["ArrowDown", "Enter"]);
    await page.waitForFunction(() => document.querySelector("input[name=pw]").value === "hunter2");
    // Hover (no focus) also shows the icon; clicking it opens the same menu.
    await page.goto(base + "/login");
    await page.waitForTimeout(300);
    const box = await page.$eval("input[name=pw]", el => { const b = el.getBoundingClientRect(); return { l: b.left, r: b.right, y: b.top + b.height / 2 }; });
    await page.mouse.move(box.l + 5, box.y);
    await page.mouse.move(box.r - 15, box.y, { steps: 5 });
    await page.mouse.click(box.r - 15, box.y);
    await page.waitForTimeout(300);
    assert.notStrictEqual(await page.evaluate(() => document.activeElement && document.activeElement.name), "pw");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("input[name=pw]").value === "hunter2");
    // "Save new login" (second to last) sends what was typed.
    await clickIcon("/login", "input[name=pw]", ["ArrowUp", "ArrowUp", "Enter"], async () => {
      await page.fill("input[name=login]", "typed@example.com");
      await page.fill("input[name=pw]", "my-typed-pw");
    });
    await page.waitForTimeout(500);
    // The dropdown lists every saved login; arrow keys + Enter pick the second.
    await page.goto(base + "/login");
    await page.waitForTimeout(300);
    await page.focus("input[name=pw]");
    await page.waitForTimeout(300); // has_match round trip
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("Enter");
    await page.waitForFunction(() => document.querySelector("input[name=pw]").value === "work-pw");
    assert.strictEqual(await page.inputValue("input[name=login]"), "alice@work.example");
    // Signup with a single password field: the only offer is "generate".
    const pick = async (url, keys) => {
      await page.goto(base + url);
      await page.waitForTimeout(300);
      await page.focus("input[name=pw]");
      await page.waitForTimeout(300);
      for (const k of keys) await page.keyboard.press(k);
    };
    await pick("/join", ["ArrowDown", "Enter"]);
    await page.waitForFunction(() => document.querySelector("input[name=pw]").value === "Gen-erated-1");
    // Could be either: the saved logins and "generate" (last row).
    await pick("/start", ["ArrowUp", "Enter"]);
    await page.waitForFunction(() => document.querySelector("input[name=pw]").value === "Gen-erated-1");
    await clickIcon("/signup", "input[type=password]", ["ArrowDown", "ArrowDown", "ArrowDown", "Enter"]);
    await page.waitForFunction(() => document.querySelector("input[type=password]").value === "Gen-erated-1");

    // Locked: the icon becomes a padlock + logo pill; one click starts the
    // unlock (a plain fill request; the app shows its panel), no menu.
    locked = true;
    await sw.evaluate(() => matchCache.clear());
    await page.goto(base + "/login");
    await page.waitForTimeout(300);
    await page.addStyleTag({ content: "body { padding: 50px 20px } input { width: 280px; height: 36px }" }); // room for the tooltip
    const lb = await page.$eval("input[name=pw]", el => { const b = el.getBoundingClientRect(); return { l: b.left, r: b.right, y: b.top + b.height / 2 }; });
    await page.mouse.move(lb.l + 5, lb.y);
    await page.mouse.move(lb.r - 15, lb.y, { steps: 5 });
    await page.waitForTimeout(300); // has_match round trip turns it into the pill
    if (process.env.P99_SHOT) await page.screenshot({ path: process.env.P99_SHOT, clip: { x: 0, y: 0, width: 700, height: 110 } });
    await page.mouse.click(lb.r - 15, lb.y);
    await page.waitForFunction(() => document.querySelector("input[name=pw]").value === "hunter2");
    locked = false;

    // The toolbar dot asks only "is there a login for this host?".
    const matches = app.seen.filter(m => m.type === "has_match");
    assert.ok(matches.length > 0, "no has_match query");
    for (const m of matches) assert.deepStrictEqual(Object.keys(m).sort(), ["host", "req_id", "type", "v"]);
    assert.ok(matches.every(m => m.host === "127.0.0.1"));

    const reqs = app.seen.filter(m => m.type === "fill_request");
    assert.deepStrictEqual(reqs.map(m => m.mode), ["login", "signup", "totp", "identity", "login", "login", "signup", "login", "signup", "signup", "signup", "login"]);
    assert.deepStrictEqual(reqs.map(m => m.entry_id), [undefined, undefined, undefined, undefined, "7", "7", undefined, "9", undefined, undefined, undefined, undefined]);
    const saved = reqs[6];
    assert.deepStrictEqual([saved.username, saved.password], ["typed@example.com", "my-typed-pw"]);
    assert.ok(reqs.every((m, i) => i === 6 || m.password === undefined), "password sent outside Save new login");
    for (const m of reqs) {
      assert.strictEqual(m.host, "127.0.0.1");
      assert.strictEqual(m.origin, base);
    }
    const bh = app.seen.find(m => m.type === "bridge_hello");
    assert.strictEqual(bh.caller_origin, `chrome-extension://${EXT_ID}/`);
    console.log(`e2e ok: ${reqs.length} fills, ${matches.length} match checks; favicon sent: ${reqs.some(m => m.favicon_png)}`);
  } finally {
    await ctx.close();
    web.close();
    app.server.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

main().catch(e => { console.error(e); process.exit(1); });
