"use strict";
const test = require("node:test");
const assert = require("node:assert");
const P99 = require("../lib.js");

const f = (type, extra = {}) => ({ type, autocomplete: "", name: "", id: "", visible: true, value: "", ...extra });

test("siteFromUrl takes host and origin, web pages only", () => {
  assert.deepStrictEqual(P99.siteFromUrl("https://GitHub.com/login?x=1"), { host: "github.com", origin: "https://github.com" });
  // The host is normalised; the origin stays what the page reports, for the fill check.
  assert.deepStrictEqual(P99.siteFromUrl("https://github.com./"), { host: "github.com", origin: "https://github.com." });
  assert.deepStrictEqual(P99.siteFromUrl("http://app.example.com:8080/"), { host: "app.example.com", origin: "http://app.example.com:8080" });
  assert.strictEqual(P99.siteFromUrl("https://user:pw@evil.net@github.com/").host, "github.com");
  for (const u of ["chrome://settings", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,x", "not a url"]) {
    assert.strictEqual(P99.siteFromUrl(u), null, u);
  }
});

test("classify: plain login", () => {
  const c = P99.classify([f("text", { name: "login", value: "alice" }), f("password")]);
  // No other clues: could be either, so the dropdown offers both.
  assert.deepStrictEqual(c, { mode: "login", unsure: true, username: 0, usernameValue: "alice", passwords: [1], otp: null });
});

test("classify: signup via new-password or two password fields", () => {
  const a = P99.classify([f("email", { autocomplete: "email" }), f("password", { autocomplete: "new-password" }), f("password", { autocomplete: "new-password" })]);
  assert.strictEqual(a.mode, "signup");
  assert.deepStrictEqual(a.passwords, [1, 2]);
  assert.strictEqual(P99.classify([f("text", { id: "username" }), f("password"), f("password")]).mode, "signup");
  // Change-password form with current-password is a login-style fill of the first field.
  const b = P99.classify([f("password", { autocomplete: "current-password" }), f("password")]);
  assert.strictEqual(b.mode, "login");
  assert.deepStrictEqual(b.passwords, [0]);
});

test("classify: TOTP page", () => {
  const c = P99.classify([f("text", { autocomplete: "one-time-code" })]);
  assert.strictEqual(c.mode, "totp");
  assert.strictEqual(c.otp, 0);
  assert.strictEqual(P99.classify([f("tel", { name: "otp" })]).mode, "totp");
});

test("classify ignores hidden fields", () => {
  const c = P99.classify([f("text", { name: "user", visible: false }), f("password", { visible: false }), f("text", { name: "q" })]);
  assert.deepStrictEqual(c, { mode: "login", unsure: false, username: null, usernameValue: null, passwords: [], otp: null });
});

test("fillRequest and acceptFill", () => {
  const site = { host: "github.com", origin: "https://github.com" };
  assert.deepStrictEqual(P99.fillRequest("r1", "login", site, null, null),
    { v: 1, type: "fill_request", req_id: "r1", mode: "login", host: "github.com", origin: "https://github.com" });
  assert.strictEqual(P99.fillRequest("r1", "signup", site, "a", "AAA").favicon_png, "AAA");
  const ok = { v: 1, type: "fill", req_id: "r1", host: "github.com", password: "x" };
  assert.ok(P99.acceptFill(ok, "r1", "github.com"));
  assert.ok(!P99.acceptFill({ ...ok, req_id: "r2" }, "r1", "github.com"));
  assert.ok(!P99.acceptFill({ ...ok, host: "github.com.evil.net" }, "r1", "github.com"));
  assert.ok(!P99.acceptFill({ ...ok, type: "cancel" }, "r1", "github.com"));
  assert.ok(!P99.acceptFill(null, "r1", "github.com"));
});

test("isFaviconPng checks signature, 32x32 and size", () => {
  const png = new Uint8Array(64);
  png.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 32, 0, 0, 0, 32]);
  assert.ok(P99.isFaviconPng(png));
  const big = png.slice(); big[19] = 64;
  assert.ok(!P99.isFaviconPng(big));
  const bad = png.slice(); bad[0] = 0;
  assert.ok(!P99.isFaviconPng(bad));
  const huge = new Uint8Array(P99.MAX_FAVICON + 1); huge.set(png.subarray(0, 24));
  assert.ok(!P99.isFaviconPng(huge));
  assert.strictEqual(P99.base64(new Uint8Array([104, 105])), "aGk=");
});

test("has_match: request carries only the host; reply must answer it", () => {
  assert.deepStrictEqual(P99.hasMatchRequest("m1", "github.com"), { v: 1, type: "has_match", req_id: "m1", host: "github.com" });
  assert.deepStrictEqual(P99.acceptHasMatch({ v: 1, type: "has_match", req_id: "m1", match: true, locked: false }, "m1"),
    { match: true, locked: false, ok: true, logins: [] });
  const r = P99.acceptHasMatch({ v: 1, type: "has_match", req_id: "m1", match: true, logins: [
    { id: "12", name: "GitHub", username: "alice", password: "leak" }, { id: "x", name: "bad id" },
    { id: "13", name: "" }, { id: "14", name: "Work" }] }, "m1");
  assert.deepStrictEqual(r.logins, [{ id: "12", name: "GitHub", username: "alice" }, { id: "14", name: "Work", username: null }]);
  assert.strictEqual(P99.fillRequest("r1", "login", { host: "a.com", origin: "https://a.com" }, null, null, "12").entry_id, "12");
  assert.strictEqual(P99.fillRequest("r1", "login", { host: "a.com", origin: "https://a.com" }, null, null, "1; x").entry_id, undefined);
  assert.strictEqual(P99.acceptHasMatch({ v: 1, type: "has_match", req_id: "other", match: true }, "m1").match, false);
  assert.strictEqual(P99.acceptHasMatch({ v: 1, type: "has_match", req_id: "m1", match: "yes" }, "m1").match, false);
  assert.strictEqual(P99.acceptHasMatch({ v: 1, type: "error", code: "app_unavailable" }, "m1").ok, false);
  assert.strictEqual(P99.acceptHasMatch(null, "m1").ok, false);
});

test("identityKey: autocomplete first, then name/id/placeholder hints", () => {
  assert.strictEqual(P99.identityKey(f("text", { autocomplete: "shipping given-name" })), "given");
  assert.strictEqual(P99.identityKey(f("text", { autocomplete: "section-a billing address-level2" })), "city");
  assert.strictEqual(P99.identityKey(f("text", { name: "billing_zip" })), "postcode");
  assert.strictEqual(P99.identityKey(f("text", { placeholder: "Last name" })), "family");
  assert.strictEqual(P99.identityKey(f("text", { label: "Email address" })), "email");
  assert.strictEqual(P99.identityKey(f("tel")), "tel");
  assert.strictEqual(P99.identityKey(f("select-one", { id: "country" })), "country");
  assert.strictEqual(P99.identityKey(f("text", { autocomplete: "username", name: "email" })), null);
  assert.strictEqual(P99.identityKey(f("password", { name: "email" })), null);
  assert.strictEqual(P99.identityKey(f("text", { name: "q" })), null);
});

test("isIdentityPage: identity forms only, never login or code pages", () => {
  const checkout = [f("text", { autocomplete: "name" }), f("email"), f("text", { name: "city" })];
  assert.ok(P99.isIdentityPage(checkout));
  assert.ok(!P99.isIdentityPage([f("email"), f("password")]));
  assert.ok(!P99.isIdentityPage([f("text", { autocomplete: "one-time-code" }), f("email"), f("tel")]));
  assert.ok(!P99.isIdentityPage([f("email")]));
  assert.ok(!P99.isIdentityPage([f("email", { visible: false }), f("tel")]));
});

test("identityValue: names and address lines", () => {
  const id = { first_name: "Ada", last_name: "Lovelace", street: "1 Analytical Way\nFlat 2", country: "GB" };
  assert.strictEqual(P99.identityValue(id, "name"), "Ada Lovelace");
  assert.strictEqual(P99.identityValue(id, "line1"), "1 Analytical Way");
  assert.strictEqual(P99.identityValue(id, "line2"), "Flat 2");
  assert.strictEqual(P99.identityValue(id, "street"), "1 Analytical Way, Flat 2");
  assert.strictEqual(P99.identityValue(id, "tel"), null);
});

// Realistic pages: fields plus the clues page.js collects around the form.
const PAGES = {
  githubLogin: [[f("text", { name: "login", autocomplete: "username" }), f("password", { autocomplete: "current-password" })],
    { buttons: "Sign in", headings: "Sign in to GitHub", path: "/login", hints: ["login login_field username  Username or email address"] }],
  plainLogin: [[f("email", { name: "email" }), f("password", { name: "password" })],
    { buttons: "Log in Forgot password?", headings: "Welcome back", path: "/account", hints: ["email"] }],
  oneFieldSignup: [[f("email", { name: "email" }), f("password", { name: "password" })],
    { buttons: "Create account", headings: "Get started", path: "/signup", hints: ["email"] }],
  namesAndTerms: [[f("text", { name: "first_name" }), f("text", { name: "last_name" }), f("email", { name: "email" }), f("password", { name: "pw" })],
    { buttons: "Continue", headings: "Create your account", path: "/", hints: ["first_name", "last_name", "email", "terms  I agree to the Terms"] }],
  frenchSignup: [[f("email", { name: "mail" }), f("password", { name: "mdp" })],
    { buttons: "Créer mon compte", headings: "Inscription", path: "/inscription", hints: ["mail"] }],
  ambiguous: [[f("email", { name: "email" }), f("password", { name: "password" })],
    { buttons: "Continue", headings: "Acme", path: "/", hints: ["email"] }],
};

test("classify: realistic login and signup pages", () => {
  const got = Object.fromEntries(Object.entries(PAGES).map(([k, [fields, ctx]]) => {
    const c = P99.classify(fields, ctx);
    return [k, c.mode === "signup" ? "signup" : c.unsure ? "unsure" : "login"];
  }));
  assert.deepStrictEqual(got, {
    githubLogin: "login", plainLogin: "login", oneFieldSignup: "signup", namesAndTerms: "signup",
    frenchSignup: "signup", ambiguous: "unsure",
  });
  // Signup fills the one password field and keeps the email as the username.
  const c = P99.classify(...PAGES.oneFieldSignup);
  assert.deepStrictEqual([c.username, c.passwords], [0, [1]]);
});

test("fillRequest sends a typed password only for signup (Save new login)", () => {
  const site = { host: "a.com", origin: "https://a.com" };
  assert.strictEqual(P99.fillRequest("r1", "signup", site, "u", null, undefined, "typed").password, "typed");
  assert.strictEqual(P99.fillRequest("r1", "login", site, "u", null, undefined, "typed").password, undefined);
});
