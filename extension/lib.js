// Pure helpers shared by the service worker and the injected page script.
// No DOM or chrome.* access here, so it can be unit-tested with `node --test`.
"use strict";

const YKV = (() => {
  const MAX_FAVICON = 8 * 1024;

  // Host and origin for a tab URL, or null for anything that is not a web page.
  function siteFromUrl(url) {
    let u;
    try { u = new URL(url); } catch { return null; }
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (!host) return null;
    return { host, origin: u.origin };
  }

  const SIGNUP_WORDS = /sign.?up|register|create.{0,12}account|join|get started|new account|s.inscrire|inscription|cr[ée]er/;
  const LOGIN_WORDS = /log.?in|sign.?in|se connecter|connexion|forgot|welcome back/;

  // Signup vs login score from everything but the password fields' count and
  // autocomplete (classify adds those). ctx (all optional, from the page):
  // { buttons: submit/button text near the form, headings: h1/h2/legend/title
  // text, path: location.pathname, hints: ["name id autocomplete placeholder
  // label"] of the form's other fields and checkboxes }.
  function contextScore(ctx = {}) {
    let s = 0;
    const lc = v => (v || "").toLowerCase();
    const buttons = lc(ctx.buttons), headings = lc(ctx.headings), path = lc(ctx.path);
    if (SIGNUP_WORDS.test(buttons)) s += 2;
    if (LOGIN_WORDS.test(buttons)) s -= 2;
    if (SIGNUP_WORDS.test(headings)) s += 1;
    if (LOGIN_WORDS.test(headings)) s -= 1;
    if (/sign.?up|register|join|create|onboard/.test(path)) s += 1;
    if (/log.?in|sign.?in|auth|session/.test(path)) s -= 1;
    const hints = (ctx.hints || []).map(lc);
    if (hints.some(h => /given-name|family-name|first.?name|last.?name|full.?name|\bname\b/.test(h))) s += 1;
    if (hints.some(h => /bday|birth|date.?of.?birth|\bdob\b/.test(h))) s += 1;
    if (hints.some(h => /terms|agree|\btos\b|privacy|conditions/.test(h))) s += 1;
    return s;
  }

  // fields: [{ type, autocomplete, name, id, visible, value }] from the page.
  // Returns the fill mode and the indexes of the fields to fill. `unsure`
  // means the page could be either a login or a signup (offer both).
  function classify(fields, ctx) {
    const vis = fields.map((f, i) => ({ ...f, i })).filter(f => f.visible);
    const ac = f => (f.autocomplete || "").toLowerCase();
    const hint = f => `${f.name || ""} ${f.id || ""}`.toLowerCase();
    const isOtp = f => ac(f).includes("one-time-code") ||
      (f.type !== "password" && /\b(otp|totp|2fa|mfa)\b|one.?time|verification.?code|auth.?code/.test(hint(f)));
    const passwords = vis.filter(f => f.type === "password");
    const otp = vis.filter(f => !passwords.includes(f) && isOtp(f));
    const hasCurrent = passwords.some(f => ac(f).includes("current-password"));
    let score = contextScore(ctx);
    if (passwords.some(f => ac(f).includes("new-password"))) score += 5;
    if (hasCurrent) score -= 5;
    if (passwords.length >= 2 && !hasCurrent) score += 3;
    if (passwords.length === 1) score -= 1;
    const userish = f => ["text", "email", "tel", ""].includes(f.type || "") && !isOtp(f) &&
      (/username|email/.test(ac(f)) || /user|email|login|account|identifier/.test(hint(f)));
    const firstPw = passwords.length ? passwords[0].i : Infinity;
    const users = vis.filter(f => userish(f) && f.i < firstPw);
    const user = users.length ? users[users.length - 1] : null;

    let mode = "login";
    if (passwords.length === 0 && otp.length > 0) mode = "totp";
    else if (score >= 2) mode = "signup";
    return {
      mode,
      unsure: mode === "login" && passwords.length > 0 && score > -2,
      username: user ? user.i : null,
      usernameValue: user && user.value ? user.value : null,
      passwords: (mode === "signup" ? passwords : passwords.slice(0, 1)).map(f => f.i),
      otp: otp.length ? otp[0].i : null,
    };
  }

  // ---- Identity (name, email, phone, address) autofill ----

  // Autocomplete tokens (WHATWG) to identity keys.
  const AC_KEYS = {
    "given-name": "given", "family-name": "family", "name": "name", "email": "email", "tel": "tel",
    "tel-national": "tel", "street-address": "street", "address-line1": "line1", "address-line2": "line2",
    "address-level2": "city", "postal-code": "postcode", "address-level1": "region",
    "country": "country", "country-name": "country",
  };
  // Fallback: name/id/placeholder/label hints, most specific first.
  const HINTS = [
    ["email", /e-?mail/],
    ["given", /first.?name|given.?name|fname|prenom|vorname/],
    ["family", /last.?name|family.?name|surname|lname|nom.?de.?famille|nachname/],
    ["line2", /address.?(line)?.?2|addr.?2|apartment|suite/],
    ["line1", /address.?(line)?.?1|addr.?1/],
    ["postcode", /zip|postal|post.?code|postcode|plz/],
    ["city", /city|town|locality|ville/],
    ["region", /state|province|region|county/],
    ["country", /country|pays/],
    ["street", /street|address|adresse/],
    ["tel", /phone|mobile|^tel/],
    ["name", /full.?name|^name$|your.?name/],
  ];

  // f: { type, autocomplete, name, id, placeholder, label }. Returns a key or null.
  function identityKey(f) {
    if (["password", "hidden", "search", "number", "date", "url"].includes(f.type)) return null;
    const tokens = (f.autocomplete || "").toLowerCase().split(/\s+/);
    for (const t of tokens) if (AC_KEYS[t]) return AC_KEYS[t];
    if (tokens.some(t => ["username", "one-time-code", "new-password", "current-password"].includes(t))) return null;
    if (f.type === "email") return "email";
    if (f.type === "tel") return "tel";
    const h = [f.name, f.id, f.placeholder, f.label].map(x => (x || "").toLowerCase().trim());
    for (const [key, re] of HINTS) if (h.some(x => re.test(x))) return key;
    return null;
  }

  // Indexes and keys of the visible identity fields.
  function identityFields(fields) {
    return fields.map((f, i) => ({ i, key: f.visible ? identityKey(f) : null })).filter(x => x.key);
  }

  // A page with no password or code field but at least two identity fields
  // (e.g. a checkout or contact form) asks for an identity.
  function isIdentityPage(fields) {
    const c = classify(fields);
    return c.passwords.length === 0 && c.otp === null && identityFields(fields).length >= 2;
  }

  // id: { first_name, last_name, email, phone, street, city, postcode, region, country }.
  function identityValue(id, key) {
    const lines = (id.street || "").split("\n").map(l => l.trim()).filter(Boolean);
    switch (key) {
      case "given": return id.first_name || null;
      case "family": return id.last_name || null;
      case "name": return [id.first_name, id.last_name].filter(Boolean).join(" ") || null;
      case "email": return id.email || null;
      case "tel": return id.phone || null;
      case "street": return lines.join(", ") || null;
      case "line1": return lines[0] || null;
      case "line2": return lines.slice(1).join(", ") || null;
      case "city": return id.city || null;
      case "postcode": return id.postcode || null;
      case "region": return id.region || null;
      case "country": return id.country || null;
      default: return null;
    }
  }

  // entryId: the login the user picked in the field dropdown (the app checks
  // it matches the host, then fills without showing the panel).
  // password: "Save new login" sends what the user typed (signup mode only).
  function fillRequest(reqId, mode, site, username, faviconPng, entryId, password) {
    const m = { v: 1, type: "fill_request", req_id: reqId, mode, host: site.host, origin: site.origin };
    if (isEntryId(entryId)) m.entry_id = entryId;
    if (mode === "signup" && typeof password === "string" && password && password.length <= 1024) m.password = password;
    if (username) m.username = username;
    if (faviconPng) m.favicon_png = faviconPng;
    return m;
  }

  // A reply is only used if it answers this request for this host.
  function acceptFill(reply, reqId, host) {
    return !!reply && reply.v === 1 && reply.type === "fill" && reply.req_id === reqId && reply.host === host;
  }

  // "Does the vault have a login for this host?" Reveals nothing else, and
  // the app answers false while locked.
  function hasMatchRequest(reqId, host) {
    return { v: 1, type: "has_match", req_id: reqId, host };
  }

  const isEntryId = id => typeof id === "string" && /^[0-9]{1,20}$/.test(id);
  const MAX_LOGINS = 20;

  // logins: names and usernames only (no secrets), for the field dropdown.
  function acceptHasMatch(reply, reqId) {
    if (!reply || reply.v !== 1 || reply.type !== "has_match" || reply.req_id !== reqId) {
      return { match: false, locked: false, ok: false, logins: [] };
    }
    const str = (v, n) => typeof v === "string" && v ? v.slice(0, n) : null;
    const logins = (Array.isArray(reply.logins) ? reply.logins : [])
      .filter(l => l && isEntryId(l.id) && str(l.name, 200))
      .slice(0, MAX_LOGINS)
      .map(l => ({ id: l.id, name: str(l.name, 200), username: str(l.username, 200) }));
    return { match: reply.match === true, locked: reply.locked === true, ok: true, logins };
  }

  function base64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  }

  // PNG signature and 32x32 IHDR (SPEC §10).
  function isFaviconPng(bytes) {
    if (bytes.length < 24 || bytes.length > MAX_FAVICON) return false;
    const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    if (!sig.every((b, i) => bytes[i] === b)) return false;
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return dv.getUint32(16) === 32 && dv.getUint32(20) === 32;
  }

  return { siteFromUrl, classify, contextScore, identityKey, identityFields, isIdentityPage, identityValue, fillRequest, acceptFill,
    hasMatchRequest, acceptHasMatch, isEntryId, base64, isFaviconPng, MAX_FAVICON };
})();

if (typeof module !== "undefined") module.exports = YKV;
