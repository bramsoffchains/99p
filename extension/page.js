// Injected into the page's top frame (isolated world) by the service worker,
// or loaded as an optional content script. Finds fields and fills them.
"use strict";

if (!globalThis.__p99) {
  const inputs = () => [...document.querySelectorAll("input")].filter(el =>
    !["hidden", "submit", "button", "checkbox", "radio", "file", "image", "reset"].includes(el.type));
  const describe = el => {
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    return {
      type: el.type, autocomplete: el.autocomplete || el.getAttribute("autocomplete") || "",
      name: el.name, id: el.id, value: el.type === "password" ? "" : el.value,
      visible: r.width > 0 && r.height > 0 && st.visibility !== "hidden" && st.display !== "none" && !el.disabled && !el.readOnly,
    };
  };
  const set = (el, value) => {
    // Use the native setter so frameworks (React etc.) notice the change.
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    el.focus();
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  // Identity forms also use <select> (country, state) and <textarea> (street).
  const formFields = () => [...inputs(), ...document.querySelectorAll("select, textarea")];
  const labelOf = el => (el.labels && el.labels[0] ? el.labels[0].textContent : "") || el.getAttribute("aria-label") || "";
  const describeId = el => ({ ...describe(el), placeholder: el.placeholder || "", label: labelOf(el) });
  const setSelect = (el, value) => {
    const v = value.trim().toLowerCase();
    const opt = [...el.options].find(o => o.value.toLowerCase() === v || o.text.trim().toLowerCase() === v);
    if (!opt) return;
    el.value = opt.value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const setAny = (el, value) => {
    if (el instanceof HTMLSelectElement) return setSelect(el, value);
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    el.focus();
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };
  const fillIdentity = id => {
    const els = formFields();
    for (const { i, key } of P99.identityFields(els.map(describeId))) {
      const v = P99.identityValue(id, key);
      if (v && !els[i].value) setAny(els[i], v);
    }
  };

  // Signup-or-login clues around the form that holds `el` (or the first
  // password field), for P99.classify.
  const context = el => {
    const anchor = el || document.querySelector("input[type=password]");
    const scope = (anchor && anchor.closest("form")) || document;
    const text = nodes => [...nodes].slice(0, 20).map(n => n.value || n.textContent || "").join(" ").slice(0, 2000);
    const others = [...scope.querySelectorAll("input, select")].filter(f => f.type !== "password" && f.type !== "hidden").slice(0, 40);
    return {
      buttons: text(scope.querySelectorAll("button, input[type=submit], [role=button]")),
      headings: `${document.title} ${text(scope.querySelectorAll("h1, h2, legend"))} ${scope === document ? "" : text(document.querySelectorAll("h1"))}`,
      path: location.pathname,
      hints: others.map(f => `${f.name} ${f.id} ${f.autocomplete || ""} ${f.placeholder || ""} ${labelOf(f)}`),
    };
  };

  globalThis.__p99 = {
    // What the focused field is for: { mode, role: "username"|"password"|"otp"|null }.
    roleOf(el) {
      const els = inputs();
      const i = els.indexOf(el);
      const c = P99.classify(els.map(describe), context(el));
      const role = i < 0 ? null : i === c.username ? "username" : c.passwords.includes(i) ||
        (el.type === "password" && c.mode !== "totp") ? "password" : i === c.otp ? "otp" : null;
      return { mode: c.mode, unsure: c.unsure, hasPassword: c.passwords.length > 0, role };
    },
    // force: "signup" (generate) or "save" (save what was typed, password included).
    probe(force) {
      const els = inputs();
      const c = P99.classify(els.map(describe), context(document.activeElement instanceof HTMLInputElement ? document.activeElement : null));
      if (force === "save") {
        const pw = c.passwords.map(i => els[i].value).find(Boolean) || null;
        return { mode: "signup", username: c.usernameValue, password: pw };
      }
      if (force === "signup" && c.passwords.length) return { mode: "signup", username: c.usernameValue };
      const mode = P99.isIdentityPage(formFields().map(describeId)) ? "identity" : c.mode;
      return { mode, username: c.usernameValue };
    },
    // creds: { username, password, totp, identity }. Fills only if we are still on `origin`.
    fill(creds, origin) {
      if (location.origin !== origin) return false;
      if (creds.identity) { fillIdentity(creds.identity); return true; }
      const els = inputs();
      const c = P99.classify(els.map(describe), context(null));
      if (creds.username && c.username !== null && !els[c.username].value) set(els[c.username], creds.username);
      // A signup the user asked for fills every visible password field.
      const pws = creds.signup ? els.map((el, i) => i).filter(i => els[i].type === "password" && describe(els[i]).visible) : c.passwords;
      if (creds.password) for (const i of pws) set(els[i], creds.password);
      if (creds.totp && c.otp !== null) set(els[c.otp], creds.totp);
      return true;
    },
  };
}
