// Content script (top frame of every page): the 99passwords icon in login
// fields, a dropdown under the field (the site's saved logins by name and
// username, or "generate and save" on signup forms), and Cmd+\ inside pages.
// It never sees passwords: picking a login asks the service worker to fill it.
"use strict";

(() => {
  if (window.top !== window || globalThis.__p99Content) return;
  globalThis.__p99Content = true;
  const send = msg => chrome.runtime.sendMessage(msg).catch(() => null);
  const ask = (entryId, mode) => {
    hide();
    const msg = { type: "p99_fill" };
    if (entryId) msg.entry_id = entryId;
    if (mode) msg.mode = mode;
    send(msg);
  };

  document.addEventListener("keydown", e => {
    if (!e.isTrusted) return;
    if ((e.metaKey || e.ctrlKey) && e.key === "\\") { e.preventDefault(); ask(); }
    if (menu.style.display === "none") return;
    const rows = [...menu.querySelectorAll(".row")];
    if (e.key === "Escape") { dismissed = true; menu.style.display = "none"; }
    else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const d = e.key === "ArrowDown" ? 1 : -1;
      highlight(active < 0 && d < 0 ? rows.length - 1 : (active + d + rows.length) % rows.length);
    } else if (e.key === "Enter" && active >= 0) {
      e.preventDefault();
      e.stopPropagation();
      rows[active].click();
    }
  }, true);

  const LOGO = `<svg viewBox="0 0 20 20" width="18" height="18" aria-hidden="true">
    <circle cx="10" cy="10" r="8.2" fill="#fff" stroke="#f8be00" stroke-width="3.2"/>
    <g transform="rotate(-35 10 10)">
      <rect x="8.7" y="11.6" width="2.6" height="3" rx=".5" fill="#4a5778"/>
      <rect x="7.4" y="4.9" width="5.2" height="7.6" rx="1.7" fill="#0f1d4b"/>
      <circle cx="10" cy="9.6" r="1.25" fill="#f8be00"/>
      <circle cx="8.9" cy="6.6" r=".7" fill="#d8dce6"/>
    </g></svg>`;
  const PADLOCK = `<svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true">
    <path d="M3.6 5.4V3.9a2.4 2.4 0 0 1 4.8 0v1.5" fill="none" stroke="#0f1d4b" stroke-width="1.4"/>
    <rect x="2.2" y="5.2" width="7.6" height="5.6" rx="1.2" fill="#0f1d4b"/></svg>`;

  const host = document.createElement("div");
  host.style.cssText = "all:initial;position:absolute;left:0;top:0;width:0;height:0;z-index:2147483647";
  const root = host.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = `
    .btn, .menu { all: initial; position: absolute; display: none; cursor: pointer; box-sizing: border-box; }
    .btn { width: 22px; height: 22px; border-radius: 11px; align-items: center; justify-content: center; }
    .btn:hover { background: rgba(15, 29, 75, .08); }
    .btn.locked { width: 38px; gap: 3px; background: #fff; border: 1px solid #c9cfdd; }
    .btn.locked:hover { background: #eef1f7; }
    .btn:hover::after { content: attr(data-tip); position: absolute; bottom: calc(100% + 8px); right: -4px;
      padding: 6px 10px; border-radius: 8px; background: #000; color: #fff; white-space: nowrap;
      font: 13px/1.2 -apple-system, system-ui, sans-serif; pointer-events: none; }
    .btn:hover::before { content: ""; position: absolute; bottom: calc(100% + 2px); right: 6px;
      border: 6px solid transparent; border-bottom: 0; border-top-color: #000; pointer-events: none; }
    svg { flex: none; }
    .menu { min-width: 260px; max-width: 340px; max-height: 300px; overflow-y: auto; padding: 4px;
      flex-direction: column; background: #fff; color: #0f1d4b; border: 1px solid #d8dce6; border-radius: 10px;
      box-shadow: 0 6px 20px rgba(15, 29, 75, .18); font: 13px/1.3 -apple-system, system-ui, sans-serif; }
    .row { display: flex; gap: 10px; align-items: center; padding: 7px 8px; border-radius: 7px; min-width: 0; }
    .row:hover, .row.on { background: #eef1f7; }
    .row div { min-width: 0; }
    .row b, .row span { display: block; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .row b { font-weight: 600; }
    .row span { color: #5a6480; font-size: 12px; }
    .row.action { padding: 6px 10px; }
    .row.action b { font-weight: 500; }
    .sep { height: 1px; background: #e3e6ee; margin: 4px 6px; }`;
  const btn = document.createElement("div");
  btn.className = "btn";
  // Locked: padlock + logo in one pill; clicking starts the unlock (the app
  // shows its panel), like the menu's "Unlock 99passwords" row.
  let locked = false;
  function setLocked(on) {
    if (on === locked) return;
    locked = on;
    btn.classList.toggle("locked", on);
    btn.dataset.tip = on ? "Unlock 99passwords" : "Fill with 99passwords";
    btn.innerHTML = on ? PADLOCK + LOGO : LOGO;
    place();
  }
  btn.dataset.tip = "Fill with 99passwords";
  btn.innerHTML = LOGO;
  const menu = document.createElement("div");
  menu.className = "menu";
  root.append(style, btn, menu);
  for (const el of [btn, menu]) el.addEventListener("mousedown", e => e.preventDefault()); // keep focus in the field
  // The field icon opens the full menu: saved logins, then actions.
  btn.addEventListener("click", async e => {
    if (!e.isTrusted || !field) return;
    if (locked) return ask();
    const el = field;
    const { hasPassword } = __p99.roleOf(el);
    const r = (await send({ type: "p99_has_match" })) || {};
    if (field !== el) return;
    if (r.locked) { setLocked(true); return ask(); }
    dismissed = false;
    const rows = loginRows(r);
    if (hasPassword) {
      rows.push(GENERATE);
      rows.push({ title: "Save new login", detail: "Save what you typed in 99passwords", mode: "save" });
    }
    rows.push({ title: "Open 99passwords", detail: "Search all your items" });
    offer(rows);
  });

  const GENERATE = { title: "Generate a strong password", detail: "Fill it in and save this login in 99passwords", mode: "signup" };
  const loginRows = r => (r.logins || []).map(l => ({ title: l.name, detail: l.username || "No username", entryId: l.id }));

  let field = null;
  let dismissed = false; // Escape hides the dropdown for this page
  let active = -1; // highlighted row (arrow keys)

  function highlight(i) {
    active = i;
    [...menu.querySelectorAll(".row")].forEach((r, j) => r.classList.toggle("on", j === i));
  }

  function place() {
    if (!field) return;
    const r = field.getBoundingClientRect();
    btn.style.left = `${r.right + scrollX - (locked ? 42 : 26)}px`;
    btn.style.top = `${r.top + scrollY + (r.height - 22) / 2}px`;
    menu.style.left = `${r.left + scrollX}px`;
    menu.style.top = `${r.bottom + scrollY + 4}px`;
  }

  // rows: [{ title, detail, entryId?, login? }]. Logins (entryId or login)
  // get the logo and a detail line; actions are compact text rows grouped
  // below a divider.
  function offer(rows) {
    const isLogin = r => !!(r.entryId || r.login);
    const make = r => {
      const row = document.createElement("div");
      const text = document.createElement("div");
      const b = document.createElement("b");
      b.textContent = r.title;
      text.append(b);
      if (isLogin(r)) {
        row.className = "row";
        row.innerHTML = LOGO;
        const s = document.createElement("span");
        s.textContent = r.detail;
        text.append(s);
      } else {
        row.className = "row action";
      }
      row.append(text);
      row.addEventListener("click", () => ask(r.entryId, r.mode)); // Enter on a row clicks it too
      return row;
    };
    const logins = rows.filter(isLogin).map(make);
    const actions = rows.filter(r => !isLogin(r)).map(make);
    const sep = document.createElement("div");
    sep.className = "sep";
    menu.replaceChildren(...logins, ...(logins.length && actions.length ? [sep] : []), ...actions);
    highlight(-1);
    menu.style.display = "flex";
  }

  function hide() {
    field = null;
    btn.style.display = menu.style.display = "none";
  }

  document.addEventListener("focusin", async e => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) || !globalThis.__p99) return;
    const { mode, unsure, hasPassword, role } = __p99.roleOf(el);
    if (!role) return;
    field = el;
    if (!host.isConnected) document.documentElement.append(host);
    place();
    btn.style.display = "flex";
    menu.style.display = "none";
    const match = send({ type: "p99_has_match" });
    match.then(r => { if (field === el && r) setLocked(!!r.locked); });
    if (dismissed) return;
    if (mode === "signup" && role !== "otp") return offer([GENERATE]);
    if (mode !== "login") return;
    const r = await match;
    if (field !== el || !r) return;
    // Could be a login or a signup page: offer both.
    const extra = unsure && hasPassword ? [GENERATE] : [];
    if (r.logins && r.logins.length) {
      offer([...loginRows(r), ...extra]);
    } else if (r.match) offer([{ title: `Fill login for ${location.hostname}`, detail: "From 99passwords", login: true }, ...extra]);
    else if (r.locked) offer([{ title: "Unlock 99passwords to fill", detail: "Your vault is locked" }]);
    else if (extra.length) offer(extra);
  }, true);
  document.addEventListener("focusout", e => { if (e.target === field) hide(); }, true);
  addEventListener("resize", place);

  // Hover shows the icon too (no dropdown until it is clicked).
  const menuOpen = () => menu.style.display !== "none";
  document.addEventListener("mouseover", async e => {
    const el = e.target;
    if (!(el instanceof HTMLInputElement) || el === field || !globalThis.__p99) return;
    if (field && (document.activeElement === field || menuOpen())) return; // keep the focused field's icon
    if (!__p99.roleOf(el).role) return;
    field = el;
    if (!host.isConnected) document.documentElement.append(host);
    place();
    btn.style.display = "flex";
    const r = await send({ type: "p99_has_match" });
    if (field === el && r) setLocked(!!r.locked);
  }, true);
  document.addEventListener("mouseout", e => {
    if (e.target !== field || e.relatedTarget === host || document.activeElement === field || menuOpen()) return;
    hide();
  }, true);
  host.addEventListener("mouseleave", e => {
    if (field && e.relatedTarget !== field && document.activeElement !== field && !menuOpen()) hide();
  });
  // A menu opened from a hovered (unfocused) field closes on a click elsewhere.
  document.addEventListener("mousedown", e => {
    if (e.target !== host && menuOpen() && document.activeElement !== field) hide();
  }, true);
})();
