// Service worker: the only part of the extension that talks to the app.
// Host and origin always come from the browser (tab.url), never from the page.
"use strict";
importScripts("lib.js");

const HOST_NAME = "app.99passwords.bridge";
const TIMEOUT_MS = 3 * 60 * 1000; // the user may need to unlock and touch the key
const MATCH_TIMEOUT_MS = 8000; // the bridge may launch the app first

let port = null;
const pending = new Map(); // req_id -> { resolve, timer }

function settle(reqId, reply) {
  const p = pending.get(reqId);
  if (!p) return;
  clearTimeout(p.timer);
  pending.delete(reqId);
  p.resolve(reply);
}

function getPort() {
  if (port) return port;
  port = chrome.runtime.connectNative(HOST_NAME);
  port.onMessage.addListener(msg => {
    if (msg && typeof msg.req_id === "string") settle(msg.req_id, msg);
    else if (msg && msg.type === "error") for (const id of [...pending.keys()]) settle(id, msg);
  });
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    port = null;
    for (const id of [...pending.keys()]) settle(id, { v: 1, type: "error", code: "disconnected", detail: err && err.message });
  });
  port.postMessage({ v: 1, type: "hello", ext_version: chrome.runtime.getManifest().version });
  return port;
}

function request(msg, timeoutMs = TIMEOUT_MS) {
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      settle(msg.req_id, { v: 1, type: "error", req_id: msg.req_id, code: "timeout" });
      if (port && msg.type === "fill_request") port.postMessage({ v: 1, type: "cancel", req_id: msg.req_id });
    }, timeoutMs);
    pending.set(msg.req_id, { resolve, timer });
    try { getPort().postMessage(msg); } catch (e) { settle(msg.req_id, { v: 1, type: "error", code: "disconnected" }); }
  });
}

async function favicon(pageUrl) {
  try {
    const u = new URL(chrome.runtime.getURL("/_favicon/"));
    u.searchParams.set("pageUrl", pageUrl);
    u.searchParams.set("size", "32");
    const img = await createImageBitmap(await (await fetch(u)).blob());
    const canvas = new OffscreenCanvas(32, 32);
    canvas.getContext("2d").drawImage(img, 0, 0, 32, 32);
    const bytes = new Uint8Array(await (await canvas.convertToBlob({ type: "image/png" })).arrayBuffer());
    return P99.isFaviconPng(bytes) ? P99.base64(bytes) : null;
  } catch {
    return null;
  }
}

async function inject(tabId, func, args = []) {
  const target = { tabId, frameIds: [0] };
  await chrome.scripting.executeScript({ target, files: ["lib.js", "page.js"] });
  const [res] = await chrome.scripting.executeScript({ target, func, args });
  return res && res.result;
}

const busy = new Set(); // one request per tab at a time

// force: undefined, "signup" (field menu: generate) or "save" (save typed login).
async function startFill(tab, entryId, force) {
  const site = tab && P99.siteFromUrl(tab.url);
  if (!site || busy.has(tab.id)) return;
  busy.add(tab.id);
  try {
    let probe = { mode: "login", username: null };
    try { probe = (await inject(tab.id, f => __p99.probe(f), [force || null])) || probe; } catch { /* no access: still ask */ }
    const reqId = crypto.randomUUID();
    const reply = await request(P99.fillRequest(reqId, probe.mode, site, probe.username, await favicon(tab.url), entryId, probe.password));
    probe.password = null;
    if (!P99.acceptFill(reply, reqId, site.host)) {
      if (reply && reply.type === "error") console.warn("99passwords:", reply.code);
      return;
    }
    // The tab may have navigated while the panel was open.
    const now = await chrome.tabs.get(tab.id);
    const still = P99.siteFromUrl(now.url);
    if (still && still.origin === site.origin) {
      await inject(tab.id, (c, o) => __p99.fill(c, o),
        [{ username: reply.username || null, password: reply.password || null, totp: reply.totp || null,
          identity: reply.identity || null, signup: probe.mode === "signup" }, site.origin]);
    }
    reply.password = reply.totp = reply.username = reply.identity = null; // drop our references
  } finally {
    busy.delete(tab.id);
    checkTab(tab.id, true); // a signup may have just saved a login
  }
}

// Toolbar dot: red when the unlocked vault has a login for the tab's site.
const DEFAULT_ICON = { 16: "icons/16.png", 32: "icons/32.png" };
let dotIcon = null;

async function makeDotIcon() {
  const out = {};
  for (const size of [16, 32]) {
    const img = await createImageBitmap(await (await fetch(chrome.runtime.getURL(DEFAULT_ICON[size]))).blob());
    const c = new OffscreenCanvas(size, size);
    const g = c.getContext("2d");
    g.drawImage(img, 0, 0, size, size);
    const r = size * 0.19;
    g.beginPath();
    g.arc(size - r - size * 0.02, r + size * 0.02, r, 0, 2 * Math.PI);
    g.fillStyle = "#e5262b";
    g.fill();
    g.lineWidth = size / 16;
    g.strokeStyle = "#fff";
    g.stroke();
    out[size] = g.getImageData(0, 0, size, size);
  }
  return out;
}

const matchCache = new Map(); // host -> { at, result }

async function hasMatch(host, fresh) {
  const hit = matchCache.get(host);
  if (!fresh && hit && Date.now() - hit.at < 5000) return hit.result;
  const reqId = crypto.randomUUID();
  const result = P99.acceptHasMatch(await request(P99.hasMatchRequest(reqId, host), MATCH_TIMEOUT_MS), reqId);
  matchCache.set(host, { at: Date.now(), result });
  return result;
}

async function setDot(tabId, on) {
  try {
    if (on) {
      dotIcon = dotIcon || await makeDotIcon();
      await chrome.action.setIcon({ tabId, imageData: dotIcon });
    } else {
      await chrome.action.setIcon({ tabId, path: DEFAULT_ICON });
    }
  } catch { /* tab closed */ }
}

async function checkTab(tabId, fresh = false) {
  let tab;
  try { tab = await chrome.tabs.get(tabId); } catch { return { match: false, locked: false }; }
  const site = P99.siteFromUrl(tab.url);
  if (!site) { setDot(tabId, false); return { match: false, locked: false }; }
  const r = await hasMatch(site.host, fresh);
  // Only paint if the tab is still on that site.
  const now = await chrome.tabs.get(tabId).catch(() => null);
  const still = now && P99.siteFromUrl(now.url);
  if (still && still.host === site.host) setDot(tabId, r.match);
  return r;
}

chrome.tabs.onActivated.addListener(({ tabId }) => { checkTab(tabId); });
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.url) setDot(tabId, false);
  if (info.status === "complete" && tab.active) checkTab(tabId);
});
// Coming back to Chrome (e.g. after unlocking in the menu bar): look again.
chrome.windows.onFocusChanged.addListener(async winId => {
  if (winId === chrome.windows.WINDOW_ID_NONE) return;
  const [tab] = await chrome.tabs.query({ active: true, windowId: winId });
  if (tab) checkTab(tab.id, true);
});

chrome.action.onClicked.addListener(tab => { startFill(tab); });
chrome.commands.onCommand.addListener((cmd, tab) => { if (cmd === "fill") startFill(tab); });
// From content.js in the top frame: the host always comes from sender.tab.url.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !sender.tab || sender.frameId !== 0 || !msg) return;
  if (msg.type === "p99_fill") {
    startFill(sender.tab, P99.isEntryId(msg.entry_id) ? msg.entry_id : undefined,
      ["signup", "save"].includes(msg.mode) ? msg.mode : undefined);
  }
  if (msg.type === "p99_has_match") {
    checkTab(sender.tab.id).then(r => sendResponse({ match: r.match, locked: r.locked, logins: r.logins || [] }));
    return true;
  }
});
