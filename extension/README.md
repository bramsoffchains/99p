# 99passwords Chrome extension

Vanilla JS, no dependencies, no popup. All UI is the menu bar app's panel.

- `sw.js`: service worker. Takes host and origin from `tab.url`, asks the app
  over native messaging (`app.99passwords.bridge`), fills the answer into the
  top frame if it is still on the same origin, then drops it. Also asks the app
  `has_match` for the active tab and paints a red dot on the toolbar icon when
  the unlocked vault has a login for the site.
- `lib.js`: pure helpers (URL to site, field classification, message checks).
- `page.js`: finds and fills fields.
- `content.js`: the 99passwords icon in login fields (on focus or hover) and a dropdown under the
  field: the site's saved logins by name and username (pick one with the mouse
  or arrow keys and Enter to fill it), or "Generate a strong password" on
  signup forms, or both when the page could be either. Clicking the field icon
  opens the full menu: logins, Generate, Save new login (sends what you typed
  to the app's Create Login) and Open 99passwords.
- `icons/`: the app logo (cropped from `macos/AppIcon.icns`).

Trigger: field icon, toolbar icon or Cmd+Shift+L (change it at `chrome://extensions/shortcuts`).

Load it unpacked from this folder at `chrome://extensions` (it asks for access
to all sites, for the field icon and the toolbar dot). The `key` in
`manifest.json` pins the extension id to `bjppeeoihhidakjbpmbpmhcddcebiieg`
wherever the folder lives (it is the e2e test key in `e2e/test-key.txt`; the
extension is never packed with a private key). The app allows that id and writes the native host manifest for
it at launch.

Tests: `node --test extension/test/*.test.js`. End-to-end in Chromium, with the
real bridge and a fake app: `cargo build -p ykvault-bridge && node extension/e2e/run.js`.
