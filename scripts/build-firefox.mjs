/**
 * Turns the built `dist/` into a Firefox-loadable `dist-firefox/`.
 *
 *   npm run build && node scripts/build-firefox.mjs
 *
 * The code is identical; only the manifest differs, and it differs in ways
 * Firefox refuses to overlook:
 *
 * - **the background.** Chrome wants `service_worker`, Firefox wants
 *   `scripts`. Firefox does not accept the first at all, which is why the
 *   Chrome package simply will not load there;
 * - **an extension identifier.** Firefox requires one for MV3;
 * - **`theme_icons` stays**, since it is Firefox's own mechanism and Chrome
 *   ignores it. `chrome.action.setIcon` covers Chrome instead.
 *
 * What is **not** carried across, and cannot be: `chrome.offscreen`, which
 * Firefox has no equivalent for. The consequence is stated in the README
 * rather than discovered — the clipboard wipe that survives the popup closing
 * is a Chrome-only guarantee, and on Firefox the wipe happens while the popup
 * lives and not after.
 */

import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const DIST = new URL('../dist/', import.meta.url);
const TARGET = new URL('../dist-firefox/', import.meta.url);

if (!existsSync(DIST)) {
  console.error('dist/ is missing — run `npm run build` first.');
  process.exit(1);
}

rmSync(TARGET, { recursive: true, force: true });
cpSync(DIST, TARGET, { recursive: true });

const manifest = JSON.parse(readFileSync(new URL('manifest.json', TARGET), 'utf8'));

// An event page, not a service worker. `type: module` is kept: Firefox has
// supported ES modules in MV3 backgrounds since 128, and the bundle is one.
delete manifest.background.service_worker;
manifest.background = { scripts: ['background.js'], type: 'module' };

manifest.browser_specific_settings = {
  gecko: {
    id: 'zwarden@zwarden.local',
    // 128 is where Firefox gained `world: "MAIN"` for registered content
    // scripts, without which passkeys cannot be hooked at all.
    strict_min_version: '128.0',
  },
};

// The offscreen document is Chrome's alone. Shipping the permission and the
// file to a browser that has neither would be claiming a capability.
manifest.permissions = manifest.permissions.filter((p) => p !== 'offscreen');
rmSync(new URL('offscreen.html', TARGET), { force: true });
rmSync(new URL('offscreen.js', TARGET), { force: true });

writeFileSync(
  new URL('manifest.json', TARGET),
  `${JSON.stringify(manifest, null, 2)}\n`,
  'utf8',
);

console.log('dist-firefox/ written:');
console.log('  background   :', JSON.stringify(manifest.background));
console.log('  gecko id     :', manifest.browser_specific_settings.gecko.id);
console.log('  permissions  :', manifest.permissions.join(', '));
