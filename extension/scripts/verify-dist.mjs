import fs from 'node:fs';
import path from 'node:path';

const rootDir = process.cwd();
const distDir = path.resolve(rootDir, 'dist');
const manifestPath = path.resolve(distDir, 'manifest.json');
const docsPath = path.resolve(rootDir, '../docs/PERMISSIONS.md');

const requiredPermissions = [
  'storage',
  'webNavigation',
  'declarativeNetRequest',
  'alarms',
  'tabs',
  'contextMenus',
];

const optionalHostPermissions = [
  '*://mail.google.com/*',
  '*://outlook.live.com/*',
  '*://*.office.com/*',
  '*://*.office365.com/*',
  '*://mail.yahoo.com/*',
  '*://*.proton.me/*',
  '*://*.protonmail.com/*',
];

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

function checkExists(filePath, message) {
  assert(fs.existsSync(filePath), `${message}: ${filePath}`);
}

if (!fs.existsSync(manifestPath)) {
  throw new Error(`dist/manifest.json does not exist at ${manifestPath}`);
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

for (const permission of requiredPermissions) {
  assert(Array.isArray(manifest.permissions) && manifest.permissions.includes(permission), `Required permission missing: ${permission}`);
}

assert(!manifest.optional_permissions || !manifest.optional_permissions.includes('webRequest'), 'optional_permissions must not include webRequest');
assert(!manifest.optional_permissions || !manifest.optional_permissions.includes('webRequestAuthProvider'), 'optional_permissions must not include webRequestAuthProvider');
assert(!('options_page' in manifest), 'Remove options_page; keep options_ui instead.');
assert(!manifest.web_accessible_resources.some((entry) => entry.matches.includes('<all_urls>')), 'web_accessible_resources.matches must not include <all_urls>');

const docsText = fs.readFileSync(docsPath, 'utf8');
for (const permission of requiredPermissions) {
  assert(docsText.includes(`\`${permission}\``), `docs/PERMISSIONS.md is missing permission documentation for ${permission}`);
}

for (const optionalHostPermission of optionalHostPermissions) {
  const hostPermissions = Array.isArray(manifest.optional_host_permissions) ? manifest.optional_host_permissions : [];
  assert(hostPermissions.includes(optionalHostPermission), `manifest.optional_host_permissions is missing ${optionalHostPermission}`);
  assert(docsText.includes(optionalHostPermission), `docs/PERMISSIONS.md is missing optional host permission documentation for ${optionalHostPermission}`);
}

const defaultLocale = manifest.default_locale;
if (defaultLocale) {
  const localeFile = path.resolve(distDir, '_locales', defaultLocale, 'messages.json');
  checkExists(localeFile, 'Missing locale file for default_locale');
}

const filePaths = [
  manifest.background?.service_worker,
  manifest.action?.default_popup,
  manifest.options_ui?.page,
  ...manifest.web_accessible_resources.flatMap((entry) => entry.resources || []),
  ...Object.values(manifest.icons || {}),
  ...Object.values(manifest.action?.default_icon || {}),
  manifest.declarative_net_request?.rule_resources?.[0]?.path,
].filter(Boolean);

for (const relativePath of filePaths) {
  const fullPath = path.resolve(distDir, relativePath);
  checkExists(fullPath, `Referenced dist file not found`);
}

const uiPages = [
  {
    page: manifest.action?.default_popup,
    requiredMarkup: ['id="root"'],
  },
  {
    page: manifest.options_ui?.page,
    requiredMarkup: ['id="protectionEnabled"', 'id="apiBaseUrl"', 'id="linkScanningEnabled"', 'id="sitesGrid"'],
  },
];

for (const { page, requiredMarkup } of uiPages) {
  assert(typeof page === 'string', 'Manifest is missing a popup or settings page');
  const htmlPath = path.resolve(distDir, page);
  checkExists(htmlPath, `Manifest UI page not found`);
  const html = fs.readFileSync(htmlPath, 'utf8');

  for (const markup of requiredMarkup) {
    assert(html.includes(markup), `${page} is missing required UI markup: ${markup}`);
  }

  const scriptPaths = Array.from(html.matchAll(/\bsrc=["']([^"']+\.js)["']/g), (match) => match[1]);
  assert(scriptPaths.length > 0, `${page} does not load a built JavaScript entry point`);
  for (const scriptPath of scriptPaths) {
    checkExists(path.resolve(distDir, scriptPath.replace(/^[/\\]+/, '')), `${page} references a missing script`);
  }
  assert(!html.includes('.tsx'), `${page} must not load TypeScript source directly`);
}

if (manifest.declarative_net_request?.rule_resources?.[0]?.path) {
  const rulesPath = path.resolve(distDir, manifest.declarative_net_request.rule_resources[0].path);
  const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
  assert(Array.isArray(rules), 'rules.json must contain a JSON array');
}

const sourceMaps = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath);
    } else if (entry.name.endsWith('.map')) {
      sourceMaps.push(fullPath);
    }
  }
}

walk(distDir);
if (sourceMaps.length > 0) {
  throw new Error(`Production build leaked source maps into dist: ${sourceMaps.join(', ')}`);
}

console.log('verify-dist: OK');
