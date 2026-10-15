# Guardian Extension Permissions Documentation

## Manifest V3 Permissions

### Required Permissions

| Permission | Purpose |
|------------|---------|
| `storage` | Store user settings, device token, blocklist cache, and local history in `chrome.storage.local` and `chrome.storage.session` |
| `webNavigation` | Listen to navigation events (`onBeforeNavigate`, `onCommitted`) to intercept and analyze URLs before page load |
| `declarativeNetRequest` | Create dynamic redirect rules for known-bad domains (pre-load blocking via `blocked.html`) |
| `alarms` | Schedule periodic blocklist synchronization (every 5 minutes) |
| `tabs` | Update tab URLs (redirect to warning page), create new tabs, query active tab |
| `notifications` | (Optional) Show desktop notifications for blocked sites or critical alerts |
| `contextMenus` | (Optional) Add "Analyze with Guardian" context menu for links |

### Host Permissions (Required)

| Host | Purpose |
|------|---------|
| `http://localhost:8000/*` | Local development API endpoint |
| `https://*.guardian.api/*` | Production API endpoint (wildcard for subdomains) |

### Optional Host Permissions

| Host | Purpose |
|------|---------|
| `*://mail.google.com/*` | Analyze Gmail messages for phishing (content script injection) |
| `*://outlook.live.com/*` | Analyze Outlook messages |
| `*://*.office.com/*` | Analyze Office 365 webmail |
| `*://*.office365.com/*` | Analyze Office 365 webmail |
| `*://mail.yahoo.com/*` | Analyze Yahoo Mail messages |
| `*://*.proton.me/*` | Analyze Proton Mail messages |
| `*://*.protonmail.com/*` | Analyze Proton Mail messages |

**Note:** Optional host permissions are requested at runtime when the user visits a supported webmail site. The user must explicitly grant access.

## Permission Rationale

### No `<all_urls>` Content Script

Unlike many security extensions, Guardian **does not** use `<all_urls>` in `content_scripts.matches`. Instead:

1. **Background service worker** handles navigation interception via `webNavigation` API
2. **Declarative Net Request** rules block known-bad domains at network level (no content script needed)
3. **Content script** only injects on-demand for inline badges (Medium risk) or webmail analysis
4. **Content script matches** are limited to `http://*/*` and `https://*/*` with exclusions for extension stores

This approach:
- Reduces permission footprint
- Improves performance (no content script on every page)
- Complies with Chrome Web Store "minimum permissions" policy
- Avoids triggering "This extension can read all your data" warnings

### Why `webNavigation` over `webRequest`?

- `webNavigation.onBeforeNavigate` fires before any network request for main-frame navigations
- Works with declarativeNetRequest (which cannot be observed by `webRequest` in MV3)
- Lower overhead than `webRequest` blocking listeners
- Allows synchronous decision-making before commit

### Why `declarativeNetRequest`?

- True pre-load blocking: malicious domains are blocked at network layer
- No race conditions between analysis and page load
- Rules persist across browser restarts
- Up to 30,000 dynamic rules supported (sufficient for blocklist)

### Optional `notifications` Permission

Used only for:
- Critical threat alerts (optional, user-configurable)
- Blocklist sync status updates

If not granted, the extension works fully without notifications.

### Optional `contextMenus` Permission

Adds "Analyze link with Guardian" to right-click menu on links.
If not granted, context menu item simply doesn't appear.

## Data Access

### What Guardian Reads

| Data | Source | Retention |
|------|--------|-----------|
| Current tab URL (on navigation) | `webNavigation` API | In-memory only during analysis |
| URL hostname (for blocklist check) | `webNavigation` API | In-memory only |
| User settings | `chrome.storage.local` | Until user clears |
| Device token | `chrome.storage.local` | 1 year (rotated monthly) |
| Blocklist cache | `chrome.storage.local` | Until next sync (5 min) |
| Analysis cache | `chrome.storage.session` | Session only |
| Local history | IndexedDB | 30 days (configurable) |

### What Guardian Sends to API

| Data | When | Privacy Setting |
|------|------|-----------------|
| Full URL | Analysis request | Standard: origin+path; Strict: domain only |
| Page text (webmail) | User triggers analysis | Only with explicit user action |
| Sender (webmail) | User triggers analysis | Only with explicit user action |
| Device token | Every request | Required for auth |
| Telemetry (optional) | After analysis | Only if `sendTelemetry: true` |

### What Guardian NEVER Collects

- Page content (except webmail with user action)
- Keystrokes, form data, passwords
- Browsing history (only local IndexedDB history)
- Personally identifiable information
- Cookies, localStorage, sessionStorage

## Privacy Modes

### Standard Mode (Default)
- Sends: `origin + path` (e.g., `https://example.com/login?ref=email`)
- Strips: query parameters that look like tokens/session IDs
- Hashes: full URL in local history (SHA-256)

### Strict Mode (Optional)
- Sends: `domain only` (e.g., `example.com`)
- No path, query, or fragment sent to API
- Less accurate analysis (no path-based signals)
- Maximum privacy

## Data Retention

| Data Type | Default Retention | Configurable |
|-----------|-------------------|--------------|
| Local history (IndexedDB) | 30 days | Yes (1-365 days) |
| Analysis cache (session storage) | Browser session | No |
| Blocklist cache (local storage) | Until next sync | No |
| Device token | 1 year | Auto-rotated |
| Settings | Permanent | User-controlled |

## Third-Party Services

### API Communication
- All API calls use HTTPS in production
- Device token is a signed JWT (HS256), not a secret
- No API keys stored in extension
- Requests include only `X-Device-Token` header

### No Third-Party Trackers
- No Google Analytics
- No Sentry, Mixpanel, Amplitude
- No crash reporting services
- All logging is local (console only)

## Chrome Web Store Compliance

| Policy | Compliance |
|--------|------------|
| Minimum permissions | ✅ Only required permissions declared |
| No `<all_urls>` content script | ✅ Uses `webNavigation` + DNR |
| Single purpose | ✅ Phishing/malware protection |
| User data transparency | ✅ This document + privacy policy |
| Remote code | ❌ None (CSP enforced) |
| Obfuscated code | ❌ None (source maps included) |

## Permission Changes

If additional permissions are needed in future versions:
1. Add to `optional_permissions` or `optional_host_permissions`
2. Request at runtime with `chrome.permissions.request()`
3. Explain rationale in changelog
4. Update this document

## Testing Permissions

To test with minimal permissions:
```bash
# Load unpacked extension in Chrome
# Check chrome://extensions -> Guardian -> Details -> Permissions
# Verify only listed permissions appear
```

To test optional permissions:
```javascript
// In background console
await chrome.permissions.request({
  origins: ["*://mail.google.com/*"]
});
```

## Related Documents

- [Privacy Policy](PRIVACY.md)
- [Data Processing Agreement](DPA.md)
- [Security Architecture](ARCHITECTURE.md)