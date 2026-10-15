# Guardian Extension Privacy Policy

**Last Updated:** October 2026
**Version:** 1.0
**Contact:** privacy@guardian.example

---

## Overview

Guardian ("we", "us", "our") is a browser extension that helps protect you from phishing, scams, and malicious URLs. This Privacy Policy explains what data we collect, how we use it, and your rights.

**Key principle: We collect the minimum data necessary to provide protection. No accounts, no tracking, no third-party analytics.**

---

## Data We Collect

### 1. Data Sent to Our API (Only When You Use Features)

| Data | When Collected | Purpose | Retention |
|------|----------------|---------|-----------|
| **Full URL** (or domain only in Strict mode) | When you click "Analyze" or a link triggers a warning | Check against threat intelligence, ML scoring | 30 days on server (configurable) |
| **Message text & sender** | Only when you explicitly use "Analyze selected text" context menu | Linguistic scam detection (urgency, impersonation, sensitive requests) | 30 days on server (configurable) |
| **Device token** | Every API request | Anonymous authentication, rate limiting | 1 year (rotated monthly) |
| **URL metadata** (host, domain, path, redirects) | During URL analysis | Domain age, reputation, TLS certificate checks | 30 days on server |

**We NEVER send:**
- Page content (except webmail text you explicitly analyze)
- Keystrokes, form data, passwords
- Browsing history
- Cookies, localStorage, sessionStorage
- Personally identifiable information

### 2. Data Stored Locally in Your Browser

| Data | Storage | Retention | Purpose |
|------|---------|-----------|---------|
| **Device token** | `chrome.storage.local` | 1 year (auto-rotated) | Anonymous API authentication |
| **User settings** | `chrome.storage.local` | Until you clear | Privacy mode, site toggles, UI preferences |
| **Blocklist cache** | `chrome.storage.local` | Until next sync (5 min) | Offline malicious domain blocking |
| **Analysis cache** | `chrome.storage.session` | Browser session | Avoid re-analyzing same domains |
| **Local history** | IndexedDB | 30 days (configurable 1-365 days) | Your searchable analysis history |
| **Webmail permission grants** | `chrome.storage.local` | Until revoked | Remember which sites you enabled |

---

## Privacy Modes

### Standard Mode (Default)
- **Sends**: Origin + path (e.g., `https://example.com/login?ref=email`)
- **Strips**: Query parameters that look like tokens/session IDs (regex patterns for `token`, `session`, `auth`, `key`, `secret`, `password`, `code`, `csrf`, `xsrf`)
- **Local history**: Stores SHA-256 hash of full URL

### Strict Mode (Optional)
- **Sends**: Domain only (e.g., `example.com`)
- **No path, query, or fragment** sent to API
- **Trade-off**: Less accurate analysis (no path-based signals)
- **Maximum privacy**: Minimal data leaves your browser

---

## How We Use Your Data

1. **Threat Detection**: Analyze URLs and text for phishing, scams, malware
2. **Rate Limiting**: Prevent abuse via anonymous device tokens
3. **Blocklist Sync**: Download malicious domain lists for offline protection
4. **Improve Detection**: Aggregated, anonymized feedback (false positive/negative reports) helps improve models

**We do NOT:**
- Sell or share your data with third parties
- Use data for advertising or marketing
- Track you across websites
- Build user profiles

---

## Third-Party Services

### Threat Intelligence APIs (Optional, Degrade Gracefully)
When enabled via server configuration, the backend may query:
- **Google Safe Browsing** — URL reputation
- **VirusTotal** — URL/domain/file reputation
- **OpenPhish** — Phishing feed
- **PhishTank** — Community-verified phishing
- **RDAP/DNS/TLS** — Domain registration, DNS records, certificates

**No API keys are stored in the extension.** All keys reside on the backend server only.

### No Third-Party Trackers
- ❌ No Google Analytics
- ❌ No Sentry, Mixpanel, Amplitude
- ❌ No crash reporting services
- ❌ No advertising networks

---

## Data Retention & Deletion

### Server-Side (API)
- **Cases & analyses**: 30 days default (configurable up to 365 days)
- **Device wipe**: `DELETE /v1/devices/me` hard-deletes ALL your data
- **Automatic cleanup**: Daily cron job removes expired data

### Client-Side (Extension)
- **Local history**: 30 days default (configurable 1-365 days in Options)
- **Clear all data**: Extension "Clear Data" button in Options → Privacy
- **Uninstall**: All extension storage cleared automatically

---

## Your Rights

| Right | How to Exercise |
|-------|-----------------|
| **Access** | View local history in Options → History; request server data via `GET /v1/cases` |
| **Rectification** | Submit feedback via `POST /v1/feedback` to correct analysis |
| **Erasure** | Click "Wipe Device" in Options → Privacy (calls `DELETE /v1/devices/me`) |
| **Portability** | Export history as JSON/CSV from Options → History |
| **Restrict Processing** | Enable Strict Mode; disable link scanning per site |
| **Object** | Disable link scanning entirely in Options |

---

## Children's Privacy

Guardian is not directed at children under 13 (or 16 in EU). We do not knowingly collect data from children. If you believe a child has provided data, contact us for deletion.

---

## Security

- **HTTPS only** for all API communication
- **Signed device tokens** (HS256 JWT), not secrets
- **No API keys in extension**
- **Content Security Policy** enforced (no inline scripts, no eval)
- **Closed Shadow DOM** for warnings (cannot be spoofed)

---

## International Transfers

If you use Guardian outside the US/EU, your data may be processed on servers in the United States (Fly.io / Google Cloud). By using Guardian, you consent to this transfer.

---

## Changes to This Policy

We may update this policy. Material changes will be notified via:
- Extension update description
- In-extension notification (if enabled)
- GitHub releases page

Continued use after changes constitutes acceptance.

---

## Compliance

- **GDPR**: Lawful basis = legitimate interest (security) + consent (optional features)
- **CCPA**: No sale of personal information; right to delete via device wipe
- **Chrome Web Store**: Single-purpose, minimum permissions, transparent data practices

---

## Contact

**Data Protection Officer**: privacy@guardian.example
**GitHub Issues**: https://github.com/guardian/guardian/issues
**Source Code**: https://github.com/guardian/guardian

---

## Appendix: Permission Justifications

See [PERMISSIONS.md](../PERMISSIONS.md) for detailed rationale for each Chrome permission.

| Permission | Data Access | Required? |
|------------|-------------|-----------|
| `storage` | Settings, token, cache, history | Yes |
| `webNavigation` | Tab URL on navigation | Yes |
| `declarativeNetRequest` | Blocklist rules | Yes |
| `alarms` | Blocklist sync schedule | Yes |
| `tabs` | Redirect, create tabs | Yes |
| `notifications` | Critical alerts (optional) | Optional |
| `contextMenus` | "Analyze" menu item | Optional |
| `scripting` | Dynamic content script injection | Yes |
| `host_permissions` (API) | API communication | Yes |
| `optional_host_permissions` (sites) | Webmail content script | Opt-in only |