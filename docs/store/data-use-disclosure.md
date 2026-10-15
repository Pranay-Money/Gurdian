# Guardian Extension - Data Use Disclosure

**This document discloses actual data practices matching the implemented code.**

---

## Data Collection Summary

| Data Type | Collected? | Sent to Server? | Stored Locally? | User Control |
|-----------|------------|-----------------|-----------------|--------------|
| Browsing history | ❌ No | ❌ No | ❌ No | N/A |
| Page content | ❌ No* | ❌ No* | ❌ No | N/A |
| Keystrokes/forms | ❌ No | ❌ No | ❌ No | N/A |
| Passwords | ❌ No | ❌ No | ❌ No | N/A |
| Cookies/storage | ❌ No | ❌ No | ❌ No | N/A |
| PII (name, email, etc.) | ❌ No | ❌ No | ❌ No | N/A |
| Full URLs analyzed | ✅ Yes** | ✅ Yes** | ✅ Yes (hashed) | Privacy mode, wipe |
| Message text analyzed | ✅ Yes*** | ✅ Yes*** | ❌ No | Explicit action only |
| Device token | ✅ Yes | ✅ Yes | ✅ Yes | Auto-rotated, wipe |
| User settings | ✅ Yes | ❌ No | ✅ Yes | Options page |
| Analysis results | ✅ Yes | ✅ Yes | ✅ Yes (cached) | Retention setting |
| Feedback reports | ✅ Yes | ✅ Yes | ❌ No | Explicit submit |

\* **Exception**: Webmail message text ONLY when user explicitly right-clicks → "Analyze selected text"
\** In Standard mode: origin+path (tokens stripped). In Strict mode: domain only.
\** Only when user explicitly triggers analysis via context menu.

---

## Detailed Data Flows

### 1. Navigation Interception (Background)
```
User clicks link → webNavigation.onBeforeNavigate fires
    ↓
Extract URL hostname only
    ↓
Check local blocklist cache (chrome.storage.local)
    ↓
If not in cache & high risk → Query API /v1/analyze with URL
    ↓
API returns risk level → Update blocklist cache + show warning if needed
```
**Data sent**: URL hostname + device token
**Data stored**: Blocklist entry (domain hash, reason, expiry)

### 2. Context Menu Text Analysis (User-Initiated)
```
User selects text → Right-click → "Analyze with Guardian"
    ↓
Popup opens with selected text pre-filled (editable)
    ↓
User clicks "Analyze" → POST /v1/analyze {channel, sender, text, urls[]}
    ↓
API returns: score, level, signals[], urls[]
    ↓
Results displayed in popup
```
**Data sent**: Channel, sender, text (up to 50KB), extracted URLs, device token
**Data stored**: Case in local history (IndexedDB), server retains per retention policy

### 3. Opt-In Link Scanning (Content Script)
```
User enables "Scan links in Gmail" in Options
    ↓
chrome.permissions.request({origins: ["*://mail.google.com/*"]})
    ↓
Content script injected on Gmail
    ↓
Collects: <a href> elements in viewport (href, visibleText, context)
    ↓
Filters: javascript:, mailto:, tel:, #, same-origin
    ↓
Checks local bloom filter + analysis cache
    ↓
Unknown domains → Batched (max 20) → Background → API /v1/analyze
    ↓
Results → Badge rendering (Shadow DOM) on each link
```
**Data sent**: Batch of domains (max 20) + device token
**Data stored**: Domain analysis cache (sessionStorage, 1hr TTL)

### 4. Blocklist Synchronization
```
Alarm fires every 5 minutes (chrome.alarms)
    ↓
Background fetches GET /v1/blocklist/delta?since=lastSync
    ↓
Response: additions[], removals[], version, timestamp
    ↓
Update declarativeNetRequest rules (block at network layer)
    ↓
Update chrome.storage.local blocklist cache
```
**Data sent**: `since` timestamp + device token (for auth)
**Data stored**: Blocklist entries (domain_hash, reason, expires_at)

### 5. Device Registration & Token Rotation
```
First install → POST /v1/devices → Returns device_token
    ↓
Token stored in chrome.storage.local
    ↓
Every request: X-Device-Token header
    ↓
Server rotates token monthly → Returns new token in X-Device-Token-New
    ↓
Extension updates stored token (old valid 5 min grace)
```
**Data sent**: None on registration; token on subsequent requests
**Data stored**: Device token (chrome.storage.local)

---

## Server-Side Data Handling (Backend)

### What the API Stores Per Analysis (`cases` table)
```sql
- id (UUID)
- device_id (FK, anonymous)
- channel (email/sms/social/url)
- sender (if provided)
- text (nullable, only if store_raw_text=true)
- text_hash (SHA-256, always stored)
- score (0-100)
- level (Low/Medium/High/Critical)
- action (allow/warn/block)
- model_version
- latency_ms
- signals[] (JSONB: key, category, label, points, reason, evidence[])
- urls[] (JSONB: url, host, registrable_domain, tld, https, subdomains, age_days, redirects[])
- created_at, updated_at
```

### Retention & Deletion
- **Default retention**: 30 days (`RETENTION_DAYS=30`)
- **Max retention**: 365 days
- **Daily cron**: Deletes cases older than retention + cascades to signals, urls, url_intel, feedback
- **Device wipe**: `DELETE /v1/devices/me` → Hard deletes device + all related data
- **Opt-in text storage**: `store_raw_text` device setting (default: false)
  - When false: Only `text_hash` stored, `text` = NULL
  - When true: Full text stored for debugging/ML

### Threat Intelligence Caching (`url_intel` table)
- **Malicious**: 30 days
- **Suspicious**: 6 hours
- **Clean**: 1 hour
- **Unknown/Error**: 5 minutes
- **Cached results**: Returned with `cached: true`, `note: "intel_unavailable"` on error

---

## Code References

| Feature | Extension Code | API Code |
|---------|---------------|----------|
| Navigation interception | `src/background/index.ts` | `src/main.py` `/v1/analyze` |
| Context menu analysis | `src/analyze-popup/index.tsx` | `src/services/analyzer.py` |
| Link scanning (content) | `src/content/link-analyzer.ts` | `src/intel/manager.py` |
| Badge rendering | `src/content/badge-renderer.ts` | N/A |
| Warning dialog | `src/content/warning-dialog.ts` | N/A |
| Blocklist sync | `src/background/index.ts` (alarm) | `src/jobs/blocklist.py` |
| Device registration | `src/background/index.ts` | `src/main.py` `/v1/devices` |
| Token rotation | `src/background/index.ts` | `src/auth/tokens.py` |
| Privacy wipe | `src/options/components/PrivacySettings.tsx` | `src/services/privacy.py` |
| Local history | `src/shared/history.ts` (IndexedDB) | N/A |

---

## Verification Checklist

- [ ] No `chrome.storage.sync` used (only local + session)
- [ ] No `chrome.history` API used
- [ ] No `chrome.cookies` API used
- [ ] No `chrome.webRequest` blocking listeners (uses declarativeNetRequest)
- [ ] No `innerHTML` with untrusted data (uses textContent, createElement)
- [ ] No inline scripts in extension (CSP compliant)
- [ ] No eval/Function constructor
- [ ] All API calls use HTTPS in production
- [ ] Device token is JWT (HS256), not a secret
- [ ] No API keys in extension bundle
- [ ] Source maps excluded from production build
- [ ] Manifest version matches package.json version
- [ ] Host permissions point to production API URL
- [ ] Privacy policy matches this disclosure
- [ ] PERMISSIONS.md matches manifest.json

---

## Contact

For questions about this disclosure: privacy@guardian.example
Source of truth: https://github.com/guardian/guardian/blob/main/docs/store/data-use-disclosure.md