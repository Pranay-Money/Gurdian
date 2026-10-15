# Guardian Browser Extension Specification

## Overview
A privacy-focused browser extension for real-time phishing, scam, and malicious URL detection with inline link analysis, context menu text analysis, and unspoofable warning UI.

---

## 1. Context Menu: "Analyze Selected Text with Guardian"

### User Flow
1. User selects text on any page
2. Right-clicks → "Analyze selected text with Guardian"
3. Popup opens with selected text pre-filled (editable)
4. User clicks "Analyze" to send to backend
5. Results display: score, level, signals with evidence, extracted URLs

### Technical Requirements
- **Manifest V3**: `contextMenus` permission
- **Popup**: Separate HTML/React entry point (`analyze-popup.html`)
- **Communication**: Message passing to background for API call
- **Security**: Never auto-send; explicit user action required
- **Text limit**: 50KB max (matching API limit)

### UI Components
- Header: Guardian logo + "Analyze Text"
- Textarea: Pre-filled with selection, editable, character counter
- Analyze button: Primary action
- Results section (hidden until response):
  - Risk badge: Score + Level (Low/Medium/High/Critical)
  - Signals list: Category, label, points, reason, evidence
  - Extracted URLs: Each with host, risk indicators
  - Action buttons: Report, Feedback, Close

---

## 2. Content Script: Opt-In Link Scanning

### Supported Sites (Configurable)
| Site | Host Patterns | Notes |
|------|--------------|-------|
| Gmail | `*://mail.google.com/*` | |
| Outlook Web | `*://outlook.live.com/*`, `*://*.office.com/*`, `*://*.office365.com/*` | |
| WhatsApp Web | `*://web.whatsapp.com/*` | |
| Telegram Web | `*://web.telegram.org/*`, `*://*.web.telegram.org/*` | |
| LinkedIn | `*://*.linkedin.com/*` | DMs only |
| X (Twitter) | `*://*.x.com/*`, `*://twitter.com/*` | DMs only |
| Instagram | `*://*.instagram.com/*` | DMs only |

### Permission Model
- **Default**: No host permissions granted
- **Opt-in**: User enables "Scan links in webmail/messaging" in options
- **On enable**: Request `optional_host_permissions` for selected sites
- **On disable**: Revoke host permissions (optional, or just stop injecting)
- **Granular**: Per-site toggles in options

### Link Collection
- **Scope**: All `<a href>` elements in viewport + dynamically added
- **Data collected per link**:
  - `href` (absolute URL)
  - `visibleText` (textContent, trimmed, max 200 chars)
  - `element` (WeakRef for decoration)
  - `context` (ancestor class names for DM detection)
- **Excluded**: `javascript:`, `mailto:`, `tel:`, `#` anchors, same-origin nav
- **Message bodies**: NEVER collected unless user clicks "Analyze this message" (future)

### Display-Text Mismatch Signal
- **Check**: Does visible text look like a domain/URL but point elsewhere?
- **Heuristics**:
  - Visible text matches domain regex but `href` host ≠ visible domain
  - Visible text contains brand keyword but `href` host doesn't match brand
  - Visible text is "Click here" / "Link" / generic but `href` is suspicious
- **Signal**: `display_text_mismatch` (category: `behavioral`, points: 25-40)

### Batch Domain Analysis
- **Unknown domains**: Not in local bloom filter, not recently cached
- **Batch size**: Max 20 domains per request
- **Cache**: LRU in background (max 500 entries, TTL 1 hour)
- **Throttling**: Min 500ms between batches
- **Response**: Per-domain risk level + signals

### Link Decoration (Badges)
- **Position**: After link text, inline-block, small (12x12px)
- **Colors**:
  - Medium: Amber `#f59e0b` (●)
  - High: Red `#ef4444` (●)
  - Critical: Red `#dc2626` with pulse (●)
- **Tooltip**: Hover shows level + top signal
- **Accessibility**: `aria-label`, keyboard focusable
- **Shadow DOM**: Badge rendered in closed shadow root on link element

### Click Interception (High/Critical Only)
- **Trigger**: User clicks link with High/Critical badge
- **Action**: Prevent default, show inline warning dialog
- **Dialog**: Shadow DOM (closed), unspoofable
- **Content**:
  - Warning icon + "Guardian Security Warning"
  - "This link was flagged as [High/Critical] risk"
  - Top 2 signals with evidence
  - Buttons: "Go Back" (default), "Continue Anyway"
- **isTrusted check**: Only intercept trusted (user) clicks
- **No re-intercept**: If user clicks "Continue Anyway", allow navigation

### MutationObserver with Throttling
- **Observe**: `subtree: true, childList: true` on `document.body`
- **Filter**: Only process added nodes containing `<a href>`
- **Throttle**: 100ms debounce, batch DOM changes
- **Zero impact**: If no links on page, observer does nothing
- **Cleanup**: Disconnect on unload, reconnect on navigation (SPA)

---

## 3. Security Hardening

### No innerHTML with Page Data
- **Rule**: Never use `innerHTML`, `outerHTML`, `insertAdjacentHTML` with untrusted data
- **Alternative**: `textContent`, `createElement`, `appendChild`, `setAttribute`
- **Sanitization**: DOMPurify for any HTML from API (if ever needed)

### Unspoofable Warning UI
- **Closed Shadow Root**: `element.attachShadow({ mode: 'closed' })`
- **Style isolation**: No page CSS leakage
- **isTrusted verification**: `event.isTrusted === true` for click handling
- **Z-index**: `2147483647` (max)
- **No page event listeners**: Use capture phase if needed

### CSP Compliance
- **No inline scripts**: All JS in separate files
- **No eval/Function constructor**
- **Styles**: Injected via `CSSStyleSheet` in shadow root

---

## 4. Performance Targets

| Metric | Target |
|--------|--------|
| Main-thread time per 100 links | < 20 ms |
| Memory per link | < 500 bytes |
| MutationObserver overhead (no links) | ~0 ms |
| Batch API latency (p95) | < 500 ms |
| Badge render time | < 5 ms per badge |

### Optimization Strategies
- **WeakRef/WeakMap**: For link elements to avoid memory leaks
- **RequestIdleCallback**: For non-urgent batch processing
- **IntersectionObserver**: Only analyze visible links first
- **Debounced MutationObserver**: 100ms, max 50 nodes per batch
- **CSS containment**: `contain: layout style` on badge containers

---

## 5. Playwright Test Fixtures

### Static HTML Fixtures (`tests/fixtures/`)
```
tests/fixtures/
├── gmail-mismatch.html      # Anchor text "paypal.com" → href "evil.xyz"
├── gmail-shortener.html     # bit.ly link in email
├── gmail-typosquat.html     # "micros0ft.com" link
├── outlook-clean.html       # Legitimate links only
├── whatsapp-dm.html         # DM conversation with links
├── linkedin-dm.html         # LinkedIn messaging
├── twitter-dm.html          # X DM with links
└── generic-page.html        # Non-opt-in site (should do nothing)
```

### Test Scenarios
1. **Badge rendering**: Medium/High/Critical badges appear correctly
2. **Click interception**: High/Critical links show warning dialog
3. **isTrusted check**: Programmatic clicks don't trigger warning
4. **Shadow DOM isolation**: Page CSS doesn't affect warning dialog
5. **Performance**: 100 links processed in < 20ms main thread
6. **Opt-in behavior**: No content script injection on disabled sites
7. **Mismatch signal**: Display-text mismatch detected and flagged
8. **Batch caching**: Repeated domains not re-requested

---

## 6. File Structure (New/Additions)

```
extension/
├── src/
│   ├── analyze-popup/
│   │   ├── index.tsx
│   │   ├── index.html
│   │   └── styles.css
│   ├── content/
│   │   ├── index.ts                 # Entry point
│   │   ├── link-analyzer.ts         # Core link analysis logic
│   │   ├── badge-renderer.ts        # Badge rendering (Shadow DOM)
│   │   ├── warning-dialog.ts        # Click warning dialog (Shadow DOM)
│   │   ├── mutation-observer.ts     # Throttled observer
│   │   ├── site-detector.ts         # Site-specific logic
│   │   ├── sanitize.ts              # Sanitization utilities
│   │   └── types.ts                 # Content script types
│   ├── background/
│   │   ├── index.ts                 # Existing + new handlers
│   │   ├── domain-cache.ts          # Domain analysis cache
│   │   ├── batch-analyzer.ts        # Batch domain analysis
│   │   └── context-menu.ts          # Context menu handler
│   ├── options/
│   │   ├── index.tsx                # Extended with opt-in toggles
│   │   └── components/
│   │       ├── SiteToggle.tsx       # Per-site enable toggle
│   │       └── PermissionsManager.tsx
│   └── shared/
│       ├── heuristics.ts            # Extended with mismatch signal
│       └── types.ts                 # Extended types
├── tests/
│   ├── fixtures/                    # Static HTML fixtures
│   ├── e2e/
│   │   ├── content-script.spec.ts   # Content script tests
│   │   ├── context-menu.spec.ts     # Context menu tests
│   │   └── performance.spec.ts      # Performance benchmarks
│   └── playwright.config.ts
├── vite.config.ts                   # Updated with new entry points
└── public/manifest.json             # Updated permissions
```

---

## 7. Manifest V3 Updates

### Permissions
```json
{
  "permissions": [
    "storage",
    "webNavigation",
    "declarativeNetRequest",
    "alarms",
    "tabs",
    "notifications",
    "contextMenus",
    "scripting"
  ],
  "optional_host_permissions": [
    "*://mail.google.com/*",
    "*://outlook.live.com/*",
    "*://*.office.com/*",
    "*://*.office365.com/*",
    "*://web.whatsapp.com/*",
    "*://web.telegram.org/*",
    "*://*.web.telegram.org/*",
    "*://*.linkedin.com/*",
    "*://*.x.com/*",
    "*://twitter.com/*",
    "*://*.instagram.com/*"
  ],
  "host_permissions": [
    "http://localhost:8000/*",
    "https://api.guardian.example/*"
  ]
}
```

### Content Scripts (Dynamic Registration)
- **Default**: No content scripts in manifest
- **Runtime**: `chrome.scripting.registerContentScripts()` when user enables opt-in
- **Matches**: Only for enabled sites
- **Run at**: `document_idle` (after DOM ready)

### Web Accessible Resources
- Warning dialog styles (if any external)
- Badge assets (inline SVG preferred)

---

## 8. Implementation Priority

1. **Context Menu + Analyze Popup** - Core user-facing feature
2. **Content Script Infrastructure** - Site detection, permission management
3. **Link Analyzer + Badge Renderer** - Core detection + UI
4. **Warning Dialog (Shadow DOM)** - Security-critical
5. **Batch Analyzer + Cache** - Background service
6. **Options UI Updates** - Per-site toggles
7. **MutationObserver + Throttling** - Performance
8. **Playwright Tests** - Acceptance verification
9. **Performance Optimization** - Meet <20ms target

---

## 9. API Integration Points

### Background → API
- `POST /v1/analyze` - Batch domain analysis (max 20)
- `POST /v1/analyze` - Text analysis (context menu)

### Content Script → Background
- `ANALYZE_DOMAINS` - Batch unknown domains
- `GET_BADGE_DATA` - Get cached analysis for link
- `SHOW_WARNING` - Notify background of click interception

### Background → Content Script
- `UPDATE_BADGE` - Update badge on specific link
- `REMOVE_BADGE` - Clean up on navigation

---

## 10. Configuration (Extension Settings)

```typescript
interface ExtendedDeviceSettings extends DeviceSettings {
  // Opt-in link scanning
  linkScanningEnabled: boolean;
  enabledSites: Record<string, boolean>;  // e.g., { gmail: true, outlook: false }
  
  // UI preferences
  badgeStyle: 'minimal' | 'detailed';
  warningDialogEnabled: boolean;
  
  // Performance
  maxLinksPerPage: number;        // Default: 200
  batchSize: number;              // Default: 20
  observerThrottleMs: number;     // Default: 100
}
```

---

## 11. Acceptance Criteria Checklist

- [ ] Context menu appears on text selection
- [ ] Analyze popup opens with selected text
- [ ] Explicit "Analyze" button sends to API
- [ ] Results show score, level, signals, evidence, URLs
- [ ] Opt-in toggles in options for each supported site
- [ ] Host permissions requested on enable
- [ ] Links collected: href + visible text only
- [ ] Display-text mismatch signal works
- [ ] Unknown domains batched (max 20) to background
- [ ] Domain cache works (TTL, LRU)
- [ ] Badges render: Medium=amber, High/Critical=red
- [ ] Badges in closed Shadow DOM
- [ ] Click interception on High/Critical links
- [ ] Warning dialog in closed Shadow DOM
- [ ] isTrusted check on clicks
- [ ] "Continue Anyway" allows navigation
- [ ] MutationObserver throttled (100ms)
- [ ] Zero overhead on pages with no links
- [ ] No innerHTML with page data
- [ ] All user-facing strings sanitized
- [ ] Playwright tests pass on all fixtures
- [ ] Performance: <20ms per 100 links
- [ ] Extension inert on non-opt-in sites