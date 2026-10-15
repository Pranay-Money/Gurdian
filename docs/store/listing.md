# Guardian - Chrome Web Store Listing

## Short Description (132 chars max)
Real-time phishing, scam & malicious URL detection with privacy-first inline warnings.

## Detailed Description

**Guardian** protects you from phishing, scams, and malicious links across email, messaging, and the web — all while respecting your privacy.

### 🔍 Smart Detection
- **Multi-engine analysis**: Combines ML scoring, threat intelligence (Google Safe Browsing, VirusTotal), and heuristic signals
- **Real-time URL analysis**: Checks links before you click — no browsing history sent to servers
- **Text analysis**: Right-click any selected text to analyze for scams, impersonation, urgency tactics
- **Display-text mismatch detection**: Catches links where the visible text says "paypal.com" but the URL points elsewhere

### 🛡️ Unspoofable Warnings
- **Closed Shadow DOM warnings**: Cannot be hidden or spoofed by malicious pages
- **Click interception**: High/Critical risk links show a warning dialog before navigation
- **Inline badges**: Medium-risk links get subtle amber/red indicators
- **isTrusted verification**: Only blocks real user clicks, not programmatic navigation

### 🔒 Privacy by Design
- **No browsing history collected**: Only analyzes URLs you explicitly check or that trigger warnings
- **Anonymous device tokens**: No accounts, no PII, tokens rotate automatically
- **Two privacy modes**:
  - Standard: Sends origin + path (strips tokens/session IDs)
  - Strict: Sends domain only — maximum privacy
- **Local-only storage**: History, cache, and settings stay in your browser
- **Configurable retention**: Auto-delete local data after 1-365 days

### 🌐 Supported Sites (Opt-in)
Enable inline link scanning for:
- Gmail, Outlook, Office 365
- WhatsApp Web, Telegram Web
- LinkedIn, X (Twitter), Instagram
- Only activates after you grant permission per site

### ⚡ Performance
- <20ms main-thread time per 100 links
- Smart caching: domains cached for 1 hour
- Batch API requests (max 20 domains)
- Zero overhead on non-opt-in pages

### 📊 Transparency
- **Open source**: Full source code available
- **Explainable results**: Every risk factor shown with evidence
- **Feedback loop**: Report false positives/negatives to improve detection
- **No third-party trackers**: No analytics, no crash reporters

---

## Single-Purpose Description (for Chrome Web Store)
Guardian is a single-purpose security extension focused exclusively on phishing, scam, and malicious URL detection. It analyzes URLs and message text in real-time to protect users from online threats, displaying unspoofable warnings before dangerous interactions. All features serve this core security purpose.

---

## Keywords (for store SEO)
phishing protection, scam detection, malicious URL blocker, security extension, privacy-first, anti-phishing, link scanner, threat intelligence

---

## Category
Productivity / Security

---

## Screenshots Needed
1. **Popup Dashboard** - Main extension popup showing protection status, recent analyses, quick actions
2. **Analyze Text Popup** - Context menu flow: selected text → right-click → analyze → results with signals
3. **Inline Badges** - Gmail/Outlook message with amber/red badges on suspicious links
4. **Warning Dialog** - High-risk click interception with unspoofable shadow DOM dialog
5. **Options Page** - Privacy settings, site toggles, retention configuration
6. **History Dashboard** - Searchable case history with filters, export options

---

## Promotional Images (Optional)
- **Small tile (440x280)**: Guardian logo + "Real-time phishing protection"
- **Large tile (920x680)**: Dashboard screenshot with tagline
- **Marquee (1400x560)**: Hero image showing warning dialog + badges in action