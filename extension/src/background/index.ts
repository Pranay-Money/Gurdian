import browser from 'webextension-polyfill';
import { DeviceSettings, AnalyzeRequest, AnalyzeResponse, Signal, BlockData, RiskLevel, ActionType, DomainAnalysis, ExtendedDeviceSettings, SupportedSite, SUPPORTED_SITES } from '@shared/types';
import { BloomFilter, loadTrancoBloomFilter } from '@shared/bloom';
import { runHeuristics, generateExplanation } from '@shared/heuristics';
import { addHistoryEntry, runRetentionCleanup } from '@shared/history';
import { parseBlocklistDelta } from '@shared/api-status';
import { ContextMenuHandler, initializeContextMenu } from './context-menu';
import { BatchAnalyzer, initializeBatchAnalyzer } from './batch-analyzer';

export const DEFAULT_SETTINGS: DeviceSettings = {
  protectionEnabled: true,
  enforcementPolicy: 'warn',
  showInlineBadges: true,
  sendTelemetry: false,
  apiBaseUrl: 'http://localhost:8000/v1',
  deviceToken: '',
  blocklistVersion: 0,
  blocklistUpdatedAt: '',
  privacyMode: 'standard',
  customAllowlist: [],
  customBlocklist: [],
};

interface CachedDecision {
  url: string;
  score: number;
  level: RiskLevel;
  action: ActionType;
  signals: Signal[];
  explanation: string;
  source: 'allowlist' | 'blocklist' | 'heuristics' | 'api' | 'fail-open';
  timestamp: number;
  blockSource?: 'blocklist' | 'ml' | 'heuristic';
}

export class BackgroundService {
  private settings: DeviceSettings = { ...DEFAULT_SETTINGS };
  private allowlistFilter: BloomFilter | null = null;
  private decisionCache = new Map<string, CachedDecision>();
  private pendingNavigations = new Map<number, { url: string; startTime: number }>();
  private navigationDebounce = new Map<string, ReturnType<typeof setTimeout>>(); // url -> timer ID
  private blockCache = new Map<number, BlockData>();

  private contextMenuHandler: ContextMenuHandler | null = null;
  private batchAnalyzer: BatchAnalyzer | null = null;

  async init() {
    await this.loadSettings();
    await this.initAllowlist();
    await this.ensureDeviceToken();
    await this.syncBlocklist();
    await this.loadCache();

    // Initialize context menu
    this.contextMenuHandler = new ContextMenuHandler(this);
    await this.contextMenuHandler.initialize();

    // Initialize batch analyzer
    this.batchAnalyzer = new BatchAnalyzer(this);
    this.batchAnalyzer.setConfig(this.settings.apiBaseUrl, this.settings.deviceToken);

    browser.webNavigation.onBeforeNavigate.addListener(this.onBeforeNavigate.bind(this), { url: [{ schemes: ['http', 'https'] }] });
    browser.webNavigation.onCommitted.addListener(this.onCommitted.bind(this), { url: [{ schemes: ['http', 'https'] }] });
    browser.runtime.onMessage.addListener(this.onMessage.bind(this));
    browser.storage.onChanged.addListener((changes, areaName) => {
      if (areaName !== 'local' || !changes.settings) return;

      const updatedSettings = changes.settings.newValue;
      this.settings = {
        ...DEFAULT_SETTINGS,
        ...(updatedSettings && typeof updatedSettings === 'object' ? updatedSettings : {}),
      };
      this.batchAnalyzer?.setConfig(this.settings.apiBaseUrl, this.settings.deviceToken);
    });
    browser.runtime.onInstalled.addListener(this.onInstalled.bind(this));
    browser.runtime.onStartup.addListener(this.onStartup.bind(this));

    browser.alarms.create('syncBlocklist', { periodInMinutes: 5 });
    browser.alarms.create('cleanupHistory', { periodInMinutes: 60 });
    browser.alarms.onAlarm.addListener(this.onAlarm.bind(this));

    console.log('Guardian background service initialized');
  }

  private async loadSettings() {
    const stored = await browser.storage.local.get('settings');
    this.settings = { ...DEFAULT_SETTINGS, ...(stored.settings || {}) };
  }

  private async saveSettings() {
    await browser.storage.local.set({ settings: this.settings });
  }

  private async initAllowlist() {
    try {
      this.allowlistFilter = await loadTrancoBloomFilter();
      console.log('Tranco allowlist loaded:', this.allowlistFilter.getStats());
    } catch (e) {
      console.error('Failed to load allowlist:', e);
    }
  }

  private async ensureDeviceToken() {
    if (!this.settings.deviceToken) {
      await this.registerDevice();
    }
  }

  private async registerDevice() {
    try {
      const response = await fetch(`${this.settings.apiBaseUrl}/devices`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (response.ok) {
        const data = await response.json();
        this.settings.deviceToken = data.device_token;
        await this.saveSettings();
      }
    } catch (e) {
      console.error('Failed to register device:', e);
    }
  }

  private blocklistEntries: Map<string, { reason: string; expiresAt: number }> = new Map();

  private async syncBlocklist() {
    try {
      const since = this.settings.blocklistUpdatedAt || new Date(0).toISOString();
      const response = await fetch(
        `${this.settings.apiBaseUrl}/blocklist/delta?since=${encodeURIComponent(since)}`,
        { headers: { 'X-Device-Token': this.settings.deviceToken } }
      );
      if (!response.ok) {
        throw new Error(`Blocklist request failed with HTTP ${response.status}`);
      }
      const data = parseBlocklistDelta(await response.json() as unknown);
      
      // Store blocklist entries in memory for hash-based matching
      for (const addition of data.additions) {
        const expiresAt = new Date(addition.expires_at).getTime();
        if (expiresAt > Date.now()) {
          this.blocklistEntries.set(addition.domain_hash, { 
            reason: addition.reason, 
            expiresAt 
          });
        }
      }
      for (const removal of data.removals) {
        this.blocklistEntries.delete(removal);
      }
      
      // Clean up expired entries
      const now = Date.now();
      for (const [hash, entry] of this.blocklistEntries.entries()) {
        if (entry.expiresAt <= now) {
          this.blocklistEntries.delete(hash);
        }
      }

      this.settings.blocklistVersion += data.additions.length > 0 ? 1 : 0;
      this.settings.blocklistUpdatedAt = data.timestamp;
      await this.saveSettings();
      console.log(`Blocklist synced: +${data.additions.length} -${data.removals.length}, active: ${this.blocklistEntries.size}`);
    } catch (e) {
      console.error('Blocklist sync failed:', e);
    }
  }

  private async onBeforeNavigate(details: browser.WebNavigation.OnBeforeNavigateDetailsType) {
    if (details.frameId !== 0) return;

    const { url, tabId } = details;

    if (this.isInternalUrl(url)) return;
    if (!this.settings.protectionEnabled) return;

    // Debounce rapid navigations to same URL
    const debounceKey = `${tabId}:${url}`;
    const existingTimer = this.navigationDebounce.get(debounceKey);
    if (existingTimer) {
      clearTimeout(existingTimer);
    }

    const timer = setTimeout(async () => {
      this.navigationDebounce.delete(debounceKey);
      await this.processNavigation(tabId, url);
    }, 50); // 50ms debounce

    this.navigationDebounce.set(debounceKey, timer);
    this.pendingNavigations.set(tabId, { url, startTime: Date.now() });
  }

  private async processNavigation(tabId: number, url: string) {
    const host = this.extractHost(url);
    if (!host) return;

    // Check custom allowlist first
    if (this.settings.customAllowlist.some(d => this.domainMatches(host, d))) {
      await this.recordDecision(url, host, 0, 'Low', 'allow', [], 'Domain in custom allowlist', 'allowlist');
      return;
    }

    // Check custom blocklist
    if (this.settings.customBlocklist.some(d => this.domainMatches(host, d))) {
      await this.blockTab(tabId, url, 'malicious', { score: 100, level: 'Critical', signals: [], blockSource: 'blocklist' });
      return;
    }

    // 1. Check Tranco allowlist (Bloom filter)
    if (this.allowlistFilter && this.allowlistFilter.test(host)) {
      await this.recordDecision(url, host, 0, 'Low', 'allow', [], 'Domain in Tranco top-100K allowlist', 'allowlist');
      return;
    }

    // 2. Check local blocklist (hash-based matching)
    const blocklistCheck = await this.checkBlocklist(host);
    if (blocklistCheck.matched) {
      this.pendingNavigations.set(tabId, { url, startTime: Date.now() });
      await this.blockTab(tabId, url, 'malicious', { autoBlocked: true, blockSource: 'blocklist' });
      return;
    }

    // 3. Run local quick heuristics
    const heuristicResult = runHeuristics(url);
    const explanation = generateExplanation(heuristicResult);

    // If clearly benign, allow without API call
    if (!heuristicResult.shouldAnalyze && heuristicResult.score < 15) {
      await this.recordDecision(url, host, heuristicResult.score, heuristicResult.level, 'allow', heuristicResult.signals, explanation, 'heuristics');
      return;
    }

    // 4. Call backend API for unknown/suspicious URLs
    const privacyMode = this.settings.privacyMode || 'standard';
    const urlToSend = privacyMode === 'strict' ? host : this.stripSensitiveParams(url);

    const request: AnalyzeRequest = {
      channel: 'url',
      urls: [urlToSend],
      options: { deep: false },
    };

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1500);

      const response = await fetch(`${this.settings.apiBaseUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Token': this.settings.deviceToken,
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const result: AnalyzeResponse = await response.json();

      // Cache the decision
      const cacheKey = this.getCacheKey(url);
      const cachedDecision: CachedDecision = {
        url,
        score: result.score,
        level: result.level,
        action: result.action,
        signals: result.signals,
        explanation: this.generateApiExplanation(result),
        source: 'api',
        timestamp: Date.now(),
      };
      this.decisionCache.set(cacheKey, cachedDecision);
      await this.persistCache();

      // Record to history
      await this.recordDecision(url, host, result.score, result.level, result.action, result.signals, cachedDecision.explanation, 'api');

      // Act on result based on enforcement policy
      const shouldBlock = this.shouldBlockBasedOnPolicy(result.level, result.action);
      if (shouldBlock) {
        await this.blockTab(tabId, url, 'malicious', { 
          caseId: result.case_id, 
          score: result.score, 
          level: result.level, 
          signals: result.signals,
          blockSource: 'ml'
        });
      } else if (result.action === 'warn' && this.settings.showInlineBadges) {
        browser.tabs.sendMessage(tabId, { type: 'SHOW_BADGE', data: { score: result.score, level: result.level, signals: result.signals } });
      }

      if (this.settings.sendTelemetry) {
        this.callApi('/cases', { method: 'POST', body: JSON.stringify({ ...request, result }) });
      }
    } catch (e) {
      // Fail-open: allow but record appropriately
      const isNetworkError = e instanceof TypeError || e instanceof DOMException || (e as Error)?.name === 'AbortError';
      const errorMessage = e instanceof Error ? e.message : String(e);
      console.warn('API analysis failed, fail-open:', errorMessage);

      // If heuristic score was low (benign), allow silently without badge
      // This handles network issues for clean domains
      if (heuristicResult.score < 15 && heuristicResult.signals.length === 0) {
        await this.recordDecision(url, host, 0, 'Low', 'allow', heuristicResult.signals, 
          'API unavailable; local heuristics found no issues.', 'fail-open');
        return;
      }

      // For suspicious domains where API failed, show unchecked warning
      const failOpenExplanation = isNetworkError 
        ? 'Analysis service temporarily unreachable. Proceed with caution.'
        : 'Analysis service error. Proceed with caution.';
      await this.recordDecision(url, host, heuristicResult.score, heuristicResult.level, 'warn', heuristicResult.signals, 
        failOpenExplanation, 'fail-open');

      // Show "unchecked" badge if inline badges enabled
      if (this.settings.showInlineBadges) {
        browser.tabs.sendMessage(tabId, {
          type: 'SHOW_BADGE',
          data: { 
            score: heuristicResult.score, 
            level: heuristicResult.level, 
            signals: heuristicResult.signals, 
            unchecked: true, 
            explanation: failOpenExplanation 
          },
        });
      }
    }
  }

  private async onCommitted(details: browser.WebNavigation.OnCommittedDetailsType) {
    if (details.frameId !== 0) return;

    const { url, tabId } = details;
    this.pendingNavigations.delete(tabId);
    this.cleanupDebounce(tabId, url);

    if (this.isInternalUrl(url)) return;
    if (!this.settings.protectionEnabled) return;

    // Check if we already blocked this navigation
    const pending = this.pendingNavigations.get(tabId);
    if (pending && pending.url === url) {
      // Navigation was already handled in onBeforeNavigate
      return;
    }

    // For navigations that didn't go through onBeforeNavigate (rare),
    // or to double-check, run analysis here too
    await this.processNavigation(tabId, url);
  }

  private cleanupDebounce(tabId: number, url: string) {
    const key = `${tabId}:${url}`;
    const timer = this.navigationDebounce.get(key);
    if (timer) {
      clearTimeout(timer);
      this.navigationDebounce.delete(key);
    }
  }

  private async checkBlocklist(host: string): Promise<{ matched: boolean; reason?: string }> {
    try {
      // Hash the domain to check against blocklist entries
      // The blocklist uses sha256(domain)[:16] format
      const domainHash = await this.hashDomain(host);
      const entry = this.blocklistEntries.get(domainHash);
      if (entry) {
        return { matched: true, reason: entry.reason };
      }
      return { matched: false };
    } catch {
      return { matched: false };
    }
  }

  private async hashDomain(domain: string): Promise<string> {
    // Match the backend format: sha256(domain)[:16]
    const encoder = new TextEncoder();
    const data = encoder.encode(domain.toLowerCase());
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.slice(0, 16).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private async blockTab(tabId: number, url: string, reason: 'malicious' | 'inappropriate', extra: Partial<BlockData>) {
    const blockData: BlockData = {
      url,
      reason,
      timestamp: Date.now(),
      ...extra,
    };

    this.blockCache.set(tabId, blockData);

    // Include referrer for proper "Go back" functionality
    const blockedUrl = browser.runtime.getURL('blocked.html') + `?tabId=${tabId}&referrer=${encodeURIComponent(url)}`;
    await browser.tabs.update(tabId, { url: blockedUrl });
  }

  private isInternalUrl(url: string): boolean {
    return url.startsWith('chrome://') ||
           url.startsWith('chrome-extension://') ||
           url.startsWith('moz-extension://') ||
           url.startsWith('about:') ||
           url.startsWith('edge://') ||
           url.startsWith('brave://');
  }

  private extractHost(url: string): string | null {
    try {
      return new URL(url).hostname;
    } catch {
      return null;
    }
  }

  private domainMatches(host: string, pattern: string): boolean {
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      return host === suffix || host.endsWith('.' + suffix);
    }
    return host === pattern;
  }

  private stripSensitiveParams(url: string): string {
    try {
      const u = new URL(url);
      // Remove common sensitive parameter names
      const sensitiveParams = ['token', 'session', 'auth', 'key', 'secret', 'password', 'code', 'state', 'nonce'];
      for (const param of sensitiveParams) {
        u.searchParams.delete(param);
      }
      return u.origin + u.pathname + (u.search ? '?' + u.search : '');
    } catch {
      return url;
    }
  }

  private getCacheKey(url: string): string {
    try {
      const u = new URL(url);
      return u.hostname + u.pathname;
    } catch {
      return url;
    }
  }

  private async persistCache() {
    const cacheArray = Array.from(this.decisionCache.entries()).slice(-500); // Keep last 500
    await browser.storage.session.set({ decisionCache: Object.fromEntries(cacheArray) });
  }

  private async loadCache() {
    const stored = await browser.storage.session.get('decisionCache');
    if (stored.decisionCache) {
      this.decisionCache = new Map(Object.entries(stored.decisionCache));
    }
  }

  private generateApiExplanation(result: AnalyzeResponse): string {
    if (result.signals.length === 0) {
      return 'Analysis complete. No suspicious signals detected.';
    }

    const topSignals = result.signals
      .sort((a, b) => b.points - a.points)
      .slice(0, 3);

    const reasons = topSignals.map(s => `• ${s.label}: ${s.reason}`).join('\n');
    return `Risk score: ${result.score}/100 (${result.level})\n\nTop reasons:\n${reasons}`;
  }

  private async recordDecision(
    url: string,
    host: string,
    score: number,
    level: RiskLevel,
    action: ActionType,
    signals: Signal[],
    explanation: string,
    source: CachedDecision['source']
  ) {
    const entry = {
      timestamp: Date.now(),
      url,
      host,
      registrableDomain: this.extractRegistrableDomain(host),
      score,
      level,
      action,
      signals,
      explanation,
      source,
      latencyMs: 0, // Would need timing
      privacyMode: this.settings.privacyMode || 'standard',
    };

    await addHistoryEntry(entry);
  }

  private extractRegistrableDomain(host: string): string {
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const tld = parts[parts.length - 1];
    const secondLevel = parts[parts.length - 2];
    const twoPartTlds = new Set(['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'com.mx']);
    const maybeTwoPart = `${secondLevel}.${tld}`;
    if (twoPartTlds.has(maybeTwoPart) && parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return `${secondLevel}.${tld}`;
  }

  private shouldBlockBasedOnPolicy(level: RiskLevel, action: ActionType): boolean {
    if (this.settings.enforcementPolicy === 'warn') {
      return false; // Never auto-block in warn mode
    }
    // Block mode: block on High/Critical when action is block
    return action === 'block' && (level === 'High' || level === 'Critical');
  }

  private async callApi(endpoint: string, options: { method?: string; body?: string } = {}) {
    return fetch(`${this.settings.apiBaseUrl}${endpoint}`, {
      method: options.method || 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Device-Token': this.settings.deviceToken,
      },
      body: options.body,
    });
  }

  private async analyzeText(text: string, channel: string, sender?: string) {
    try {
      const request: AnalyzeRequest = {
        channel: channel as any,
        sender,
        text: text.slice(0, 50000), // Limit to 50KB
        urls: [],
        options: { deep: true },
      };

      const response = await this.callApi('/analyze', { body: JSON.stringify(request) });
      
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }

      const result: AnalyzeResponse = await response.json();
      
      // Extract URLs from text for response
      const extractedUrls = this.extractUrlsFromText(text);
      
      return {
        ...result,
        extractedUrls: extractedUrls.map(url => ({
          url,
          host: new URL(url).hostname,
          riskLevel: result.level,
          signals: result.signals,
        })),
      };
    } catch (error) {
      console.error('Text analysis failed:', error);
      return {
        case_id: '',
        score: 0,
        level: 'Low' as RiskLevel,
        action: 'allow' as ActionType,
        signals: [],
        urls: [],
        model_version: '',
        latency_ms: 0,
        extractedUrls: [],
        error: String(error),
      };
    }
  }

  private extractUrlsFromText(text: string): string[] {
    const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/g;
    const matches = text.match(urlRegex) || [];
    return [...new Set(matches)]; // Deduplicate
  }

  private onMessage(message: unknown, sender: browser.Runtime.MessageSender, sendResponse: (response: unknown) => void): true {
    const msg = message as { type: string; data?: unknown };

    switch (msg.type) {
      case 'GET_BLOCK_DATA': {
        const tabId = (msg.data as { tabId: number }).tabId;
        const blockData = this.blockCache.get(tabId);
        sendResponse(blockData || null);
        break;
      }
      case 'GET_SETTINGS': {
        sendResponse(this.settings);
        break;
      }
      case 'UPDATE_SETTINGS': {
        this.settings = { ...this.settings, ...(msg.data as Partial<DeviceSettings>) };
        this.saveSettings().then(() => sendResponse({ success: true }));
        return true;
      }
      case 'REPORT_URL': {
        const { url, note } = msg.data as { url: string; note?: string };
        this.callApi('/report', { method: 'POST', body: JSON.stringify({ url, note }) }).then(() => sendResponse({ success: true }));
        return true;
      }
      case 'FEEDBACK': {
        const { case_id, verdict, notes } = msg.data as { case_id: string; verdict: string; notes?: string };
        this.callApi('/feedback', { method: 'POST', body: JSON.stringify({ case_id, verdict, notes }) }).then(() => sendResponse({ success: true }));
        return true;
      }
      case 'CONTINUE_ANYWAY': {
        const tabId = (msg.data as { tabId: number }).tabId;
        const blockData = this.blockCache.get(tabId);
        if (blockData) {
          this.blockCache.delete(tabId);
          // Navigate back to the original URL without permanently adding to allowlist
          // The user explicitly chose to proceed for this session only
          browser.tabs.update(tabId, { url: blockData.url }).then(() => sendResponse({ success: true }));
          return true;
        }
        // If no block data, do nothing
        sendResponse({ success: false, error: 'No block data found' });
        return true;
      }
      case 'ANALYZE_CURRENT_URL': {
        const { tabId, url } = msg.data as { tabId: number; url: string };
        this.processNavigation(tabId, url).then(() => sendResponse({ success: true }));
        return true;
      }
      case 'GET_CACHED_DECISION': {
        const { url } = msg.data as { url: string };
        const cacheKey = this.getCacheKey(url);
        const cached = this.decisionCache.get(cacheKey);
        sendResponse(cached || null);
        break;
      }
      case 'ANALYZE_DOMAINS': {
        const { domains } = msg.data as { domains: string[] };
        this.batchAnalyzer!.analyzeDomains(domains).then(results => sendResponse({ results }));
        return true;
      }
      case 'GET_BADGE_DATA': {
        const { href } = msg.data as { href: string };
        // Find cached decision for this URL
        const cacheKey = this.getCacheKey(href);
        const cached = this.decisionCache.get(cacheKey);
        if (cached) {
          sendResponse({
            level: cached.level,
            score: cached.score,
            topSignal: cached.signals[0],
          });
        } else {
          sendResponse(null);
        }
        break;
      }
      case 'UPDATE_BADGE': {
        // Badge updates are handled by content script directly
        sendResponse({ success: true });
        break;
      }
      case 'REMOVE_BADGE': {
        // Badge removal handled by content script
        sendResponse({ success: true });
        break;
      }
      case 'CONTEXT_MENU_ANALYZE': {
        const { text, channel, sender: senderParam } = msg.data as { text: string; channel: string; sender?: string };
        this.analyzeText(text, channel, senderParam).then(result => sendResponse(result));
        return true;
      }
      default:
        sendResponse({ error: 'Unknown message type' });
    }

    return true;
  }

  private async onInstalled(details: browser.Runtime.OnInstalledDetailsType) {
    if (details.reason === 'install') {
      await this.registerDevice();
      browser.tabs.create({ url: browser.runtime.getURL('options.html') });
    }
  }

  private async onStartup() {
    await this.loadSettings();
    await this.initAllowlist();
    await this.loadCache();
    await this.syncBlocklist();
  }

  private async onAlarm(alarm: browser.Alarms.Alarm) {
    if (alarm.name === 'syncBlocklist') {
      await this.syncBlocklist();
    } else if (alarm.name === 'cleanupHistory') {
      await runRetentionCleanup();
    }
  }
}

const service = new BackgroundService();
service.init();

export {};