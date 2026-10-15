/**
 * Link Analyzer - Core content script logic for link analysis
 * Coordinates: mismatch detection, batch analysis, badge rendering, click interception
 */

import browser from 'webextension-polyfill';
import { 
  RiskLevel, 
  Signal, 
  SignalCategory, 
  EvidenceItem,
  LinkData, 
  DomainAnalysis,
  BadgeData,
  ExtendedDeviceSettings,
  SupportedSite,
  SUPPORTED_SITES 
} from '@shared/types';
import { 
  extractRegistrableDomain, 
  looksLikeDomain, 
  checkBrandMismatch, 
  createMismatchSignal,
  extractVisibleText,
  isAnalyzableUrl,
  isExternalUrl,
  sanitizeText,
  truncateText,
  BRAND_KEYWORDS 
} from './sanitize';
import { renderBadge, updateBadge, removeBadge, hasBadge, getBadgeData } from './badge-renderer';
import { showWarningDialog, hideWarningDialog, isWarningDialogShown } from './warning-dialog';
import { LinkMutationObserver, createLinkObserver } from './mutation-observer';
import { 
  detectSite, 
  getCurrentSite, 
  setCurrentSite, 
  isLinkScanningEnabledForCurrentSite,
  getScanRoot,
  watchForSiteChanges,
  shouldScanAnchor 
} from './site-detector';

// Brand keywords for mismatch detection (imported from sanitize)
const BRAND_KEYWORDS_SET = new Set(BRAND_KEYWORDS);

// ===== State =====

interface LinkAnalyzerState {
  settings: ExtendedDeviceSettings | null;
  domainCache: Map<string, DomainAnalysis>;
  pendingBatch: Set<string>;
  batchTimer: ReturnType<typeof setTimeout> | null;
  observer: LinkMutationObserver | null;
  siteWatcher: (() => void) | null;
  clickHandlers: WeakMap<HTMLAnchorElement, EventListener>;
  initialized: boolean;
}

const state: LinkAnalyzerState = {
  settings: null,
  domainCache: new Map(),
  pendingBatch: new Set(),
  batchTimer: null,
  observer: null,
  siteWatcher: null,
  clickHandlers: new WeakMap(),
  initialized: false,
};

// ===== Constants =====

const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_CACHE_SIZE = 500;
const BATCH_SIZE = 20;
const BATCH_DELAY_MS = 500;

// ===== Initialization =====

export async function initializeLinkAnalyzer(settings: ExtendedDeviceSettings): Promise<void> {
  if (state.initialized) return;
  
  state.settings = settings;
  
  // Check if link scanning is enabled
  if (!settings.linkScanningEnabled) {
    console.log('[Guardian] Link scanning disabled');
    return;
  }
  
  // Detect current site
  const site = detectSite();
  setCurrentSite(site);
  
  if (!site || !isLinkScanningEnabledForCurrentSite(settings.enabledSites)) {
    console.log('[Guardian] Not on a supported/enabled site');
    // Still watch for site changes
    setupSiteWatcher();
    return;
  }
  
  console.log(`[Guardian] Link scanning active on ${site.config.name}`);
  
  // Set up mutation observer
  setupObserver();
  
  // Watch for site changes (SPA navigation)
  setupSiteWatcher();
  
  // Listen for settings changes
  browser.storage.onChanged.addListener(handleSettingsChange);
  
  state.initialized = true;
}

function setupObserver(): void {
  if (!state.settings) return;
  
  const root = getScanRoot();
  
  state.observer = createLinkObserver(
    handleLinksFound,
    handleLinksRemoved,
    state.settings.observerThrottleMs,
    state.settings.maxLinksPerPage
  );
  
  state.observer.start();
}

function setupSiteWatcher(): void {
  state.siteWatcher = watchForSiteChanges(handleSiteChange, 1000);
}

function handleSiteChange(site: ReturnType<typeof detectSite>): void {
  setCurrentSite(site);
  
  if (!state.settings) return;
  
  const enabled = site && isLinkScanningEnabledForCurrentSite(state.settings.enabledSites);
  
  if (enabled && !state.observer) {
    console.log(`[Guardian] Link scanning activated on ${site?.config.name}`);
    setupObserver();
  } else if (!enabled && state.observer) {
    console.log('[Guardian] Link scanning deactivated');
    state.observer.stop();
    state.observer = null;
    clearAllBadges();
  }
}

// ===== Settings Change Handling =====

function handleSettingsChange(changes: { [key: string]: browser.Storage.StorageChange }, area: string): void {
  if (area !== 'local') return;
  
  if (changes.settings) {
    const newSettings = changes.settings.newValue as ExtendedDeviceSettings;
    if (newSettings) {
      state.settings = newSettings;
      
      // Re-check site enablement
      const site = getCurrentSite();
      const enabled = site && isLinkScanningEnabledForCurrentSite(newSettings.enabledSites);
      
      if (enabled && !state.observer) {
        setupObserver();
      } else if (!enabled && state.observer) {
        state.observer.stop();
        state.observer = null;
        clearAllBadges();
      }
      
      // Update observer config
      if (state.observer) {
        state.observer.updateConfig({
          throttleMs: newSettings.observerThrottleMs,
          maxLinksPerPage: newSettings.maxLinksPerPage,
        });
      }
    }
  }
}

// ===== Link Processing =====

function handleLinksFound(links: LinkData[]): void {
  if (!state.settings) return;
  
  // Check each link for display-text mismatch
  for (const link of links) {
    checkAndAttachMismatchSignal(link);
  }
  
  // Filter links that need analysis (no cached result, not Low risk)
  const unknownLinks = links.filter(link => {
    // Skip if already has badge (already analyzed)
    if (hasBadge(link.element)) return false;
    
    // Skip if in cache and not expired
    const cached = state.domainCache.get(link.registrableDomain);
    if (cached && Date.now() - cached.analyzedAt < CACHE_TTL_MS) {
      applyCachedResult(link, cached);
      return false;
    }
    
    return true;
  });
  
  // Queue unknown domains for batch analysis
  for (const link of unknownLinks) {
    queueForBatchAnalysis(link.registrableDomain);
  }
}

function handleLinksRemoved(anchors: HTMLAnchorElement[]): void {
  for (const anchor of anchors) {
    removeBadge(anchor);
    hideWarningDialog(anchor);
    removeClickHandler(anchor);
  }
}

function checkAndAttachMismatchSignal(link: LinkData): void {
  const { visibleText, href, host } = link;
  
  // Check 1: Visible text looks like a domain but doesn't match href host
  if (looksLikeDomain(visibleText)) {
    const textDomain = extractRegistrableDomain(visibleText);
    const hrefDomain = extractRegistrableDomain(host);
    
    if (textDomain !== hrefDomain) {
      link.mismatchSignal = createMismatchSignal(visibleText, href, host);
      applyMismatchBadge(link);
      return;
    }
  }
  
  // Check 2: Visible text contains brand but href doesn't
  const brandMismatch = checkBrandMismatch(visibleText, host, BRAND_KEYWORDS);
  if (brandMismatch) {
    link.mismatchSignal = brandMismatch;
    applyMismatchBadge(link);
    return;
  }
  
  // Check 3: Generic text ("Click here", "Link") with suspicious href
  const genericTexts = ['click here', 'click', 'here', 'link', 'read more', 'learn more', 'view', 'open'];
  const lowerText = visibleText.toLowerCase().trim();
  if (genericTexts.includes(lowerText)) {
    // Run quick heuristic on href
    const heuristic = quickHeuristicCheck(href);
    if (heuristic.score >= 25) {
      link.mismatchSignal = {
        key: 'display_text_mismatch',
        category: 'behavioral',
        label: 'Generic link text with suspicious destination',
        points: 20,
        reason: `Generic text "${visibleText}" points to suspicious URL`,
        evidence: [
          { type: 'visible_text', value: visibleText, description: 'Visible link text' },
          { type: 'destination_url', value: href, description: 'Actual destination URL' },
          { type: 'heuristic_score', value: String(heuristic.score), description: 'Heuristic risk score' },
        ],
      };
      applyMismatchBadge(link);
    }
  }
}

function applyMismatchBadge(link: LinkData): void {
  if (!link.mismatchSignal) return;
  
  // Mismatch alone = Medium risk at minimum
  const level: RiskLevel = 'Medium';
  const score = Math.max(25, link.mismatchSignal.points);
  
  renderBadge(link.element, level, score, link.mismatchSignal);
  
  // Attach click handler for Medium+ (warning dialog for High/Critical)
  attachClickHandler(link.element, link.href, level, score, link.mismatchSignal ? [link.mismatchSignal] : []);
}

function applyCachedResult(link: LinkData, cached: DomainAnalysis): void {
  if (cached.level === 'Low') return;
  
  renderBadge(link.element, cached.level, cached.score, cached.signals[0]);
  attachClickHandler(link.element, link.href, cached.level, cached.score, cached.signals);
}

function quickHeuristicCheck(url: string): { score: number; level: RiskLevel } {
  let score = 0;
  
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    
    // URL shortener check
    const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'short.io', 'cutt.ly'];
    if (shorteners.some(s => domain.includes(s))) score += 15;
    
    // Suspicious TLD
    const suspiciousTlds = ['xyz', 'top', 'loan', 'click', 'link', 'online', 'site', 'space', 'tech', 'info', 'biz'];
    const tld = domain.split('.').pop() || '';
    if (suspiciousTlds.includes(tld)) score += 15;
    
    // IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) score += 30;
    
    // Long domain
    if (domain.length > 50) score += 10;
    
    // Excessive subdomains
    if (domain.split('.').length >= 5) score += 10;
    
    // Suspicious keywords in URL
    const suspiciousKeywords = ['login', 'verify', 'update', 'confirm', 'secure', 'account', 'auth', 'wallet', 'crypto', 'urgent', 'immediate'];
    const lowerUrl = url.toLowerCase();
    const matches = suspiciousKeywords.filter(k => lowerUrl.includes(k)).length;
    if (matches >= 3) score += 20;
    else if (matches >= 1) score += 8;
    
  } catch {
    score = 0;
  }
  
  let level: RiskLevel = 'Low';
  if (score >= 70) level = 'Critical';
  else if (score >= 50) level = 'High';
  else if (score >= 25) level = 'Medium';
  
  return { score, level };
}

// ===== Batch Analysis =====

function queueForBatchAnalysis(domain: string): void {
  // Skip if already pending or cached
  if (state.pendingBatch.has(domain)) return;
  if (state.domainCache.has(domain)) {
    const cached = state.domainCache.get(domain)!;
    if (Date.now() - cached.analyzedAt < CACHE_TTL_MS) return;
  }
  
  state.pendingBatch.add(domain);
  
  // Schedule batch
  if (state.batchTimer) clearTimeout(state.batchTimer);
  
  state.batchTimer = setTimeout(() => {
    processBatch();
  }, BATCH_DELAY_MS);
  
  // If batch is full, process immediately
  if (state.pendingBatch.size >= BATCH_SIZE) {
    if (state.batchTimer) clearTimeout(state.batchTimer);
    processBatch();
  }
}

async function processBatch(): Promise<void> {
  if (state.pendingBatch.size === 0) return;
  if (!state.settings) return;
  
  const domains = Array.from(state.pendingBatch).slice(0, BATCH_SIZE);
  state.pendingBatch.clear();
  
  try {
    const response = await browser.runtime.sendMessage({
      type: 'ANALYZE_DOMAINS',
      data: { domains },
    }) as { results: DomainAnalysis[] } | null;
    
    if (response && response.results) {
      handleBatchResults(response.results);
    }
  } catch (error) {
    console.error('[Guardian] Batch analysis failed:', error);
    // Re-queue domains on failure
    for (const domain of domains) {
      state.pendingBatch.add(domain);
    }
  }
}

function handleBatchResults(results: DomainAnalysis[]): void {
  for (const result of results) {
    // Cache result
    cacheDomainResult(result);
    
    // Find and update matching links
    // Note: We can't easily find links by domain here without a reverse index
    // The next mutation observer scan will pick up cached results
  }
}

function cacheDomainResult(result: DomainAnalysis): void {
  // LRU eviction
  if (state.domainCache.size >= MAX_CACHE_SIZE) {
    const firstKey = state.domainCache.keys().next().value;
    if (firstKey) state.domainCache.delete(firstKey);
  }
  
  state.domainCache.set(result.domain, {
    ...result,
    analyzedAt: Date.now(),
  });
}

// ===== Click Handling =====

function attachClickHandler(
  anchor: HTMLAnchorElement,
  targetUrl: string,
  level: RiskLevel,
  score: number,
  signals: Signal[]
): void {
  // Only intercept High/Critical clicks
  if (level !== 'High' && level !== 'Critical') return;
  if (!state.settings?.warningDialogEnabled) return;
  
  // Check if already has handler
  if (state.clickHandlers.has(anchor)) return;
  
  const handler = (event: Event) => {
    // Only handle click events
    if (event.type !== 'click') return;
    
    const mouseEvent = event as MouseEvent;
    
    // Only intercept trusted (user) clicks
    if (!mouseEvent.isTrusted) return;
    
    // Don't intercept if modifier keys held (open in new tab, etc.)
    if (mouseEvent.ctrlKey || mouseEvent.metaKey || mouseEvent.shiftKey || mouseEvent.altKey) return;
    
    // Don't intercept middle/right click
    if (mouseEvent.button !== 0) return;
    
    // Prevent navigation
    mouseEvent.preventDefault();
    mouseEvent.stopPropagation();
    mouseEvent.stopImmediatePropagation();
    
    // Show warning dialog
    showWarningDialog(
      anchor,
      targetUrl,
      level,
      score,
      signals,
      // On confirm - allow navigation
      () => {
        // Remove handler temporarily to allow navigation
        removeClickHandler(anchor);
        anchor.click(); // This will be a trusted click since it's user-initiated
        // Re-attach after a tick
        setTimeout(() => attachClickHandler(anchor, targetUrl, level, score, signals), 100);
      },
      // On cancel - do nothing (stay on page)
      () => {}
    );
  };
  
  // Use capture phase to intercept before page handlers
  anchor.addEventListener('click', handler, { capture: true, passive: false });
  state.clickHandlers.set(anchor, handler);
}

function removeClickHandler(anchor: HTMLAnchorElement): void {
  const handler = state.clickHandlers.get(anchor);
  if (handler) {
    anchor.removeEventListener('click', handler, { capture: true });
    state.clickHandlers.delete(anchor);
  }
}

// ===== Badge Management =====

function clearAllBadges(): void {
  // Badges are cleaned up via WeakMap when elements are removed
  // But we can remove from currently visible elements
  const anchors = document.querySelectorAll('a[href]');
  for (const anchor of anchors) {
    removeBadge(anchor as HTMLAnchorElement);
    hideWarningDialog(anchor as HTMLAnchorElement);
    removeClickHandler(anchor as HTMLAnchorElement);
  }
}

// ===== Message Handling (from background) =====

export function handleMessage(message: any, sender: browser.Runtime.MessageSender, sendResponse: (response: any) => void): boolean {
  switch (message.type) {
    case 'GET_BADGE_DATA': {
      const { href } = message.data;
      // Find link by href and return badge data
      const anchors = document.querySelectorAll(`a[href="${CSS.escape(href)}"]`);
      for (const anchor of anchors) {
        const badgeData = getBadgeData(anchor as HTMLAnchorElement);
        if (badgeData) {
          sendResponse({
            level: badgeData.level,
            score: badgeData.score,
            topSignal: badgeData.topSignal,
          });
          return true;
        }
      }
      sendResponse(null);
      return true;
    }
    
    case 'UPDATE_BADGE': {
      const { href, level, score, topSignal } = message.data;
      const anchors = document.querySelectorAll(`a[href="${CSS.escape(href)}"]`);
      for (const anchor of anchors) {
        if (level === 'Low') {
          removeBadge(anchor as HTMLAnchorElement);
        } else {
          renderBadge(anchor as HTMLAnchorElement, level, score, topSignal);
        }
      }
      sendResponse({ success: true });
      return true;
    }
    
    case 'REMOVE_BADGE': {
      const { href } = message.data;
      const anchors = document.querySelectorAll(`a[href="${CSS.escape(href)}"]`);
      for (const anchor of anchors) {
        removeBadge(anchor as HTMLAnchorElement);
      }
      sendResponse({ success: true });
      return true;
    }
    
    case 'PING': {
      sendResponse({ pong: true, initialized: state.initialized });
      return true;
    }
  }
  return false;
}

// ===== Cleanup =====

export function cleanup(): void {
  if (state.observer) {
    state.observer.stop();
    state.observer = null;
  }
  if (state.siteWatcher) {
    state.siteWatcher();
    state.siteWatcher = null;
  }
  if (state.batchTimer) {
    clearTimeout(state.batchTimer);
    state.batchTimer = null;
  }
  clearAllBadges();
  state.domainCache.clear();
  state.pendingBatch.clear();
  state.initialized = false;
}