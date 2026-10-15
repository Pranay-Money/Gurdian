/**
 * Site Detector - Identifies supported sites and conversation/DM areas
 */

import { SupportedSite, SiteConfig, SUPPORTED_SITES } from '@shared/types';

interface DetectedSite {
  site: SupportedSite;
  config: SiteConfig;
  isInConversation: boolean;
  conversationRoot: Element | null;
}

let currentSite: DetectedSite | null = null;
let siteCheckTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * Check if current page matches a supported site
 */
export function detectSite(): DetectedSite | null {
  const hostname = window.location.hostname;
  const href = window.location.href;
  
  for (const [key, config] of Object.entries(SUPPORTED_SITES)) {
    const siteKey = key as SupportedSite;
    
    // Check host patterns
    for (const pattern of config.hostPatterns) {
      if (matchHostPattern(href, pattern)) {
        // Check if in conversation/DM area
        const { isInConversation, conversationRoot } = checkConversationArea(config);
        
        return {
          site: siteKey,
          config,
          isInConversation,
          conversationRoot,
        };
      }
    }
  }
  
  return null;
}

/**
 * Match URL against host pattern (supports wildcards)
 */
function matchHostPattern(url: string, pattern: string): boolean {
  // Convert pattern to regex
  // *://mail.google.com/* -> ^https?://[^/]*\.?mail\.google\.com/
  const regexPattern = pattern
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')
    .replace(/\./g, '\\.');
  
  try {
    return new RegExp(`^${regexPattern}$`).test(url);
  } catch {
    return false;
  }
}

/**
 * Check if we're in a conversation/DM area
 */
function checkConversationArea(config: SiteConfig): { isInConversation: boolean; conversationRoot: Element | null } {
  if (!config.dmSelectors || config.dmSelectors.length === 0) {
    // If no DM selectors, consider whole page
    return { isInConversation: true, conversationRoot: document.body };
  }
  
  for (const selector of config.dmSelectors) {
    try {
      const element = document.querySelector(selector);
      if (element) {
        return { isInConversation: true, conversationRoot: element };
      }
    } catch {
      // Invalid selector, continue
    }
  }
  
  return { isInConversation: false, conversationRoot: null };
}

/**
 * Get currently detected site
 */
export function getCurrentSite(): DetectedSite | null {
  return currentSite;
}

/**
 * Set current site (called when navigation changes)
 */
export function setCurrentSite(site: DetectedSite | null): void {
  currentSite = site;
}

/**
 * Check if link scanning is enabled for current site
 */
export function isLinkScanningEnabledForCurrentSite(enabledSites: Record<SupportedSite, boolean>): boolean {
  if (!currentSite) return false;
  return enabledSites[currentSite.site] === true;
}

/**
 * Get the root element for link scanning (conversation area or body)
 */
export function getScanRoot(): Element {
  if (currentSite?.conversationRoot) {
    return currentSite.conversationRoot;
  }
  return document.body;
}

/**
 * Check if URL is a supported site (for permission requests)
 */
export function isSupportedSite(url: string): SupportedSite | null {
  for (const [key, config] of Object.entries(SUPPORTED_SITES)) {
    for (const pattern of config.hostPatterns) {
      if (matchHostPattern(url, pattern)) {
        return key as SupportedSite;
      }
    }
  }
  return null;
}

/**
 * Get all host patterns for a site (for permission requests)
 */
export function getHostPatternsForSite(site: SupportedSite): string[] {
  return SUPPORTED_SITES[site]?.hostPatterns || [];
}

/**
 * Get all host patterns for all enabled sites
 */
export function getHostPatternsForEnabledSites(enabledSites: Record<SupportedSite, boolean>): string[] {
  const patterns: string[] = [];
  for (const [site, enabled] of Object.entries(enabledSites)) {
    if (enabled) {
      patterns.push(...getHostPatternsForSite(site as SupportedSite));
    }
  }
  return patterns;
}

/**
 * Watch for site changes (SPA navigation)
 */
export function watchForSiteChanges(
  onSiteChange: (site: DetectedSite | null) => void,
  intervalMs = 1000
): () => void {
  let lastHref = window.location.href;
  let lastSiteKey: SupportedSite | null = null;
  
  const check = () => {
    if (window.location.href !== lastHref) {
      lastHref = window.location.href;
      const site = detectSite();
      const siteKey = site?.site || null;
      
      if (siteKey !== lastSiteKey) {
        lastSiteKey = siteKey;
        currentSite = site;
        onSiteChange(site);
      }
    }
  };
  
  // Initial check
  check();
  
  // Set up interval
  siteCheckTimer = setInterval(check, intervalMs);
  
  // Return cleanup function
  return () => {
    if (siteCheckTimer) {
      clearInterval(siteCheckTimer);
      siteCheckTimer = null;
    }
  };
}

/**
 * Get site display name
 */
export function getSiteDisplayName(site: SupportedSite): string {
  return SUPPORTED_SITES[site]?.name || site;
}

/**
 * Check if we should scan a specific anchor (in conversation area)
 */
export function shouldScanAnchor(anchor: HTMLAnchorElement): boolean {
  if (!currentSite?.isInConversation) return false;
  if (!currentSite?.conversationRoot) return false;
  
  // Check if anchor is within conversation root
  return currentSite.conversationRoot.contains(anchor);
}