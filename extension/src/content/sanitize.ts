/**
 * Sanitization utilities for content script
 * Never use innerHTML with page data - use these safe alternatives
 */

import { Signal } from '@shared/types';

// Brand keywords for mismatch detection (copied from heuristics for content script use)
export const BRAND_KEYWORDS = [
  'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
  'instagram', 'whatsapp', 'netflix', 'bank', 'chase', 'wellsfargo',
  'bankofamerica', 'citibank', 'capitalone', 'amex', 'americanexpress',
  'coinbase', 'binance', 'blockchain', 'metamask', 'wallet',
  'github', 'gitlab', 'bitbucket', 'atlassian', 'jira', 'confluence',
  'slack', 'zoom', 'teams', 'webex', 'dropbox', 'box', 'drive',
  'onedrive', 'icloud', 'office365', 'outlook', 'live', 'hotmail',
  'yahoo', 'proton', 'protonmail', 'aol', 'mail', 'email',
];

/**
 * Safely set text content on an element
 */
export function setTextContent(element: Element, text: string): void {
  element.textContent = text;
}

/**
 * Safely create an element with attributes and text content
 */
export function createElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Record<string, string> = {},
  textContent?: string
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(attributes)) {
    element.setAttribute(key, value);
  }
  if (textContent !== undefined) {
    element.textContent = textContent;
  }
  return element;
}

/**
 * Safely append children to a parent
 */
export function appendChildren(parent: Element, ...children: (Node | string)[]): void {
  for (const child of children) {
    if (typeof child === 'string') {
      parent.appendChild(document.createTextNode(child));
    } else {
      parent.appendChild(child);
    }
  }
}

/**
 * Create a badge element safely (no innerHTML)
 */
export function createBadgeElement(level: 'Low' | 'Medium' | 'High' | 'Critical'): HTMLElement {
  const badge = document.createElement('span');
  badge.setAttribute('role', 'img');
  badge.setAttribute('aria-label', `Guardian: ${level} risk`);
  
  const colors: Record<string, string> = {
    Low: '#16a34a',
    Medium: '#f59e0b',
    High: '#ef4444',
    Critical: '#dc2626',
  };
  
  const color = colors[level] || '#6b7280';
  
  badge.style.cssText = `
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 12px;
    height: 12px;
    min-width: 12px;
    border-radius: 50%;
    background-color: ${color};
    margin-left: 4px;
    vertical-align: middle;
    flex-shrink: 0;
    box-shadow: 0 1px 2px rgba(0,0,0,0.2);
  `;
  
  // Add pulse animation for Critical
  if (level === 'Critical') {
    badge.style.animation = 'guardian-pulse 1.5s ease-in-out infinite';
    // Inject keyframes once
    if (!document.getElementById('guardian-keyframes')) {
      const style = document.createElement('style');
      style.id = 'guardian-keyframes';
      style.textContent = `
        @keyframes guardian-pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(220, 38, 38, 0.6); }
          50% { box-shadow: 0 0 0 6px rgba(220, 38, 38, 0); }
        }
      `;
      document.head.appendChild(style);
    }
  }
  
  return badge;
}

/**
 * Create a tooltip element safely
 */
export function createTooltipElement(text: string): HTMLElement {
  const tooltip = document.createElement('div');
  tooltip.setAttribute('role', 'tooltip');
  tooltip.style.cssText = `
    position: absolute;
    bottom: 100%;
    left: 50%;
    transform: translateX(-50%);
    margin-bottom: 4px;
    padding: 6px 10px;
    background: #1f2937;
    color: white;
    font-size: 11px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    border-radius: 4px;
    white-space: nowrap;
    z-index: 2147483647;
    pointer-events: none;
    opacity: 0;
    transition: opacity 0.15s ease;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  `;
  tooltip.textContent = text;
  
  // Arrow
  const arrow = document.createElement('div');
  arrow.style.cssText = `
    position: absolute;
    top: 100%;
    left: 50%;
    transform: translateX(-50%);
    width: 0;
    height: 0;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid #1f2937;
  `;
  tooltip.appendChild(arrow);
  
  return tooltip;
}

/**
 * Sanitize a string for safe use in textContent
 * Removes control characters except newline/tab
 */
export function sanitizeText(text: string): string {
  return text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

/**
 * Truncate text to max length with ellipsis
 */
export function truncateText(text: string, maxLength: number): string {
  const sanitized = sanitizeText(text);
  if (sanitized.length <= maxLength) return sanitized;
  return sanitized.slice(0, maxLength - 1) + '…';
}

/**
 * Extract visible text from an anchor element safely
 */
export function extractVisibleText(anchor: HTMLAnchorElement): string {
  // Clone to avoid modifying original
  const clone = anchor.cloneNode(true) as HTMLAnchorElement;
  
  // Remove nested interactive elements that shouldn't count as link text
  const toRemove = clone.querySelectorAll('img, svg, button, input, select, textarea');
  toRemove.forEach(el => el.remove());
  
  // Get text content
  let text = clone.textContent || '';
  
  // Clean up whitespace
  text = text.replace(/\s+/g, ' ').trim();
  
  return truncateText(text, 200);
}

/**
 * Check if a URL is external (different origin)
 */
export function isExternalUrl(href: string, baseOrigin: string): boolean {
  try {
    const url = new URL(href, baseOrigin);
    return url.origin !== baseOrigin;
  } catch {
    return true; // Treat unparseable as external
  }
}

/**
 * Check if URL should be analyzed (not javascript:, mailto:, etc.)
 */
export function isAnalyzableUrl(href: string): boolean {
  try {
    const url = new URL(href);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Extract registrable domain from hostname
 */
export function extractRegistrableDomain(hostname: string): string {
  const parts = hostname.toLowerCase().split('.');
  if (parts.length <= 2) return hostname.toLowerCase();
  
  const tld = parts[parts.length - 1];
  const secondLevel = parts[parts.length - 2];
  
  // Common two-part TLDs
  const twoPartTlds = new Set([
    'co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'com.mx',
    'org.uk', 'ac.uk', 'gov.uk', 'nhs.uk',
    'co.za', 'com.cn', 'net.cn', 'org.cn',
    'co.kr', 'ne.kr', 'or.kr', 'pe.kr', 'go.kr',
  ]);
  
  const maybeTwoPart = `${secondLevel}.${tld}`;
  if (twoPartTlds.has(maybeTwoPart) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return `${secondLevel}.${tld}`;
}

/**
 * Check if visible text looks like a domain/URL
 */
export function looksLikeDomain(text: string): boolean {
  const trimmed = text.trim().toLowerCase();
  // Domain-like patterns: example.com, sub.example.com, www.example.com
  return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(trimmed) && !trimmed.includes(' ');
}

/**
 * Check if visible text contains a brand but href doesn't match
 */
export function checkBrandMismatch(visibleText: string, hrefHost: string, brandKeywords: string[]): Signal | null {
  const lowerText = visibleText.toLowerCase();
  const lowerHost = hrefHost.toLowerCase();
  
  for (const brand of brandKeywords) {
    if (lowerText.includes(brand) && !lowerHost.includes(brand)) {
      return {
        key: 'display_text_mismatch',
        category: 'behavioral',
        label: 'Display text / destination mismatch',
        points: 35,
        reason: `Link text mentions "${brand}" but destination is "${hrefHost}"`,
        evidence: [
          { type: 'visible_text', value: visibleText, description: 'Visible link text' },
          { type: 'destination_host', value: hrefHost, description: 'Actual destination host' },
          { type: 'brand', value: brand, description: 'Brand mentioned in text' },
        ],
      };
    }
  }
  return null;
}

/**
 * Create a Signal object for display-text mismatch (generic)
 */
export function createMismatchSignal(visibleText: string, href: string, hrefHost: string): Signal {
  return {
    key: 'display_text_mismatch',
    category: 'behavioral',
    label: 'Display text / destination mismatch',
    points: 25,
    reason: `Link text "${truncateText(visibleText, 50)}" does not match destination "${hrefHost}"`,
    evidence: [
      { type: 'visible_text', value: visibleText, description: 'Visible link text' },
      { type: 'destination_url', value: href, description: 'Actual destination URL' },
      { type: 'destination_host', value: hrefHost, description: 'Actual destination host' },
    ],
  };
}