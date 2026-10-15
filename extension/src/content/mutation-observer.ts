/**
 * Mutation Observer - Throttled observer for dynamic link detection
 * Zero impact on pages with no links
 */

import { LinkData } from '@shared/types';
import { extractVisibleText, isAnalyzableUrl, isExternalUrl, extractRegistrableDomain } from './sanitize';

interface ObserverConfig {
  throttleMs: number;
  maxLinksPerPage: number;
  onLinksFound: (links: LinkData[]) => void;
  onLinksRemoved: (anchors: HTMLAnchorElement[]) => void;
}

interface QueuedMutation {
  addedNodes: Node[];
  removedNodes: Node[];
}

export class LinkMutationObserver {
  private observer: MutationObserver | null = null;
  private config: ObserverConfig;
  private mutationQueue: QueuedMutation[] = [];
  private throttleTimer: ReturnType<typeof setTimeout> | null = null;
  private processedAnchors = new WeakSet<HTMLAnchorElement>();
  private linkCount = 0;
  private isObserving = false;
  private rootElement: Element;
  
  constructor(rootElement: Element, config: ObserverConfig) {
    this.rootElement = rootElement;
    this.config = config;
  }
  
  /**
   * Start observing
   */
  start(): void {
    if (this.isObserving) return;
    
    this.observer = new MutationObserver(this.handleMutations.bind(this));
    this.observer.observe(this.rootElement, {
      childList: true,
      subtree: true,
      attributes: false,
      characterData: false,
    });
    
    this.isObserving = true;
    
    // Initial scan
    this.scanExistingLinks();
  }
  
  /**
   * Stop observing
   */
  stop(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    if (this.throttleTimer) {
      clearTimeout(this.throttleTimer);
      this.throttleTimer = null;
    }
    this.mutationQueue = [];
    this.isObserving = false;
  }
  
  /**
   * Update configuration
   */
  updateConfig(config: Partial<ObserverConfig>): void {
    this.config = { ...this.config, ...config };
  }
  
  /**
   * Handle mutations from observer
   */
  private handleMutations(mutations: MutationRecord[]): void {
    // Quick check: any relevant mutations?
    let hasRelevantMutations = false;
    
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        // Check if any added nodes are or contain links
        for (const node of mutation.addedNodes) {
          if (this.nodeContainsLinks(node)) {
            hasRelevantMutations = true;
            break;
          }
        }
        if (hasRelevantMutations) break;
      }
    }
    
    if (!hasRelevantMutations) return;
    
    // Queue mutations for batch processing
    for (const mutation of mutations) {
      if (mutation.type === 'childList') {
        this.mutationQueue.push({
          addedNodes: Array.from(mutation.addedNodes),
          removedNodes: Array.from(mutation.removedNodes),
        });
      }
    }
    
    // Throttle processing
    this.scheduleProcessing();
  }
  
  /**
   * Check if a node is or contains an anchor with href
   */
  private nodeContainsLinks(node: Node): boolean {
    if (node.nodeType !== Node.ELEMENT_NODE) return false;
    
    const element = node as Element;
    
    // Quick check for anchor
    if (element.tagName === 'A' && element.hasAttribute('href')) {
      return true;
    }
    
    // Check descendants (but limit depth for performance)
    if (element.querySelector) {
      return element.querySelector('a[href]') !== null;
    }
    
    return false;
  }
  
  /**
   * Schedule throttled processing
   */
  private scheduleProcessing(): void {
    if (this.throttleTimer) return;
    
    this.throttleTimer = setTimeout(() => {
      this.throttleTimer = null;
      this.processQueue();
    }, this.config.throttleMs);
  }
  
  /**
   * Process queued mutations
   */
  private processQueue(): void {
    if (this.mutationQueue.length === 0) return;
    
    const addedLinks: LinkData[] = [];
    const removedAnchors: HTMLAnchorElement[] = [];
    
    // Process all queued mutations
    for (const mutation of this.mutationQueue) {
      // Process added nodes
      for (const node of mutation.addedNodes) {
        this.extractLinksFromNode(node, addedLinks);
      }
      
      // Process removed nodes
      for (const node of mutation.removedNodes) {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const element = node as Element;
          if (element.tagName === 'A') {
            removedAnchors.push(element as HTMLAnchorElement);
          } else {
            // Find anchors in removed subtree
            const anchors = element.querySelectorAll('a[href]');
            for (const anchor of anchors) {
              removedAnchors.push(anchor as HTMLAnchorElement);
            }
          }
        }
      }
    }
    
    // Clear queue
    this.mutationQueue = [];
    
    // Deduplicate added links
    const uniqueAddedLinks = this.deduplicateLinks(addedLinks);
    
    // Filter by max links per page
    const filteredLinks = uniqueAddedLinks.slice(0, this.config.maxLinksPerPage - this.linkCount);
    
    if (filteredLinks.length > 0) {
      this.linkCount += filteredLinks.length;
      this.config.onLinksFound(filteredLinks);
    }
    
    if (removedAnchors.length > 0) {
      this.config.onLinksRemoved(removedAnchors);
      this.linkCount = Math.max(0, this.linkCount - removedAnchors.length);
    }
  }
  
  /**
   * Extract links from a node and its descendants
   */
  private extractLinksFromNode(node: Node, output: LinkData[]): void {
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    
    const element = node as Element;
    const baseOrigin = window.location.origin;
    
    // Check the element itself
    if (element.tagName === 'A' && element.hasAttribute('href')) {
      this.processAnchor(element as HTMLAnchorElement, baseOrigin, output);
    }
    
    // Check descendants
    const anchors = element.querySelectorAll('a[href]');
    for (const anchor of anchors) {
      this.processAnchor(anchor as HTMLAnchorElement, baseOrigin, output);
    }
  }
  
  /**
   * Process a single anchor element
   */
  private processAnchor(anchor: HTMLAnchorElement, baseOrigin: string, output: LinkData[]): void {
    // Skip if already processed
    if (this.processedAnchors.has(anchor)) return;
    
    const href = anchor.getAttribute('href') || '';
    
    // Skip non-analyzable URLs
    if (!isAnalyzableUrl(href)) return;
    
    // Skip if not external (same-origin navigation)
    if (!isExternalUrl(href, baseOrigin)) return;
    
    // Extract visible text
    const visibleText = extractVisibleText(anchor);
    
    // Parse URL
    let host: string;
    let registrableDomain: string;
    try {
      const url = new URL(href, baseOrigin);
      host = url.hostname;
      registrableDomain = extractRegistrableDomain(host);
    } catch {
      return; // Invalid URL
    }
    
    // Mark as processed
    this.processedAnchors.add(anchor);
    
    // Add to output
    output.push({
      href,
      visibleText,
      element: anchor,
      host,
      registrableDomain,
      isExternal: true,
    });
  }
  
  /**
   * Deduplicate links by href
   */
  private deduplicateLinks(links: LinkData[]): LinkData[] {
    const seen = new Set<string>();
    const unique: LinkData[] = [];
    
    for (const link of links) {
      if (!seen.has(link.href)) {
        seen.add(link.href);
        unique.push(link);
      }
    }
    
    return unique;
  }
  
  /**
   * Scan existing links on page
   */
  private scanExistingLinks(): void {
    const anchors = this.rootElement.querySelectorAll('a[href]');
    const links: LinkData[] = [];
    const baseOrigin = window.location.origin;
    
    for (const anchor of anchors) {
      this.processAnchor(anchor as HTMLAnchorElement, baseOrigin, links);
    }
    
    if (links.length > 0) {
      this.linkCount = links.length;
      this.config.onLinksFound(links.slice(0, this.config.maxLinksPerPage));
    }
  }
  
  /**
   * Mark anchor as unprocessed (for re-analysis)
   */
  markForReprocessing(anchor: HTMLAnchorElement): void {
    this.processedAnchors.delete(anchor);
  }
  
  /**
   * Get current link count
   */
  getLinkCount(): number {
    return this.linkCount;
  }
  
  /**
   * Check if currently observing
   */
  isActive(): boolean {
    return this.isObserving;
  }
}

/**
 * Create observer for document.body with default config
 */
export function createLinkObserver(
  onLinksFound: (links: LinkData[]) => void,
  onLinksRemoved: (anchors: HTMLAnchorElement[]) => void,
  throttleMs = 100,
  maxLinksPerPage = 200
): LinkMutationObserver {
  return new LinkMutationObserver(document.body, {
    throttleMs,
    maxLinksPerPage,
    onLinksFound,
    onLinksRemoved,
  });
}