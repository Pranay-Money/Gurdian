/**
 * Badge Renderer - Renders risk badges on links using closed Shadow DOM
 * Ensures badges cannot be spoofed or styled by page CSS
 */

import { RiskLevel, Signal } from '@shared/types';
import { createBadgeElement, createTooltipElement } from './sanitize';

interface BadgeInstance {
  anchor: HTMLAnchorElement;
  shadowRoot: ShadowRoot;
  badgeElement: HTMLElement;
  tooltipElement: HTMLElement;
  level: RiskLevel;
  score: number;
  topSignal?: Signal;
}

const badgeInstances = new WeakMap<HTMLAnchorElement, BadgeInstance>();

/**
 * Get or create a closed shadow root on the anchor element
 */
function getOrCreateShadowRoot(anchor: HTMLAnchorElement): ShadowRoot {
  // Check if we already have a shadow root (closed mode prevents direct access)
  // We track instances via WeakMap instead
  let instance = badgeInstances.get(anchor);
  if (instance) {
    return instance.shadowRoot;
  }
  
  // Create closed shadow root
  const shadowRoot = anchor.attachShadow({ mode: 'closed' });
  
  // Add styles to shadow root
  const style = document.createElement('style');
  style.textContent = `
    :host {
      display: inline-flex;
      align-items: center;
      position: relative;
    }
    .guardian-badge-container {
      display: inline-flex;
      align-items: center;
      position: relative;
    }
    .guardian-tooltip {
      visibility: hidden;
      opacity: 0;
      transition: opacity 0.15s ease, visibility 0.15s ease;
    }
    .guardian-badge-container:hover .guardian-tooltip,
    .guardian-badge-container:focus-within .guardian-tooltip {
      visibility: visible;
      opacity: 1;
    }
  `;
  shadowRoot.appendChild(style);
  
  return shadowRoot;
}

/**
 * Render a badge on an anchor element
 */
export function renderBadge(
  anchor: HTMLAnchorElement,
  level: RiskLevel,
  score: number,
  topSignal?: Signal
): void {
  // Remove existing badge if present
  removeBadge(anchor);
  
  // Only render for Medium, High, Critical
  if (level === 'Low') return;
  
  const shadowRoot = getOrCreateShadowRoot(anchor);
  
  // Create container
  const container = document.createElement('div');
  container.className = 'guardian-badge-container';
  container.style.cssText = `
    display: inline-flex;
    align-items: center;
    position: relative;
    margin-left: 4px;
    vertical-align: middle;
  `;
  
  // Create badge
  const badge = createBadgeElement(level);
  badge.setAttribute('data-guardian-score', String(score));
  badge.setAttribute('data-guardian-level', level);
  
  // Create tooltip
  const tooltipText = topSignal 
    ? `${level} risk (${score}/100): ${topSignal.label}`
    : `${level} risk (${score}/100)`;
  const tooltip = createTooltipElement(tooltipText);
  tooltip.className = 'guardian-tooltip';
  
  // Assemble
  container.appendChild(badge);
  container.appendChild(tooltip);
  shadowRoot.appendChild(container);
  
  // Track instance
  badgeInstances.set(anchor, {
    anchor,
    shadowRoot,
    badgeElement: badge,
    tooltipElement: tooltip,
    level,
    score,
    topSignal,
  });
  
  // Make anchor focusable for keyboard users
  if (!anchor.hasAttribute('tabindex')) {
    anchor.setAttribute('tabindex', '0');
  }
}

/**
 * Update an existing badge
 */
export function updateBadge(
  anchor: HTMLAnchorElement,
  level: RiskLevel,
  score: number,
  topSignal?: Signal
): void {
  const instance = badgeInstances.get(anchor);
  if (!instance) {
    renderBadge(anchor, level, score, topSignal);
    return;
  }
  
  // Update badge appearance
  const colors: Record<RiskLevel, string> = {
    Low: '#16a34a',
    Medium: '#f59e0b',
    High: '#ef4444',
    Critical: '#dc2626',
  };
  
  instance.badgeElement.style.backgroundColor = colors[level];
  instance.badgeElement.setAttribute('data-guardian-score', String(score));
  instance.badgeElement.setAttribute('data-guardian-level', level);
  instance.badgeElement.setAttribute('aria-label', `Guardian: ${level} risk`);
  
  // Update pulse animation
  if (level === 'Critical') {
    instance.badgeElement.style.animation = 'guardian-pulse 1.5s ease-in-out infinite';
  } else {
    instance.badgeElement.style.animation = '';
  }
  
  // Update tooltip
  const tooltipText = topSignal 
    ? `${level} risk (${score}/100): ${topSignal.label}`
    : `${level} risk (${score}/100)`;
  instance.tooltipElement.textContent = tooltipText;
  
  // Re-add arrow
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
  instance.tooltipElement.appendChild(arrow);
  
  instance.level = level;
  instance.score = score;
  instance.topSignal = topSignal;
  
  // If downgraded to Low, remove badge
  if (level === 'Low') {
    removeBadge(anchor);
  }
}

/**
 * Remove badge from anchor
 */
export function removeBadge(anchor: HTMLAnchorElement): void {
  const instance = badgeInstances.get(anchor);
  if (instance) {
    // Clear shadow root
    instance.shadowRoot.innerHTML = '';
    badgeInstances.delete(anchor);
  }
}

/**
 * Check if anchor has a badge
 */
export function hasBadge(anchor: HTMLAnchorElement): boolean {
  return badgeInstances.has(anchor);
}

/**
 * Get badge data for anchor
 */
export function getBadgeData(anchor: HTMLAnchorElement): BadgeInstance | undefined {
  return badgeInstances.get(anchor);
}

/**
 * Clear all badges (e.g., on navigation)
 */
export function clearAllBadges(): void {
  // WeakMap automatically cleans up when anchors are GC'd
  // But we can't iterate WeakMap, so this is a no-op for now
  // Individual badges are removed when anchors are removed from DOM
}

/**
 * Get all badged anchors (for debugging)
 */
export function getAllBadgedAnchors(): HTMLAnchorElement[] {
  // Can't iterate WeakMap, would need a separate Set for tracking
  return [];
}