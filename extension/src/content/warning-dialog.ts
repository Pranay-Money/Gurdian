/**
 * Warning Dialog - Unspoofable click interception dialog using closed Shadow DOM
 * Shows before navigation on High/Critical risk links
 */

import { RiskLevel, Signal } from '@shared/types';
import { createElement, setTextContent, appendChildren, sanitizeText } from './sanitize';

interface WarningDialogInstance {
  shadowRoot: ShadowRoot;
  overlay: HTMLElement;
  dialog: HTMLElement;
  anchor: HTMLAnchorElement;
  targetUrl: string;
  onConfirm: () => void;
  onCancel: () => void;
}

const dialogInstances = new WeakMap<HTMLAnchorElement, WarningDialogInstance>();
let globalStyleInjected = false;

/**
 * Inject global styles for warning dialog (once)
 */
function injectGlobalStyles(): void {
  if (globalStyleInjected) return;
  
  const style = document.createElement('style');
  style.id = 'guardian-warning-styles';
  style.textContent = `
    /* Ensure Guardian warning dialogs are always on top */
    .guardian-warning-overlay {
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100vw !important;
      height: 100vh !important;
      z-index: 2147483647 !important;
      pointer-events: none;
    }
    .guardian-warning-dialog {
      pointer-events: auto !important;
    }
  `;
  document.head.appendChild(style);
  globalStyleInjected = true;
}

/**
 * Create the warning dialog in a closed shadow root on the anchor
 */
export function showWarningDialog(
  anchor: HTMLAnchorElement,
  targetUrl: string,
  level: RiskLevel,
  score: number,
  signals: Signal[],
  onConfirm: () => void,
  onCancel: () => void
): void {
  // Prevent multiple dialogs for same anchor
  if (dialogInstances.has(anchor)) return;
  
  injectGlobalStyles();
  
  // Create closed shadow root on anchor (or body if anchor not suitable)
  const host = anchor;
  const shadowRoot = host.attachShadow({ mode: 'closed' });
  
  // Create overlay
  const overlay = createElement('div', {
    class: 'guardian-warning-overlay',
    style: `
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      background: rgba(0, 0, 0, 0.5);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 2147483647;
      pointer-events: auto;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    `,
  });
  
  // Determine colors based on level
  const isCritical = level === 'Critical';
  const bgColor = isCritical ? '#fef2f2' : '#fffbeb';
  const borderColor = isCritical ? '#ef4444' : '#f59e0b';
  const titleColor = isCritical ? '#dc2626' : '#d97706';
  const buttonColor = isCritical ? '#dc2626' : '#d97706';
  const buttonHoverColor = isCritical ? '#b91c1c' : '#b45309';
  const iconChar = isCritical ? '🛑' : '⚠️';
  
  // Create dialog
  const dialog = createElement('div', {
    class: 'guardian-warning-dialog',
    style: `
      background: ${bgColor};
      border: 2px solid ${borderColor};
      border-radius: 12px;
      padding: 24px;
      max-width: 480px;
      width: 90%;
      max-height: 80vh;
      overflow-y: auto;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
      pointer-events: auto;
      animation: guardian-dialog-enter 0.2s ease-out;
    `,
  });
  
  // Add animation keyframes
  const style = createElement('style', {}, `
    @keyframes guardian-dialog-enter {
      from { opacity: 0; transform: scale(0.95) translateY(-10px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
    }
  `);
  shadowRoot.appendChild(style);
  
  // Build dialog content
  const iconDiv = createElement('div', {
    style: `
      font-size: 32px;
      text-align: center;
      margin-bottom: 12px;
      line-height: 1;
    `,
  });
  setTextContent(iconDiv, iconChar);
  
  const title = createElement('h2', {
    style: `
      margin: 0 0 8px;
      font-size: 20px;
      font-weight: 600;
      color: ${titleColor};
      text-align: center;
    `,
  });
  setTextContent(title, 'Guardian Security Warning');
  
  const subtitle = createElement('p', {
    style: `
      margin: 0 0 16px;
      font-size: 14px;
      color: #374151;
      text-align: center;
      line-height: 1.5;
    `,
  });
  setTextContent(subtitle, `This link was flagged as ${level} risk (${score}/100). Proceed with caution.`);
  
  // URL display
  const urlContainer = createElement('div', {
    style: `
      background: white;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
      word-break: break-all;
      font-family: ui-monospace, SFMono-Regular, monospace;
      font-size: 13px;
      color: #1f2937;
    `,
  });
  setTextContent(urlContainer, sanitizeText(targetUrl));
  
  // Top signals
  const signalsContainer = createElement('div', {
    style: `
      margin-bottom: 20px;
    `,
  });
  
  const signalsTitle = createElement('h3', {
    style: `
      margin: 0 0 10px;
      font-size: 13px;
      font-weight: 600;
      color: #374151;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    `,
  });
  setTextContent(signalsTitle, 'Why this was flagged:');
  signalsContainer.appendChild(signalsTitle);
  
  const topSignals = signals.slice(0, 3);
  for (const signal of topSignals) {
    const signalDiv = createElement('div', {
      style: `
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 6px;
        padding: 10px 12px;
        margin-bottom: 8px;
        font-size: 13px;
        color: #1f2937;
      `,
    });
    
    const signalHeader = createElement('div', {
      style: `
        display: flex;
        justify-content: space-between;
        margin-bottom: 4px;
      `,
    });
    
    const signalName = createElement('span', {
      style: 'font-weight: 500;',
    });
    setTextContent(signalName, sanitizeText(signal.label));
    
    const signalPoints = createElement('span', {
      style: `color: ${signal.points > 20 ? '#dc2626' : signal.points > 10 ? '#d97706' : '#16a34a'}; font-weight: 600;`,
    });
    setTextContent(signalPoints, `${signal.points > 0 ? '+' : ''}${signal.points} pts`);
    
    appendChildren(signalHeader, signalName, signalPoints);
    
    const signalReason = createElement('div', {
      style: 'color: #4b5563; font-size: 12px; line-height: 1.4;',
    });
    setTextContent(signalReason, sanitizeText(signal.reason));
    
    appendChildren(signalDiv, signalHeader, signalReason);
    signalsContainer.appendChild(signalDiv);
  }
  
  // Risk disclaimer
  const disclaimer = createElement('p', {
    style: `
      margin: 0 0 20px;
      font-size: 12px;
      color: #6b7280;
      line-height: 1.5;
      padding: 12px;
      background: white;
      border-radius: 6px;
      border: 1px solid #e5e7eb;
    `,
  });
  setTextContent(disclaimer, 
    'Continuing may expose you to phishing, malware, identity theft, or financial fraud. ' +
    'Only proceed if you absolutely trust this destination.'
  );
  
  // Buttons
  const buttonContainer = createElement('div', {
    style: `
      display: flex;
      gap: 12px;
      justify-content: flex-end;
    `,
  });
  
  const cancelButton = createElement('button', {
    type: 'button',
    style: `
      padding: 10px 20px;
      border: 1px solid #d1d5db;
      border-radius: 8px;
      background: white;
      color: #374151;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    `,
  });
  setTextContent(cancelButton, 'Go Back (Recommended)');
  cancelButton.addEventListener('mouseenter', () => {
    cancelButton.style.background = '#f9fafb';
    cancelButton.style.borderColor = '#9ca3af';
  });
  cancelButton.addEventListener('mouseleave', () => {
    cancelButton.style.background = 'white';
    cancelButton.style.borderColor = '#d1d5db';
  });
  cancelButton.addEventListener('click', (e) => {
    if (!e.isTrusted) return; // Ignore synthetic clicks
    cleanup();
    onCancel();
  });
  
  const confirmButton = createElement('button', {
    type: 'button',
    style: `
      padding: 10px 20px;
      border: none;
      border-radius: 8px;
      background: ${buttonColor};
      color: white;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s ease;
    `,
  });
  setTextContent(confirmButton, 'Continue Anyway');
  confirmButton.addEventListener('mouseenter', () => {
    confirmButton.style.background = buttonHoverColor;
  });
  confirmButton.addEventListener('mouseleave', () => {
    confirmButton.style.background = buttonColor;
  });
  confirmButton.addEventListener('click', (e) => {
    if (!e.isTrusted) return; // Ignore synthetic clicks
    cleanup();
    onConfirm();
  });
  
  appendChildren(buttonContainer, cancelButton, confirmButton);
  
  // Assemble dialog
  appendChildren(
    dialog,
    iconDiv,
    title,
    subtitle,
    urlContainer,
    signalsContainer,
    disclaimer,
    buttonContainer
  );
  
  // Assemble overlay
  overlay.appendChild(dialog);
  shadowRoot.appendChild(overlay);
  
  // Focus trap
  const focusableElements = dialog.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
  const firstFocusable = focusableElements[0] as HTMLElement;
  const lastFocusable = focusableElements[focusableElements.length - 1] as HTMLElement;
  
  firstFocusable?.focus();
  
  function handleTabKey(e: KeyboardEvent): void {
    if (e.key !== 'Tab') return;
    
    if (e.shiftKey) {
      if (document.activeElement === firstFocusable) {
        e.preventDefault();
        lastFocusable?.focus();
      }
    } else {
      if (document.activeElement === lastFocusable) {
        e.preventDefault();
        firstFocusable?.focus();
      }
    }
  }
  
  function handleEscapeKey(e: KeyboardEvent): void {
    if (e.key === 'Escape') {
      cleanup();
      onCancel();
    }
  }
  
  dialog.addEventListener('keydown', handleTabKey);
  dialog.addEventListener('keydown', handleEscapeKey);
  
  // Click outside to cancel
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay && e.isTrusted) {
      cleanup();
      onCancel();
    }
  });
  
  // Store instance
  const instance: WarningDialogInstance = {
    shadowRoot,
    overlay,
    dialog,
    anchor,
    targetUrl,
    onConfirm,
    onCancel,
  };
  dialogInstances.set(anchor, instance);
  
  function cleanup(): void {
    dialog.removeEventListener('keydown', handleTabKey);
    dialog.removeEventListener('keydown', handleEscapeKey);
    shadowRoot.innerHTML = '';
    dialogInstances.delete(anchor);
  }
}

/**
 * Hide warning dialog for anchor
 */
export function hideWarningDialog(anchor: HTMLAnchorElement): void {
  const instance = dialogInstances.get(anchor);
  if (instance) {
    instance.shadowRoot.innerHTML = '';
    dialogInstances.delete(anchor);
  }
}

/**
 * Check if warning dialog is shown for anchor
 */
export function isWarningDialogShown(anchor: HTMLAnchorElement): boolean {
  return dialogInstances.has(anchor);
}