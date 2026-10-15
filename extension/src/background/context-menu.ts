/**
 * Context Menu Handler
 * Creates "Analyze selected text with Guardian" context menu item
 */

import browser from 'webextension-polyfill';
import { BackgroundService } from './index';

export class ContextMenuHandler {
  private background: BackgroundService;
  private menuId = 'guardian-analyze-text';
  
  constructor(background: BackgroundService) {
    this.background = background;
  }
  
  async initialize(): Promise<void> {
    // Remove existing menu if any
    await this.removeMenu();
    
    // Create context menu
    await browser.contextMenus.create({
      id: this.menuId,
      title: 'Analyze selected text with Guardian',
      contexts: ['selection'],
      documentUrlPatterns: ['http://*/*', 'https://*/*'],
    });
    
    // Add click listener
    browser.contextMenus.onClicked.addListener(this.onClick.bind(this));
  }
  
  private async removeMenu(): Promise<void> {
    try {
      await browser.contextMenus.remove(this.menuId);
    } catch {
      // Ignore if doesn't exist
    }
  }
  
  private async onClick(info: browser.ContextMenus.OnClickData, tab?: browser.Tabs.Tab): Promise<void> {
    if (info.menuItemId !== this.menuId) return;
    if (!info.selectionText) return;
    if (!tab?.id) return;
    
    const selectedText = info.selectionText.trim();
    if (!selectedText) return;
    
    // Open analyze popup with selected text
    const popupUrl = browser.runtime.getURL('analyze-popup.html') + 
      `?text=${encodeURIComponent(selectedText)}` +
      `&tabId=${tab.id}`;
    
    // Open as popup window
    await browser.windows.create({
      url: popupUrl,
      type: 'popup',
      width: 480,
      height: 600,
      focused: true,
    });
  }
  
  async updateMenuVisibility(enabled: boolean): Promise<void> {
    if (enabled) {
      await this.initialize();
    } else {
      await this.removeMenu();
    }
  }
}

let contextMenuInstance: ContextMenuHandler | null = null;

export async function initializeContextMenu(): Promise<void> {
  // This will be called from background service init
  // The actual instance is created there
}

export function getContextMenuHandler(): ContextMenuHandler | null {
  return contextMenuInstance;
}

export function setContextMenuHandler(handler: ContextMenuHandler): void {
  contextMenuInstance = handler;
}