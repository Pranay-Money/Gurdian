/**
 * Content Script Entry Point
 * Initializes link analyzer for opt-in sites
 */

import browser from 'webextension-polyfill';
import { ExtendedDeviceSettings } from '@shared/types';
import { initializeLinkAnalyzer, cleanup, handleMessage } from './link-analyzer';

// Skip on blocked page
if (window.location.href.includes(browser.runtime.getURL('blocked.html'))) {
  // Still allow messages for blocked page
} else {
  // Initialize when settings are available
  browser.storage.local.get('settings').then(({ settings }) => {
    const extendedSettings = settings as ExtendedDeviceSettings;
    if (extendedSettings) {
      initializeLinkAnalyzer(extendedSettings);
    }
  });
}

// Message listener
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender, sendResponse);
  return true; // Always return true to support async sendResponse
});

// Cleanup on unload
window.addEventListener('beforeunload', () => {
  cleanup();
});

// Also listen for pagehide (bfcache)
window.addEventListener('pagehide', () => {
  cleanup();
});

export {};