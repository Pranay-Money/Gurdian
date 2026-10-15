// Test setup file for vitest
import { vi } from 'vitest';

// Mock Chrome APIs
const mockChrome = {
  runtime: {
    getURL: vi.fn((path) => `chrome-extension://test-id/${path}`),
    sendMessage: vi.fn(),
    onMessage: { addListener: vi.fn() },
    onInstalled: { addListener: vi.fn() },
    onStartup: { addListener: vi.fn() },
  },
  storage: {
    local: { get: vi.fn(), set: vi.fn() },
    session: { get: vi.fn(), set: vi.fn() },
  },
  webNavigation: {
    onBeforeNavigate: { addListener: vi.fn() },
    onCommitted: { addListener: vi.fn() },
  },
  declarativeNetRequest: {
    updateDynamicRules: vi.fn(),
    getDynamicRules: vi.fn(),
  },
  tabs: {
    update: vi.fn(),
    query: vi.fn(),
    create: vi.fn(),
  },
  alarms: {
    create: vi.fn(),
    onAlarm: { addListener: vi.fn() },
  },
  scripting: {
    executeScript: vi.fn(),
  },
};

vi.stubGlobal('chrome', mockChrome);
vi.stubGlobal('browser', mockChrome);

// Mock ResizeObserver (used by some components)
global.ResizeObserver = vi.fn().mockImplementation(() => ({
  observe: vi.fn(),
  unobserve: vi.fn(),
  disconnect: vi.fn(),
}));

// Mock matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
});