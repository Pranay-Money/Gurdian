import { useState, useEffect, useCallback } from 'react';
import browser from 'webextension-polyfill';
import { ExtendedDeviceSettings, SupportedSite, DEFAULT_EXTENDED_SETTINGS, RiskLevel } from '@shared/types';

export function useSettings() {
  const [settings, setSettingsState] = useState<ExtendedDeviceSettings>(DEFAULT_EXTENDED_SETTINGS);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = useCallback(async () => {
    setLoading(true);
    try {
      const result = await browser.storage.local.get(['settings', 'syncEnabled']);
      const stored = result.settings || {};
      const syncEnabled = result.syncEnabled || false;
      setSettings(prev => ({ ...prev, ...stored, syncEnabled }));
    } catch (err) {
      console.error('Failed to load settings:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const updateSetting = useCallback(async <K extends keyof ExtendedDeviceSettings>(
    key: K,
    value: ExtendedDeviceSettings[K]
  ) => {
    const newSettings = { ...settings, [key]: value };
    setSettingsState(newSettings);
    await browser.storage.local.set({ settings: newSettings });
  }, [settings]);

  const updateMultipleSettings = useCallback(async (
    updates: Partial<ExtendedDeviceSettings>
  ) => {
    const newSettings = { ...settings, ...updates };
    setSettingsState(newSettings);
    await browser.storage.local.set({ settings: newSettings });
  }, [settings]);

  const resetSettings = useCallback(async () => {
    setSettingsState(DEFAULT_EXTENDED_SETTINGS);
    await browser.storage.local.set({ settings: DEFAULT_EXTENDED_SETTINGS });
  }, []);

  const exportSettings = useCallback(() => {
    const data = JSON.stringify(settings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `guardian-settings-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [settings]);

  const importSettings = useCallback(async (file: File): Promise<boolean> => {
    try {
      const text = await file.text();
      const imported = JSON.parse(text) as Partial<ExtendedDeviceSettings>;
      const merged = { ...DEFAULT_EXTENDED_SETTINGS, ...settings, ...imported };
      setSettingsState(merged);
      await browser.storage.local.set({ settings: merged });
      return true;
    } catch {
      return false;
    }
  }, [settings]);

  const deleteAllData = useCallback(async () => {
    await browser.storage.local.clear();
    setSettingsState(DEFAULT_EXTENDED_SETTINGS);
  }, []);

  return {
    settings,
    loading,
    updateSetting,
    updateMultipleSettings,
    resetSettings,
    exportSettings,
    importSettings,
    deleteAllData,
    refresh: loadSettings,
  };
}

// Helper for risk level colors
export const RISK_LEVEL_COLORS: Record<RiskLevel, string> = {
  Low: '#10b981',      // emerald-500
  Medium: '#f59e0b',   // amber-500
  High: '#ef4444',     // red-500
  Critical: '#7c2d12', // orange-900
};

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  Low: 'Low',
  Medium: 'Medium',
  High: 'High',
  Critical: 'Critical',
};

export const CHANNEL_LABELS: Record<string, string> = {
  email: 'Email',
  sms: 'SMS',
  social: 'Social',
  url: 'Direct URL',
};

export const SOURCE_LABELS: Record<string, string> = {
  allowlist: 'Allowlist',
  blocklist: 'Blocklist',
  heuristics: 'Heuristics',
  api: 'API',
  'fail-open': 'Fail-open',
};

export function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleString();
}

export function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;

  if (diff < 60 * 1000) return 'Just now';
  if (diff < 60 * 60 * 1000) return `${Math.floor(diff / (60 * 1000))}m ago`;
  if (diff < 24 * 60 * 60 * 1000) return `${Math.floor(diff / (60 * 60 * 1000))}h ago`;
  if (diff < 7 * 24 * 60 * 60 * 1000) return `${Math.floor(diff / (24 * 60 * 60 * 1000))}d ago`;

  return formatTimestamp(timestamp);
}

export function truncateUrl(url: string, maxLength = 50): string {
  if (url.length <= maxLength) return url;
  return url.slice(0, maxLength - 3) + '...';
}