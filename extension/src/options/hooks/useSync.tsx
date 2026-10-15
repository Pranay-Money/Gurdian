import { useState, useEffect, useCallback } from 'react';
import browser from 'webextension-polyfill';
import { CaseSummary, StatsResponse, DeviceSettings } from '@shared/types';

interface SyncState {
  enabled: boolean;
  status: 'idle' | 'syncing' | 'success' | 'error';
  lastSync: number | null;
  error: string | null;
  deviceToken: string | null;
}

const SYNC_INTERVAL = 5 * 60 * 1000; // 5 minutes

export function useSync() {
  const [state, setState] = useState<SyncState>({
    enabled: false,
    status: 'idle',
    lastSync: null,
    error: null,
    deviceToken: null,
  });

  const loadSyncState = useCallback(async () => {
    const result = await browser.storage.local.get([
      'syncEnabled',
      'deviceToken',
      'lastSync',
      'settings',
    ]);
    setState(prev => ({
      ...prev,
      enabled: result.syncEnabled || false,
      deviceToken: result.deviceToken || null,
      lastSync: result.lastSync || null,
    }));
  }, []);

  const registerDevice = useCallback(async (apiBaseUrl: string): Promise<string> => {
    try {
      const response = await fetch(`${apiBaseUrl}/devices/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ platform: 'chrome' }),
      });
      if (!response.ok) throw new Error('Registration failed');
      const data = await response.json() as { device_token: string; expires_at: string };
      await browser.storage.local.set({ deviceToken: data.device_token });
      setState(prev => ({ ...prev, deviceToken: data.device_token }));
      return data.device_token;
    } catch (err) {
      throw new Error(err instanceof Error ? err.message : 'Device registration failed');
    }
  }, []);

  const syncCases = useCallback(async (apiBaseUrl: string, deviceToken: string): Promise<{ synced: number; stats?: StatsResponse }> => {
    setState(prev => ({ ...prev, status: 'syncing', error: null }));

    try {
      // Get local cases since last sync
      const lastSync = state.lastSync || 0;
      const response = await fetch(`${apiBaseUrl}/cases?since=${lastSync}&limit=1000`, {
        headers: { 'Authorization': `Bearer ${deviceToken}` },
      });

      if (!response.ok) {
        if (response.status === 401) {
          // Token expired, re-register
          const newToken = await registerDevice(apiBaseUrl);
          return syncCases(apiBaseUrl, newToken);
        }
        throw new Error(`Sync failed: ${response.status}`);
      }

      const data = await response.json() as { cases: CaseSummary[]; stats?: StatsResponse };
      const timestamp = Date.now();

      await browser.storage.local.set({ lastSync: timestamp });
      setState(prev => ({
        ...prev,
        status: 'success',
        lastSync: timestamp,
        error: null,
      }));

      return { synced: data.cases.length, stats: data.stats };
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Sync failed';
      setState(prev => ({ ...prev, status: 'error', error: errorMsg }));
      throw err;
    }
  }, [state.lastSync, registerDevice]);

  const syncStats = useCallback(async (apiBaseUrl: string, deviceToken: string): Promise<StatsResponse | null> => {
    try {
      const response = await fetch(`${apiBaseUrl}/stats`, {
        headers: { 'Authorization': `Bearer ${deviceToken}` },
      });
      if (!response.ok) throw new Error('Stats sync failed');
      return response.json() as Promise<StatsResponse>;
    } catch {
      return null;
    }
  }, []);

  const startSync = useCallback(async (settings: DeviceSettings) => {
    if (!state.enabled) return;

    try {
      let token = state.deviceToken;
      if (!token) {
        token = await registerDevice(settings.apiBaseUrl);
      }

      await syncCases(settings.apiBaseUrl, token);
      await syncStats(settings.apiBaseUrl, token);
    } catch (err) {
      console.error('Sync failed:', err);
    }
  }, [state.enabled, state.deviceToken, registerDevice, syncCases, syncStats]);

  const toggleSync = useCallback(async (enabled: boolean, settings: DeviceSettings) => {
    await browser.storage.local.set({ syncEnabled: enabled });
    setState(prev => ({ ...prev, enabled }));

    if (enabled) {
      await startSync(settings);
    }
  }, [startSync]);

  useEffect(() => {
    loadSyncState();
  }, [loadSyncState]);

  // Periodic sync
  useEffect(() => {
    if (!state.enabled) return;

    const interval = setInterval(async () => {
      const result = await browser.storage.local.get('settings');
      const settings = result.settings as DeviceSettings;
      if (settings) await startSync(settings);
    }, SYNC_INTERVAL);

    return () => clearInterval(interval);
  }, [state.enabled, startSync]);

  return {
    ...state,
    toggleSync,
    syncNow: startSync,
    registerDevice,
  };
}