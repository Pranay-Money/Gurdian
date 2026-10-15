import { useState, useEffect, useCallback, useRef } from 'react';
import { openDB, DBSchema, IDBPDatabase } from 'idb';
import { Signal, RiskLevel, ActionType, URLAnalysis, ChannelType } from '@shared/types';

export interface HistoryEntry {
  id?: number;
  timestamp: number;
  url: string;
  host: string;
  registrableDomain: string;
  score: number;
  level: RiskLevel;
  action: ActionType;
  signals: Signal[];
  urlAnalysis?: URLAnalysis[];
  explanation: string;
  source: 'allowlist' | 'blocklist' | 'heuristics' | 'api' | 'fail-open';
  latencyMs: number;
  privacyMode: 'standard' | 'strict';
  channel: ChannelType;
  sender?: string;
  text?: string;
}

interface GuardianHistoryDB extends DBSchema {
  decisions: {
    key: number;
    value: HistoryEntry;
    indexes: {
      'by-timestamp': number;
      'by-host': string;
      'by-domain': string;
      'by-level': string;
      'by-source': string;
      'by-channel': string;
    };
  };
  metadata: {
    key: string;
    value: { key: string; value: unknown };
  };
}

const DB_NAME = 'GuardianHistory';
const DB_VERSION = 1;
const STORE_NAME = 'decisions';
const MAX_ENTRIES = 10000;

let dbPromise: Promise<IDBPDatabase<GuardianHistoryDB>> | null = null;

function getDB(): Promise<IDBPDatabase<GuardianHistoryDB>> {
  if (!dbPromise) {
    dbPromise = openDB<GuardianHistoryDB>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        const store = db.createObjectStore(STORE_NAME, {
          keyPath: 'id',
          autoIncrement: true,
        });
        store.createIndex('by-timestamp', 'timestamp');
        store.createIndex('by-host', 'host');
        store.createIndex('by-domain', 'registrableDomain');
        store.createIndex('by-level', 'level');
        store.createIndex('by-source', 'source');
        store.createIndex('by-channel', 'channel');
      },
    });
  }
  return dbPromise;
}

interface HistoryFilters {
  query?: string;
  level?: RiskLevel;
  source?: HistoryEntry['source'];
  channel?: ChannelType;
  domain?: string;
  from?: number;
  to?: number;
  limit?: number;
  offset?: number;
}

interface HistoryStats {
  total: number;
  byLevel: Record<RiskLevel, number>;
  bySource: Record<HistoryEntry['source'], number>;
  byChannel: Record<ChannelType, number>;
  avgScore: number;
  todayCount: number;
  thisWeekCount: number;
}

export function useHistory() {
  const [entries, setEntries] = useState<HistoryEntry[]>([]);
  const [stats, setStats] = useState<HistoryStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const loadEntries = useCallback(async (filters: HistoryFilters = {}) => {
    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();

    setLoading(true);
    setError(null);

    try {
      const db = await getDB();
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);

      let results: HistoryEntry[] = [];

      if (filters.query) {
        // Full-text-like search - we need to scan all entries
        const allEntries = await store.getAll();
        const query = filters.query.toLowerCase();
        results = allEntries.filter(entry =>
          entry.url.toLowerCase().includes(query) ||
          entry.host.toLowerCase().includes(query) ||
          entry.registrableDomain.toLowerCase().includes(query) ||
          entry.sender?.toLowerCase().includes(query) ||
          entry.text?.toLowerCase().includes(query) ||
          entry.signals.some(s => s.label.toLowerCase().includes(query) || s.reason.toLowerCase().includes(query))
        );
        // Sort by timestamp descending
        results.sort((a, b) => b.timestamp - a.timestamp);
      } else {
        // Use index for better performance
        const index = store.index('by-timestamp');
        let cursor = await index.openCursor(null, 'prev');
        const limit = filters.limit || 100;
        const offset = filters.offset || 0;
        let count = 0;

        while (cursor && results.length < limit) {
          if (count >= offset) {
            const entry = cursor.value;
            let match = true;

            if (filters.level && entry.level !== filters.level) match = false;
            if (filters.source && entry.source !== filters.source) match = false;
            if (filters.channel && entry.channel !== filters.channel) match = false;
            if (filters.domain && entry.registrableDomain !== filters.domain) match = false;
            if (filters.from && entry.timestamp < filters.from) match = false;
            if (filters.to && entry.timestamp > filters.to) match = false;

            if (match) results.push(entry);
          }
          count++;
          cursor = await cursor.continue();
        }
      }

      setEntries(results);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load history');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadStats = useCallback(async () => {
    try {
      const db = await getDB();
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);

      const allEntries = await store.getAll();
      const now = Date.now();
      const todayStart = new Date(now).setHours(0, 0, 0, 0);
      const weekStart = todayStart - 7 * 24 * 60 * 60 * 1000;

      const byLevel: Record<RiskLevel, number> = { Low: 0, Medium: 0, High: 0, Critical: 0 };
      const bySource: Record<HistoryEntry['source'], number> = { allowlist: 0, blocklist: 0, heuristics: 0, api: 0, 'fail-open': 0 };
      const byChannel: Record<ChannelType, number> = { email: 0, sms: 0, social: 0, url: 0 };
      let totalScore = 0;
      let todayCount = 0;
      let thisWeekCount = 0;

      for (const entry of allEntries) {
        byLevel[entry.level]++;
        bySource[entry.source]++;
        byChannel[entry.channel]++;
        totalScore += entry.score;

        if (entry.timestamp >= todayStart) todayCount++;
        if (entry.timestamp >= weekStart) thisWeekCount++;
      }

      setStats({
        total: allEntries.length,
        byLevel,
        bySource,
        byChannel,
        avgScore: allEntries.length > 0 ? Math.round(totalScore / allEntries.length) : 0,
        todayCount,
        thisWeekCount,
      });
    } catch (err) {
      console.error('Failed to load stats:', err);
    }
  }, []);

  const addEntry = useCallback(async (entry: Omit<HistoryEntry, 'id'>): Promise<number> => {
    const db = await getDB();
    const id = await db.add(STORE_NAME, entry as HistoryEntry);

    // Enforce max entries
    const count = await db.count(STORE_NAME);
    if (count > MAX_ENTRIES) {
      const excess = count - MAX_ENTRIES;
      const oldEntries = await db.getAllFromIndex(STORE_NAME, 'by-timestamp', undefined, excess);
      for (const old of oldEntries) {
        await db.delete(STORE_NAME, old.id!);
      }
    }

    // Refresh
    await loadEntries({});
    await loadStats();
    return id;
  }, [loadEntries, loadStats]);

  const clearHistory = useCallback(async (olderThan?: number): Promise<number> => {
    const db = await getDB();
    let deleted = 0;

    if (olderThan) {
      let cursor = await db.transaction(STORE_NAME, 'readwrite')
        .store.index('by-timestamp')
        .openCursor(IDBKeyRange.upperBound(olderThan, true));

      while (cursor) {
        await cursor.delete();
        deleted++;
        cursor = await cursor.continue();
      }
    } else {
      await db.clear(STORE_NAME);
      deleted = await db.count(STORE_NAME);
    }

    await loadEntries({});
    await loadStats();
    return deleted;
  }, [loadEntries, loadStats]);

  const exportHistory = useCallback(async (): Promise<HistoryEntry[]> => {
    const db = await getDB();
    return db.getAll(STORE_NAME);
  }, []);

  const importHistory = useCallback(async (entries: HistoryEntry[]): Promise<number> => {
    const db = await getDB();
    const tx = db.transaction(STORE_NAME, 'readwrite');
    let count = 0;
    for (const entry of entries) {
      await tx.store.add(entry);
      count++;
    }
    await tx.done;
    await loadEntries({});
    await loadStats();
    return count;
  }, [loadEntries, loadStats]);

  useEffect(() => {
    loadEntries({});
    loadStats();
    return () => {
      if (abortRef.current) abortRef.current.abort();
    };
  }, []);

  return {
    entries,
    stats,
    loading,
    error,
    loadEntries,
    loadStats,
    addEntry,
    clearHistory,
    exportHistory,
    importHistory,
  };
}