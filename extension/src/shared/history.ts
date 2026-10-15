/**
 * IndexedDB wrapper for local history storage.
 * Stores every decision with its explanation for the local dashboard.
 */

import { Signal, URLAnalysis, RiskLevel, ActionType } from './types';

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
}

const DB_NAME = 'GuardianHistory';
const DB_VERSION = 1;
const STORE_NAME = 'decisions';
const MAX_ENTRIES = 10000;
const DEFAULT_RETENTION_DAYS = 30;

let dbPromise: Promise<IDBDatabase> | null = null;

function getDB(): Promise<IDBDatabase> {
  if (!dbPromise) {
    dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result);
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, {
            keyPath: 'id',
            autoIncrement: true,
          });
          store.createIndex('timestamp', 'timestamp', { unique: false });
          store.createIndex('host', 'host', { unique: false });
          store.createIndex('registrableDomain', 'registrableDomain', { unique: false });
          store.createIndex('level', 'level', { unique: false });
          store.createIndex('source', 'source', { unique: false });
        }
      };
    });
  }
  return dbPromise;
}

export async function addHistoryEntry(entry: Omit<HistoryEntry, 'id'>): Promise<number> {
  const db = await getDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const request = store.add(entry);
    request.onsuccess = () => resolve(request.result as number);
    request.onerror = () => reject(request.error);
  });
}

export async function getHistoryEntries(options?: {
  limit?: number;
  offset?: number;
  host?: string;
  level?: RiskLevel;
  source?: HistoryEntry['source'];
  from?: number;
  to?: number;
}): Promise<HistoryEntry[]> {
  const db = await getDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const index = store.index('timestamp');
    const direction = 'prev'; // Newest first

    let request: IDBRequest<IDBCursorWithValue>;
    if (options?.from || options?.to) {
      const range = IDBKeyRange.bound(
        options.from || 0,
        options.to || Infinity,
        false,
        false
      );
      request = index.openCursor(range, direction);
    } else {
      request = index.openCursor(null, direction);
    }

    const results: HistoryEntry[] = [];
    let count = 0;
    const limit = options?.limit || 100;
    const offset = options?.offset || 0;

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
      if (cursor) {
        if (count >= offset) {
          const entry = cursor.value as HistoryEntry;
          // Apply filters
          if (options?.host && entry.host !== options.host) {
            cursor.continue();
            return;
          }
          if (options?.level && entry.level !== options.level) {
            cursor.continue();
            return;
          }
          if (options?.source && entry.source !== options.source) {
            cursor.continue();
            return;
          }
          results.push(entry);
          if (results.length >= limit) {
            resolve(results);
            return;
          }
        }
        count++;
        cursor.continue();
      } else {
        resolve(results);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

export async function getHistoryStats(): Promise<{
  total: number;
  byLevel: Record<RiskLevel, number>;
  bySource: Record<HistoryEntry['source'], number>;
  todayCount: number;
}> {
  const db = await getDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const countRequest = store.count();
    countRequest.onsuccess = () => {
      const total = countRequest.result;
      // For detailed stats, we'd need to iterate
      // For now return basic info
      resolve({
        total,
        byLevel: { Low: 0, Medium: 0, High: 0, Critical: 0 },
        bySource: { allowlist: 0, blocklist: 0, heuristics: 0, api: 0, 'fail-open': 0 },
        todayCount: 0,
      });
    };
    countRequest.onerror = () => reject(countRequest.error);
  });
}

export async function clearHistory(olderThan?: number): Promise<number> {
  const db = await getDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    const index = store.index('timestamp');

    let range: IDBKeyRange | undefined;
    if (olderThan) {
      range = IDBKeyRange.upperBound(olderThan, true);
    }

    const request = range ? index.openCursor(range) : store.openCursor();
    let deleted = 0;

    request.onsuccess = (event) => {
      const cursor = (event.target as IDBRequest<IDBCursorWithValue>).result;
      if (cursor) {
        cursor.delete();
        deleted++;
        cursor.continue();
      } else {
        resolve(deleted);
      }
    };
    request.onerror = () => reject(request.error);
  });
}

export async function exportHistory(): Promise<HistoryEntry[]> {
  return getHistoryEntries({ limit: MAX_ENTRIES });
}

export function setRetentionDays(days: number): void {
  // Store in localStorage for background script to use
  localStorage.setItem('guardian:retentionDays', String(days));
}

export function getRetentionDays(): number {
  const stored = localStorage.getItem('guardian:retentionDays');
  return stored ? parseInt(stored, 10) : DEFAULT_RETENTION_DAYS;
}

/**
 * Run retention cleanup - call periodically from background
 */
export async function runRetentionCleanup(): Promise<number> {
  const days = getRetentionDays();
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  return clearHistory(cutoff);
}