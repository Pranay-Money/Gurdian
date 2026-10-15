import type { BlocklistDeltaResponse } from './types';

export type MlHealthState = 'loaded' | 'not-loaded' | 'unknown';

export interface MlHealthStatus {
  state: MlHealthState;
  description: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

export function getApiRoot(apiBaseUrl: string): string {
  return apiBaseUrl.replace(/\/v1\/?$/, '').replace(/\/+$/, '');
}

export function parseMlHealthStatus(payload: unknown): MlHealthStatus {
  if (!isRecord(payload)) {
    return { state: 'unknown', description: 'Status unavailable' };
  }

  const components = isRecord(payload.components) ? payload.components : undefined;
  const ml = isRecord(payload.ml)
    ? payload.ml
    : components && isRecord(components.ml)
      ? components.ml
      : undefined;

  if (typeof ml?.available === 'boolean') {
    return ml.available
      ? { state: 'loaded', description: 'Model loaded' }
      : { state: 'not-loaded', description: 'Model not loaded' };
  }

  if (ml?.status === 'loaded') {
    return { state: 'loaded', description: 'Model loaded' };
  }

  if (ml?.status === 'model_not_found' || ml?.status === 'model_load_failed') {
    return { state: 'not-loaded', description: 'Model not loaded' };
  }

  return { state: 'unknown', description: 'Status unavailable' };
}

export function parseBlocklistDelta(payload: unknown): BlocklistDeltaResponse {
  if (!isRecord(payload)
    || !Array.isArray(payload.additions)
    || !Array.isArray(payload.removals)
    || typeof payload.timestamp !== 'string') {
    throw new Error('Invalid blocklist delta response');
  }

  const rawAdditions: unknown[] = payload.additions;
  const additions = rawAdditions.map((entry) => {
    if (!isRecord(entry)
      || typeof entry.domain_hash !== 'string'
      || typeof entry.reason !== 'string'
      || typeof entry.expires_at !== 'string') {
      throw new Error('Invalid blocklist addition');
    }

    return {
      domain_hash: entry.domain_hash,
      reason: entry.reason,
      expires_at: entry.expires_at,
    };
  });

  const rawRemovals: unknown[] = payload.removals;
  const removals: string[] = [];
  for (const domainHash of rawRemovals) {
    if (typeof domainHash !== 'string') {
      throw new Error('Invalid blocklist removal');
    }
    removals.push(domainHash);
  }

  return {
    additions,
    removals,
    timestamp: payload.timestamp,
  };
}
