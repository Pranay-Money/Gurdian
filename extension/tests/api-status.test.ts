import { describe, expect, it } from 'vitest';
import {
  getApiRoot,
  parseBlocklistDelta,
  parseMlHealthStatus,
} from '../src/shared/api-status';

describe('Guardian API status parsing', () => {
  it('uses the API root when settings contain the versioned API base URL', () => {
    expect(getApiRoot('http://localhost:8000/v1/')).toBe('http://localhost:8000');
  });

  it('reads model availability from the health endpoint response', () => {
    expect(parseMlHealthStatus({
      status: 'healthy',
      ml: {
        available: true,
        status: 'loaded',
        mode: 'ml_and_rules',
        model_version: 'test-version',
      },
    })).toEqual({ state: 'loaded', description: 'Model loaded' });
  });

  it('reads nested model availability from readiness responses', () => {
    expect(parseMlHealthStatus({
      status: 'ready',
      components: { ml: { available: false, status: 'model_load_failed' } },
    })).toEqual({ state: 'not-loaded', description: 'Model not loaded' });
  });

  it('keeps model state unknown when the health response does not report it', () => {
    expect(parseMlHealthStatus({ status: 'healthy' })).toEqual({
      state: 'unknown',
      description: 'Status unavailable',
    });
  });
});

describe('blocklist delta parsing', () => {
  it('parses the backend response field names without assuming a version field', () => {
    expect(parseBlocklistDelta({
      additions: [
        {
          domain_hash: 'abc123',
          reason: 'phishing',
          expires_at: '2026-10-16T00:00:00Z',
        },
      ],
      removals: ['def456'],
      timestamp: '2026-10-15T00:00:00Z',
    })).toEqual({
      additions: [
        {
          domain_hash: 'abc123',
          reason: 'phishing',
          expires_at: '2026-10-16T00:00:00Z',
        },
      ],
      removals: ['def456'],
      timestamp: '2026-10-15T00:00:00Z',
    });
  });

  it('rejects malformed blocklist entries', () => {
    expect(() => parseBlocklistDelta({
      additions: [{ h: 'abc123', r: 'phishing', exp: '2026-10-16T00:00:00Z' }],
      removals: [],
      timestamp: '2026-10-15T00:00:00Z',
    })).toThrow('Invalid blocklist addition');
  });
});
