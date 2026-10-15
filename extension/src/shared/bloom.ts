/**
 * Bloom Filter implementation for Tranco top-N allowlist.
 * Uses a bit array with multiple hash functions for space-efficient membership testing.
 * False positives possible (safe - may allow a domain that's not in top-N).
 * False negatives impossible (never blocks a domain that IS in top-N).
 */

export interface BloomFilterConfig {
  /** Number of bits in the filter */
  size: number;
  /** Number of hash functions */
  hashCount: number;
  /** Bit array as base64 string */
  bits: string;
  /** Expected number of items (for info) */
  itemCount: number;
  /** False positive probability (approx) */
  falsePositiveRate: number;
}

export class BloomFilter {
  private bits: Uint8Array;
  private readonly size: number;
  private readonly hashCount: number;

  constructor(config: BloomFilterConfig) {
    this.size = config.size;
    this.hashCount = config.hashCount;
    // Decode base64 bit array
    const binary = atob(config.bits);
    this.bits = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      this.bits[i] = binary.charCodeAt(i);
    }
  }

  /**
   * Check if a domain might be in the allowlist.
   * Returns true if domain is likely in top-N (allow).
   * Returns false if domain is definitely NOT in top-N (needs further checks).
   */
  test(domain: string): boolean {
    const normalized = this.normalizeDomain(domain);
    const hashes = this.getHashes(normalized);

    for (const hash of hashes) {
      const byteIndex = Math.floor(hash / 8);
      const bitIndex = hash % 8;
      if (!(this.bits[byteIndex] & (1 << bitIndex))) {
        return false; // Definitely not in set
      }
    }
    return true; // Probably in set
  }

  /**
   * Normalize domain: lowercase, remove www., get registrable domain
   */
  private normalizeDomain(domain: string): string {
    let d = domain.toLowerCase().trim();
    // Remove protocol if present
    d = d.replace(/^https?:\/\//, '');
    // Remove path, query, fragment
    d = d.split('/')[0].split('?')[0].split('#')[0];
    // Remove port
    d = d.split(':')[0];
    // Remove www. prefix
    d = d.replace(/^www\./, '');
    return d;
  }

  /**
   * Generate k hash values for a string using FNV-1a with different seeds
   */
  private getHashes(str: string): number[] {
    const hashes: number[] = [];
    for (let i = 0; i < this.hashCount; i++) {
      let hash = 0x811c9dc5 ^ (i + 1); // FNV offset basis + seed
      for (let j = 0; j < str.length; j++) {
        hash ^= str.charCodeAt(j);
        hash = Math.imul(hash, 0x01000193); // FNV prime
      }
      hashes.push(hash >>> 0 % this.size);
    }
    return hashes;
  }

  /**
   * Get filter statistics
   */
  getStats(): { size: number; hashCount: number; bitDensity: number } {
    let setBits = 0;
    for (const byte of this.bits) {
      setBits += byte & 1;
      setBits += (byte >> 1) & 1;
      setBits += (byte >> 2) & 1;
      setBits += (byte >> 3) & 1;
      setBits += (byte >> 4) & 1;
      setBits += (byte >> 5) & 1;
      setBits += (byte >> 6) & 1;
      setBits += (byte >> 7) & 1;
    }
    return {
      size: this.size,
      hashCount: this.hashCount,
      bitDensity: setBits / this.size,
    };
  }
}

/**
 * Create a Bloom filter from a list of domains.
 * Utility for generating the static filter at build time.
 */
export function createBloomFilter(domains: string[], falsePositiveRate = 0.01): BloomFilterConfig {
  const n = domains.length;
  // Optimal size: m = -n * ln(p) / (ln(2)^2)
  const size = Math.ceil((-n * Math.log(falsePositiveRate)) / (Math.LN2 * Math.LN2));
  // Optimal hash count: k = (m/n) * ln(2)
  const hashCount = Math.max(1, Math.round((size / n) * Math.LN2));

  // Round size to multiple of 8 for byte alignment
  const byteSize = Math.ceil(size / 8) * 8;
  const bits = new Uint8Array(byteSize / 8);

  for (const domain of domains) {
    const normalized = normalizeDomain(domain);
    const hashes = getHashes(normalized, hashCount, byteSize);
    for (const hash of hashes) {
      const byteIndex = Math.floor(hash / 8);
      const bitIndex = hash % 8;
      bits[byteIndex] |= 1 << bitIndex;
    }
  }

  // Encode as base64
  let binary = '';
  for (const byte of bits) {
    binary += String.fromCharCode(byte);
  }
  const bitsBase64 = btoa(binary);

  return {
    size: byteSize,
    hashCount,
    bits: bitsBase64,
    itemCount: n,
    falsePositiveRate,
  };
}

function normalizeDomain(domain: string): string {
  let d = domain.toLowerCase().trim();
  d = d.replace(/^https?:\/\//, '');
  d = d.split('/')[0].split('?')[0].split('#')[0];
  d = d.split(':')[0];
  d = d.replace(/^www\./, '');
  return d;
}

function getHashes(str: string, hashCount: number, size: number): number[] {
  const hashes: number[] = [];
  for (let i = 0; i < hashCount; i++) {
    let hash = 0x811c9dc5 ^ (i + 1);
    for (let j = 0; j < str.length; j++) {
      hash ^= str.charCodeAt(j);
      hash = Math.imul(hash, 0x01000193);
    }
    hashes.push(hash >>> 0 % size);
  }
  return hashes;
}

import { trancoBloomConfig } from './tranco-bloom';

/**
 * Load the pre-built Tranco top-100K Bloom filter from generated config.
 * The config is generated at build time by `npm run generate:bloom`.
 */
export async function loadTrancoBloomFilter(): Promise<BloomFilter> {
  return new BloomFilter(trancoBloomConfig);
}