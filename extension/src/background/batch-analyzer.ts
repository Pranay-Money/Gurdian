/**
 * Batch Domain Analyzer
 * Analyzes multiple domains in batches via backend API
 */

import { DomainAnalysis, RiskLevel, Signal, SignalCategory, EvidenceItem } from '@shared/types';
import { runHeuristics } from '@shared/heuristics';

export class BatchAnalyzer {
  private cache = new Map<string, DomainAnalysis>();
  private readonly CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
  private readonly MAX_CACHE_SIZE = 500;
  private apiBaseUrl = 'http://localhost:8000/v1';
  private deviceToken = '';
  
  constructor(private background: any) {}
  
  setConfig(apiBaseUrl: string, deviceToken: string): void {
    this.apiBaseUrl = apiBaseUrl;
    this.deviceToken = deviceToken;
  }
  
  async analyzeDomains(domains: string[]): Promise<DomainAnalysis[]> {
    const results: DomainAnalysis[] = [];
    const unknownDomains: string[] = [];
    
    // Check cache first
    for (const domain of domains) {
      const cached = this.cache.get(domain);
      if (cached && Date.now() - cached.analyzedAt < this.CACHE_TTL_MS) {
        results.push({ ...cached, cached: true });
      } else {
        unknownDomains.push(domain);
      }
    }
    
    // If all cached, return early
    if (unknownDomains.length === 0) {
      return results;
    }
    
    // Batch unknown domains (max 20 per request)
    const batches = this.chunkArray(unknownDomains, 20);
    
    for (const batch of batches) {
      const batchResults = await this.analyzeBatch(batch);
      results.push(...batchResults);
    }
    
    return results;
  }
  
  private async analyzeBatch(domains: string[]): Promise<DomainAnalysis[]> {
    try {
      const response = await fetch(`${this.apiBaseUrl}/analyze/domains`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Device-Token': this.deviceToken,
        },
        body: JSON.stringify({ domains }),
      });
      
      if (!response.ok) {
        throw new Error(`API error: ${response.status}`);
      }
      
      const data = await response.json();
      
      // Process results
      const results: DomainAnalysis[] = [];
      
      for (const domain of domains) {
        const apiResult = data.results?.[domain];
        
        let analysis: DomainAnalysis;
        
        if (apiResult) {
          // Use API result
          analysis = {
            domain,
            level: apiResult.level,
            score: apiResult.score,
            signals: apiResult.signals || [],
            cached: false,
            analyzedAt: Date.now(),
          };
        } else {
          // Fallback to local heuristics
          const heuristic = runHeuristics(`https://${domain}`);
          analysis = {
            domain,
            level: heuristic.level,
            score: heuristic.score,
            signals: heuristic.signals,
            cached: false,
            analyzedAt: Date.now(),
          };
        }
        
        // Cache result
        this.cacheResult(analysis);
        results.push(analysis);
      }
      
      return results;
    } catch (error) {
      console.error('[BatchAnalyzer] Batch analysis failed:', error);
      
      // Fallback to local heuristics for all domains
      const results: DomainAnalysis[] = [];
      for (const domain of domains) {
        const heuristic = runHeuristics(`https://${domain}`);
        const analysis: DomainAnalysis = {
          domain,
          level: heuristic.level,
          score: heuristic.score,
          signals: heuristic.signals,
          cached: false,
          analyzedAt: Date.now(),
        };
        this.cacheResult(analysis);
        results.push(analysis);
      }
      return results;
    }
  }
  
  private cacheResult(analysis: DomainAnalysis): void {
    // LRU eviction
    if (this.cache.size >= this.MAX_CACHE_SIZE) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) this.cache.delete(firstKey);
    }
    
    this.cache.set(analysis.domain, analysis);
  }
  
  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }
  
  clearCache(): void {
    this.cache.clear();
  }
  
  getCacheStats(): { size: number; maxSize: number } {
    return { size: this.cache.size, maxSize: this.MAX_CACHE_SIZE };
  }
}

let batchAnalyzerInstance: BatchAnalyzer | null = null;

export function initializeBatchAnalyzer(background: any): void {
  // Instance created in background service
}

export function getBatchAnalyzer(): BatchAnalyzer | null {
  return batchAnalyzerInstance;
}

export function setBatchAnalyzer(analyzer: BatchAnalyzer): void {
  batchAnalyzerInstance = analyzer;
}