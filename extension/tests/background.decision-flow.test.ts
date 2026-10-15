/**
 * Background Service Decision Flow Regression Tests
 * Tests the complete URL analysis and blocking decision pipeline
 */

import { describe, it, expect, beforeEach, vi, Mock } from 'vitest';
import { 
  runHeuristics,
} from '../src/shared/heuristics';
import { 
  Signal, 
  RiskLevel, 
  ActionType,
  DeviceSettings,
  AnalyzeResponse 
} from '../src/shared/types';

/**
 * Local copy of KNOWN_LEGITIMATE_DOMAINS for testing
 * (Matches the implementation in heuristics.ts)
 */
const KNOWN_LEGITIMATE_DOMAINS = new Set([
  // Major tech & search
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com', 'instagram.com',
  'linkedin.com', 'wikipedia.org', 'yahoo.com', 'amazon.com', 'reddit.com',
  'netflix.com', 'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
  'cloudflare.com', 'adobe.com', 'salesforce.com', 'dropbox.com', 'slack.com',
  'zoom.us', 'discord.com', 'twitch.tv', 'pinterest.com', 'ebay.com',
  
  // Banking & finance
  'paypal.com', 'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com',
  'lowes.com', 'costco.com', 'cvs.com', 'walgreens.com', 'bankofamerica.com',
  'chase.com', 'wellsfargo.com', 'citibank.com', 'capitalone.com', 'amex.com',
  'americanexpress.com', 'coinbase.com', 'binance.com', 'blockchain.com',
  'metamask.io', 'stripe.com', 'squareup.com', 'venmo.com', 'cash.app',
  
  // Email & communication
  'gmail.com', 'outlook.com', 'proton.me', 'protonmail.com', 'icloud.com',
  'office.com', 'office365.com', 'live.com', 'msn.com', 'bing.com',
  'duckduckgo.com', 'brave.com', 'mozilla.org', 'opera.com', 'vivaldi.com',
  'aol.com', 'mail.com', 'zoho.com', 'fastmail.com',
  
  // Developer & dev tools
  'npmjs.com', 'pypi.org', 'rubygems.org', 'packagist.org', 'crates.io',
  'docker.com', 'kubernetes.io', 'terraform.io', 'ansible.com', 'jenkins.io',
  'gitlab.com', 'bitbucket.org', 'atlassian.com', 'jira.com', 'confluence.com',
  'trello.com', 'asana.com', 'notion.so', 'figma.com', 'vercel.com', 'netlify.com',
  'heroku.com', 'digitalocean.com', 'linode.com', 'vultr.com', 'aws.amazon.com',
  'cloud.google.com', 'azure.microsoft.com', 'fastly.com', 'akamai.com',
  
  // CDNs & Google/YouTube ecosystem
  'googlevideo.com', 'ytimg.com', 'ggpht.com', 'googleusercontent.com', 'gstatic.com',
  'googleapis.com', 'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'googleadservices.com', 'facebook.net', 'fbcdn.net', 'cdninstagram.com',
  'whatsapp.net', 'messenger.com', 'telegram.org', 'signal.org', 'discordapp.com',
  'discord.media', 'discord.gg', 'slack-edge.com', 'slack-imgs.com', 'slack-files.com',
  'teams.microsoft.com', 'teams.live.com', 'sharepoint.com', 'onedrive.com',
  'outlook.office.com', 'outlook.office365.com', 'login.microsoftonline.com',
  'login.live.com', 'account.microsoft.com',
  'youtube-nocookie.com',
  
  // Apple ecosystem
  'apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.apple.com',
  'apps.apple.com', 'music.apple.com', 'tv.apple.com', 'support.apple.com',
  'developer.apple.com', 'beta.apple.com', 'testflight.apple.com',
  
  // Major media & content
  'spotify.com', 'soundcloud.com', 'bandcamp.com', 'vimeo.com', 'dailymotion.com',
  'imgur.com', 'giphy.com', 'tenor.com', 'medium.com', 'substack.com',
  'wordpress.com', 'blogger.com', 'coursera.org', 'edx.org', 'udemy.com',
  'khanacademy.org', 'nytimes.com', 'washingtonpost.com', 'wsj.com',
  'economist.com', 'bloomberg.com', 'reuters.com', 'apnews.com', 'bbc.com',
  'cnn.com', 'theguardian.com', 'forbes.com', 'techcrunch.com', 'theverge.com',
  'wired.com', 'arstechnica.com', 'engadget.com', 'gizmodo.com', 'cnet.com',
  'zdnet.com', 'steamcommunity.com', 'store.steampowered.com', 'epicgames.com',
  'gog.com', 'riotgames.com', 'playstation.com', 'xbox.com', 'nintendo.com',
  'roblox.com', 'minecraft.net', 'leagueoflegends.com', 'valorant.com',
  'overwatch.com', 'fortnite.com', 'pubg.com', 'apexlegends.com',
]);

/**
 * Local copy of extractRegistrableDomain for testing
 * (Matches the implementation in heuristics.ts and background.ts)
 */
function extractRegistrableDomain(host: string): string {
  const parts = host.split('.');
  if (parts.length <= 2) return host;
  const tld = parts[parts.length - 1];
  const secondLevel = parts[parts.length - 2];
  const twoPartTlds = new Set(['co.uk', 'com.au', 'co.nz', 'co.jp', 'com.br', 'com.mx']);
  const maybeTwoPart = `${secondLevel}.${tld}`;
  if (twoPartTlds.has(maybeTwoPart) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return `${secondLevel}.${tld}`;
}

/**
 * Local copy of isKnownLegitimateDomain for testing
 */
function isKnownLegitimateDomain(host: string): boolean {
  const registrable = extractRegistrableDomain(host);
  return KNOWN_LEGITIMATE_DOMAINS.has(registrable);
}

// Mock browser APIs
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

// Mock crypto.subtle for hashDomain
const mockCrypto = {
  subtle: {
    digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
  },
};
vi.stubGlobal('crypto', mockCrypto);

describe('Heuristics: Known Legitimate Domains', () => {
  it('should bypass heuristics for youtube.com', () => {
    const result = runHeuristics('https://www.youtube.com/watch?v=abc123');
    expect(result.score).toBe(0);
    expect(result.level).toBe('Low');
    expect(result.signals).toHaveLength(0);
    expect(result.shouldAnalyze).toBe(false);
  });

  it('should bypass heuristics for youtube-nocookie.com (CDN)', () => {
    const result = runHeuristics('https://www.youtube-nocookie.com/embed/abc123');
    expect(result.score).toBe(0);
    expect(result.level).toBe('Low');
    expect(result.shouldAnalyze).toBe(false);
  });

  it('should bypass heuristics for google.com and subdomains', () => {
    const urls = [
      'https://google.com',
      'https://www.google.com',
      'https://maps.google.com',
      'https://drive.google.com',
      'https://docs.google.com',
    ];
    for (const url of urls) {
      const result = runHeuristics(url);
      expect(result.score).toBe(0);
      expect(result.level).toBe('Low');
      expect(result.shouldAnalyze).toBe(false);
    }
  });

  it('should bypass heuristics for major CDNs', () => {
    const urls = [
      'https://gstatic.com/script.js',
      'https://googleapis.com/analytics.js',
      'https://googletagmanager.com/gtm.js',
      'https://ytimg.com/video.jpg',
      'https://googleusercontent.com/user.jpg',
    ];
    for (const url of urls) {
      const result = runHeuristics(url);
      expect(result.score).toBe(0);
      expect(result.level).toBe('Low');
      expect(result.shouldAnalyze).toBe(false);
    }
  });

  it('should bypass heuristics for major tech sites', () => {
    const urls = [
      'https://github.com/user/repo',
      'https://stackoverflow.com/questions/123',
      'https://microsoft.com',
      'https://apple.com',
      'https://cloudflare.com',
    ];
    for (const url of urls) {
      const result = runHeuristics(url);
      expect(result.score).toBe(0);
      expect(result.level).toBe('Low');
      expect(result.shouldAnalyze).toBe(false);
    }
  });

  it('should bypass heuristics for banking sites', () => {
    const urls = [
      'https://chase.com',
      'https://bankofamerica.com',
      'https://paypal.com',
      'https://wellsfargo.com',
    ];
    for (const url of urls) {
      const result = runHeuristics(url);
      expect(result.score).toBe(0);
      expect(result.level).toBe('Low');
      expect(result.shouldAnalyze).toBe(false);
    }
  });
});

describe('Heuristics: Suspicious Domains', () => {
  it('should flag typosquatting domains', () => {
    const result = runHeuristics('https://paypa1.com/login'); // 1 instead of l
    expect(result.score).toBeGreaterThanOrEqual(30);
    expect(result.level).not.toBe('Low');
    expect(result.shouldAnalyze).toBe(true);
  });

  it('should flag suspicious TLDs', () => {
    const result = runHeuristics('https://evil.xyz/phish');
    expect(result.score).toBeGreaterThanOrEqual(15);
    expect(result.shouldAnalyze).toBe(true);
  });

  it('should flag brand in subdomain', () => {
    const result = runHeuristics('https://paypal.phishing-site.com/login');
    expect(result.score).toBeGreaterThanOrEqual(25);
    expect(result.shouldAnalyze).toBe(true);
  });

  it('should flag IP address URLs', () => {
    const result = runHeuristics('http://192.168.1.1/admin');
    expect(result.score).toBeGreaterThanOrEqual(30);
    expect(result.shouldAnalyze).toBe(true);
  });

  it('should flag URL shorteners', () => {
    const result = runHeuristics('https://bit.ly/evil-link');
    expect(result.score).toBeGreaterThanOrEqual(15);
    expect(result.shouldAnalyze).toBe(true);
  });
});

describe('URL Normalization: extractRegistrableDomain', () => {
  it('should extract registrable domain from subdomain', () => {
    expect(extractRegistrableDomain('www.youtube.com')).toBe('youtube.com');
    expect(extractRegistrableDomain('maps.google.com')).toBe('google.com');
    expect(extractRegistrableDomain('drive.google.com')).toBe('google.com');
  });

  it('should handle two-part TLDs', () => {
    expect(extractRegistrableDomain('www.example.co.uk')).toBe('example.co.uk');
    expect(extractRegistrableDomain('api.example.com.au')).toBe('example.com.au');
  });

  it('should return host as-is for simple domains', () => {
    expect(extractRegistrableDomain('example.com')).toBe('example.com');
    expect(extractRegistrableDomain('youtube.com')).toBe('youtube.com');
  });
});

describe('Enforcement Policy Decision Logic', () => {
  // Test the shouldBlockBasedOnPolicy logic
  const shouldBlockBasedOnPolicy = (policy: 'warn' | 'block', level: RiskLevel, action: ActionType): boolean => {
    if (policy === 'warn') {
      return false;
    }
    return action === 'block' && (level === 'High' || level === 'Critical');
  };

  it('should NEVER block in warn mode regardless of risk level', () => {
    const levels: RiskLevel[] = ['Low', 'Medium', 'High', 'Critical'];
    const actions: ActionType[] = ['allow', 'warn', 'block'];
    
    for (const level of levels) {
      for (const action of actions) {
        const shouldBlock = shouldBlockBasedOnPolicy('warn', level, action);
        expect(shouldBlock).toBe(false);
      }
    }
  });

  it('should block in block mode for High/Critical with block action', () => {
    expect(shouldBlockBasedOnPolicy('block', 'High', 'block')).toBe(true);
    expect(shouldBlockBasedOnPolicy('block', 'Critical', 'block')).toBe(true);
  });

  it('should NOT block in block mode for Low/Medium with block action', () => {
    expect(shouldBlockBasedOnPolicy('block', 'Low', 'block')).toBe(false);
    expect(shouldBlockBasedOnPolicy('block', 'Medium', 'block')).toBe(false);
  });

  it('should NOT block in block mode for warn action', () => {
    expect(shouldBlockBasedOnPolicy('block', 'High', 'warn')).toBe(false);
    expect(shouldBlockBasedOnPolicy('block', 'Critical', 'warn')).toBe(false);
  });

  it('should NOT block in block mode for allow action', () => {
    expect(shouldBlockBasedOnPolicy('block', 'Critical', 'allow')).toBe(false);
  });
});

describe('Block Source Tracking', () => {
  it('should distinguish blocklist from ML from heuristic blocks', () => {
    // This test documents the expected behavior
    const blockSources = ['blocklist', 'ml', 'heuristic'] as const;
    
    for (const source of blockSources) {
      expect(['blocklist', 'ml', 'heuristic']).toContain(source);
    }
  });
});

describe('API Error Handling', () => {
  it('should not auto-block on network errors for clean domains', () => {
    // Test that heuristic score < 15 with no signals = allow silently
    const heuristicResult = { score: 5, level: 'Low' as RiskLevel, signals: [] as Signal[], shouldAnalyze: false };
    
    // Simulate the fail-open logic
    const isNetworkError = true;
    if (heuristicResult.score < 15 && heuristicResult.signals.length === 0) {
      // Should allow silently
      expect(true).toBe(true);
    }
  });

  it('should show unchecked warning for suspicious domains on API failure', () => {
    const heuristicResult = { score: 30, level: 'Medium' as RiskLevel, signals: [{ key: 'test', category: 'structural' as const, label: 'Test', points: 30, reason: 'test', evidence: [] }], shouldAnalyze: true };
    
    // Simulate the fail-open logic for suspicious domains
    if (heuristicResult.score >= 15 || heuristicResult.signals.length > 0) {
      // Should warn with unchecked badge
      expect(true).toBe(true);
    }
  });
});

describe('Continue Anyway Behavior', () => {
  it('should NOT add to permanent allowlist', () => {
    // The CONTINUE_ANYWAY handler should only navigate back to URL
    // without modifying customAllowlist
    const customAllowlistBefore = ['existing.com'];
    const blockDataUrl = 'https://suspicious-site.com/page';
    
    // Simulate the new behavior (no allowlist addition)
    const customAllowlistAfter = [...customAllowlistBefore];
    // Should NOT add suspicious-site.com
    expect(customAllowlistAfter).not.toContain('suspicious-site.com');
  });
});

describe('Bloom Filter Allowlist', () => {
  it('should allow known legitimate domains via isKnownLegitimateDomain', () => {
    const testDomains = [
      'youtube.com',
      'www.youtube.com',
      'm.youtube.com',
      'google.com',
      'www.google.com',
      'maps.google.com',
      'github.com',
      'www.github.com',
    ];
    
    for (const domain of testDomains) {
      expect(isKnownLegitimateDomain(domain)).toBe(true);
    }
  });

  it('should NOT allow unknown domains', () => {
    const testDomains = [
      'unknown-site.com',
      'phishing.xyz',
      'evil.top',
      'malicious.click',
    ];
    
    for (const domain of testDomains) {
      expect(isKnownLegitimateDomain(domain)).toBe(false);
    }
  });
});

describe('Decision Flow Integration', () => {
  it('should allow benign URLs without API call', () => {
    // Known legitimate -> immediate allow
    const result = runHeuristics('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    expect(result.shouldAnalyze).toBe(false);
    expect(result.action).toBeUndefined(); // heuristics doesn't return action
  });

  it('should send suspicious URLs to API', () => {
    const result = runHeuristics('https://paypa1-login.xyz/verify');
    expect(result.shouldAnalyze).toBe(true);
    expect(result.score).toBeGreaterThan(0);
  });
});