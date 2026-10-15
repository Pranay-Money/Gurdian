/**
 * Quick local heuristics for URL analysis.
 * Runs synchronously in the background service worker before API call.
 * Returns a risk score (0-100) and signals for suspicious patterns.
 */

import { Signal, SignalCategory, EvidenceItem } from './types';

/**
 * Well-known legitimate domains that should never be flagged by heuristics.
 * These are registrable domains (e.g., "google.com" matches "www.google.com", "maps.google.com", etc.)
 * This list is a subset of the Tranco top-100K for immediate heuristic bypass.
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
 * Extract registrable domain from hostname (e.g., "www.google.com" -> "google.com")
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
 * Check if a domain is a known legitimate domain (or subdomain thereof).
 * Returns true if the registrable domain is in the known-legitimate set.
 */
function isKnownLegitimateDomain(host: string): boolean {
  const registrable = extractRegistrableDomain(host);
  return KNOWN_LEGITIMATE_DOMAINS.has(registrable);
}

export interface HeuristicResult {
  score: number;
  level: 'Low' | 'Medium' | 'High' | 'Critical';
  signals: Signal[];
  shouldAnalyze: boolean; // Whether to send to backend API
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'loan', 'click', 'link', 'online', 'site', 'website',
  'space', 'tech', 'info', 'biz', 'club', 'win', 'bid', 'racing',
  'download', 'stream', 'review', 'party', 'science', 'work',
  'accountant', 'date', 'faith', 'cricket', 'trade', 'men',
]);

const BRAND_KEYWORDS = [
  'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
  'instagram', 'whatsapp', 'netflix', 'bank', 'chase', 'wellsfargo',
  'bankofamerica', 'citibank', 'capitalone', 'amex', 'americanexpress',
  'coinbase', 'binance', 'blockchain', 'metamask', 'wallet',
  'github', 'gitlab', 'bitbucket', 'atlassian', 'jira', 'confluence',
  'slack', 'zoom', 'teams', 'webex', 'dropbox', 'box', 'drive',
  'onedrive', 'icloud', 'office365', 'outlook', 'live', 'hotmail',
  'yahoo', 'proton', 'protonmail', 'aol', 'mail', 'email',
];

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'update', 'confirm', 'secure',
  'account', 'security', 'auth', 'authenticate', 'validate',
  'recovery', 'reset', 'unlock', 'suspend', 'verify-now',
  'wallet', 'crypto', 'bitcoin', 'ethereum', 'airdrop',
  'claim', 'reward', 'bonus', 'gift', 'free', 'urgent',
  'immediate', 'action-required', 'limited-time', 'expire',
  'support', 'helpdesk', 'service', 'billing', 'invoice',
  'payment', 'refund', 'transaction', 'order', 'shipment',
  'delivery', 'tracking', 'package', 'parcel', 'customs',
];

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'bc.vc', 'short.io', 'cutt.ly', 'rebrand.ly',
  'shorturl.at', 'v.gd', 'tr.im', 'urlzs.com', 'tiny.cc',
]);

function shannonEntropy(str: string): number {
  const freq = new Map<string, number>();
  for (const char of str) {
    freq.set(char, (freq.get(char) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function levenshteinDistance(a: string, b: string): number {
  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + cost
      );
    }
  }
  return matrix[b.length][a.length];
}

function checkTyposquatting(domain: string): Signal[] {
  const signals: Signal[] = [];
  const registrable = extractRegistrableDomain(domain);
  const mainDomain = registrable.split('.')[0];

  for (const brand of BRAND_KEYWORDS) {
    const dist = levenshteinDistance(mainDomain, brand);
    if (dist === 1 && mainDomain.length === brand.length) {
      // Single character substitution
      signals.push({
        key: 'typosquatting_substitution',
        category: 'structural',
        label: 'Typosquatting: Character substitution',
        points: 35,
        reason: `Domain "${mainDomain}" is one character different from known brand "${brand}"`,
        evidence: [
          { type: 'domain', value: domain, description: 'Full domain' },
          { type: 'brand', value: brand, description: 'Target brand' },
        ],
      });
    } else if (dist === 1 && mainDomain.length === brand.length + 1) {
      // Extra character
      signals.push({
        key: 'typosquatting_insertion',
        category: 'structural',
        label: 'Typosquatting: Extra character',
        points: 30,
        reason: `Domain "${mainDomain}" adds a character to known brand "${brand}"`,
        evidence: [
          { type: 'domain', value: domain, description: 'Full domain' },
          { type: 'brand', value: brand, description: 'Target brand' },
        ],
      });
    } else if (dist === 1 && mainDomain.length === brand.length - 1) {
      // Missing character
      signals.push({
        key: 'typosquatting_deletion',
        category: 'structural',
        label: 'Typosquatting: Missing character',
        points: 30,
        reason: `Domain "${mainDomain}" omits a character from known brand "${brand}"`,
        evidence: [
          { type: 'domain', value: domain, description: 'Full domain' },
          { type: 'brand', value: brand, description: 'Target brand' },
        ],
      });
    } else if (dist === 2 && mainDomain.length === brand.length) {
      // Two substitutions (less severe)
      signals.push({
        key: 'typosquatting_double_sub',
        category: 'structural',
        label: 'Possible typosquatting',
        points: 15,
        reason: `Domain "${mainDomain}" resembles known brand "${brand}" (2 char diff)`,
        evidence: [
          { type: 'domain', value: domain, description: 'Full domain' },
          { type: 'brand', value: brand, description: 'Target brand' },
        ],
      });
    }
  }
  return signals;
}

function checkSuspiciousTLD(domain: string): Signal[] {
  const tld = domain.split('.').pop()?.toLowerCase() || '';
  if (SUSPICIOUS_TLDS.has(tld)) {
    return [{
      key: 'suspicious_tld',
      category: 'structural',
      label: 'Suspicious TLD',
      points: 15,
      reason: `Domain uses suspicious TLD ".${tld}" commonly abused for phishing`,
      evidence: [
        { type: 'tld', value: tld, description: 'Top-level domain' },
        { type: 'domain', value: domain, description: 'Full domain' },
      ],
    }];
  }
  return [];
}

function checkBrandInSubdomain(domain: string): Signal[] {
  const signals: Signal[] = [];
  const parts = domain.split('.');
  if (parts.length < 3) return signals;

  const registrable = extractRegistrableDomain(domain);
  const subdomainPart = domain.slice(0, -(registrable.length + 1)).toLowerCase();

  for (const brand of BRAND_KEYWORDS) {
    if (subdomainPart.includes(brand) && !registrable.startsWith(brand + '.')) {
      signals.push({
        key: 'brand_in_subdomain',
        category: 'structural',
        label: 'Brand name in subdomain',
        points: 25,
        reason: `Brand "${brand}" appears in subdomain but not in registrable domain`,
        evidence: [
          { type: 'subdomain', value: subdomainPart, description: 'Subdomain portion' },
          { type: 'brand', value: brand, description: 'Impersonated brand' },
          { type: 'registrable_domain', value: registrable, description: 'Actual registrable domain' },
        ],
      });
    }
  }
  return signals;
}

function checkSuspiciousKeywords(url: string): Signal[] {
  const signals: Signal[] = [];
  const lowerUrl = url.toLowerCase();
  let matchCount = 0;
  const matched: string[] = [];

  for (const keyword of SUSPICIOUS_KEYWORDS) {
    if (lowerUrl.includes(keyword)) {
      matchCount++;
      matched.push(keyword);
    }
  }

  if (matchCount >= 3) {
    signals.push({
      key: 'multiple_suspicious_keywords',
      category: 'linguistic',
      label: 'Multiple suspicious keywords',
      points: 20,
      reason: `URL contains ${matchCount} suspicious keywords: ${matched.slice(0, 5).join(', ')}`,
      evidence: matched.slice(0, 10).map(k => ({
        type: 'keyword', value: k, description: 'Suspicious keyword found'
      })),
    });
  } else if (matchCount >= 1) {
    signals.push({
      key: 'suspicious_keyword',
      category: 'linguistic',
      label: 'Suspicious keyword in URL',
      points: 8,
      reason: `URL contains suspicious keyword: ${matched.join(', ')}`,
      evidence: matched.map(k => ({
        type: 'keyword', value: k, description: 'Suspicious keyword found'
      })),
    });
  }
  return signals;
}

function checkUrlShortener(domain: string): Signal[] {
  if (URL_SHORTENERS.has(domain.toLowerCase())) {
    return [{
      key: 'url_shortener',
      category: 'structural',
      label: 'URL shortener domain',
      points: 15,
      reason: 'URL shorteners hide the true destination and are commonly abused',
      evidence: [
        { type: 'domain', value: domain, description: 'Shortener domain' },
      ],
    }];
  }
  return [];
}

function checkEntropy(domain: string): Signal[] {
  // Check subdomain entropy for algorithmically generated domains
  const parts = domain.split('.');
  if (parts.length < 3) return [];

  const registrable = extractRegistrableDomain(domain);
  const subdomain = domain.slice(0, -(registrable.length + 1));
  const entropy = shannonEntropy(subdomain.replace(/\./g, ''));

  if (entropy > 3.5 && subdomain.length > 8) {
    return [{
      key: 'high_entropy_subdomain',
      category: 'structural',
      label: 'High entropy subdomain',
      points: 20,
      reason: `Subdomain has high character entropy (${entropy.toFixed(2)}), suggesting algorithmic generation`,
      evidence: [
        { type: 'entropy', value: entropy.toFixed(2), description: 'Shannon entropy' },
        { type: 'subdomain', value: subdomain, description: 'Subdomain analyzed' },
      ],
    }];
  }
  return [];
}

function checkIpAddress(url: string): Signal[] {
  const ipv4Regex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
  const ipv6Regex = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/;
  if (ipv4Regex.test(url) || ipv6Regex.test(url)) {
    return [{
      key: 'ip_address_in_url',
      category: 'structural',
      label: 'IP address in URL',
      points: 30,
      reason: 'Legitimate sites rarely use raw IP addresses',
      evidence: [
        { type: 'url', value: url, description: 'URL containing IP address' },
      ],
    }];
  }
  return [];
}

function checkExcessiveSubdomains(domain: string): Signal[] {
  const parts = domain.split('.');
  if (parts.length >= 5) {
    return [{
      key: 'excessive_subdomains',
      category: 'structural',
      label: 'Excessive subdomains',
      points: 10,
      reason: `Domain has ${parts.length - 2} subdomain levels (unusual for legitimate sites)`,
      evidence: [
        { type: 'domain', value: domain, description: 'Full domain' },
        { type: 'subdomain_count', value: String(parts.length - 2), description: 'Number of subdomain levels' },
      ],
    }];
  }
  return [];
}

function checkHomograph(domain: string): Signal[] {
  // Check for mixed scripts (Cyrillic, Greek lookalikes)
  const suspiciousChars = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u044F\u03B1\u03B2\u03B5\u03B7\u03B9\u03BA\u03BC\u03BD\u03BF\u03C1\u03C4\u03C5\u03C7]/; // Common lookalikes
  if (suspiciousChars.test(domain)) {
    return [{
      key: 'homograph_attack',
      category: 'structural',
      label: 'Possible homograph attack',
      points: 40,
      reason: 'Domain contains non-Latin characters that resemble Latin letters',
      evidence: [
        { type: 'domain', value: domain, description: 'Domain with mixed scripts' },
      ],
    }];
  }
  return [];
}

function checkLongDomain(domain: string): Signal[] {
  if (domain.length > 50) {
    return [{
      key: 'long_domain',
      category: 'structural',
      label: 'Unusually long domain',
      points: 10,
      reason: `Domain length is ${domain.length} characters (typical: <30)`,
      evidence: [
        { type: 'length', value: String(domain.length), description: 'Domain character count' },
        { type: 'domain', value: domain, description: 'Full domain' },
      ],
    }];
  }
  return [];
}

export function runHeuristics(url: string): HeuristicResult {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;

    // Quick bypass for known legitimate domains
    if (isKnownLegitimateDomain(domain)) {
      return { score: 0, level: 'Low', signals: [], shouldAnalyze: false };
    }

    const allSignals: Signal[] = [];

    // Run all heuristic checks
    allSignals.push(...checkTyposquatting(domain));
    allSignals.push(...checkSuspiciousTLD(domain));
    allSignals.push(...checkBrandInSubdomain(domain));
    allSignals.push(...checkSuspiciousKeywords(url));
    allSignals.push(...checkUrlShortener(domain));
    allSignals.push(...checkEntropy(domain));
    allSignals.push(...checkIpAddress(url));
    allSignals.push(...checkExcessiveSubdomains(domain));
    allSignals.push(...checkHomograph(domain));
    allSignals.push(...checkLongDomain(domain));

    // Calculate total score (capped at 100)
    const totalPoints = allSignals.reduce((sum, s) => sum + s.points, 0);
    const score = Math.min(100, totalPoints);

    // Determine level
    let level: HeuristicResult['level'] = 'Low';
    if (score >= 70) level = 'Critical';
    else if (score >= 50) level = 'High';
    else if (score >= 25) level = 'Medium';

    // Decide if we should send to API
    // Send to API if: score >= 15 (some suspicion) OR no signals but unknown domain
    const shouldAnalyze = score >= 15 || allSignals.length === 0;

    return { score, level, signals: allSignals, shouldAnalyze };
  } catch {
    // Invalid URL
    return { score: 0, level: 'Low', signals: [], shouldAnalyze: false };
  }
}

export function generateExplanation(result: HeuristicResult): string {
  if (result.signals.length === 0) {
    return 'No suspicious patterns detected locally. Domain appears clean based on quick heuristics.';
  }

  const topSignals = result.signals
    .sort((a, b) => b.points - a.points)
    .slice(0, 3);

  const reasons = topSignals.map(s => `• ${s.label}: ${s.reason}`).join('\n');
  return `Local heuristics found suspicious patterns:\n${reasons}\n\nRisk score: ${result.score}/100 (${result.level})`;
}