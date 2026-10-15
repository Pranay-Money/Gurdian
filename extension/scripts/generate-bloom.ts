#!/usr/bin/env node
/**
 * Build-time script to generate Tranco top-N Bloom filter.
 * Downloads Tranco list, extracts domains, and creates optimized Bloom filter config.
 * Output: public/assets/tranco-bloom.json (imported by background service worker)
 */

import { createBloomFilter, BloomFilterConfig } from '../src/shared/bloom';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip';
const OUTPUT_PATH = resolve(__dirname, '../public/assets/tranco-bloom.json');
const TARGET_COUNT = 100_000; // Top 100K domains
const FALSE_POSITIVE_RATE = 0.01; // 1% false positive rate

async function downloadTrancoList(): Promise<string[]> {
  console.log(`Downloading Tranco list from ${TRANCO_URL}...`);
  
  const response = await fetch(TRANCO_URL);
  if (!response.ok) {
    throw new Error(`Failed to download Tranco list: ${response.statusText}`);
  }
  
  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);
  
  // Unzip the CSV
  const { unzip } = await import('zlib');
  const { promisify } = await import('util');
  const unzipAsync = promisify(unzip);
  
  const csvBuffer = await unzipAsync(buffer);
  const csvText = csvBuffer.toString('utf-8');
  
  // Parse CSV: rank,domain
  const lines = csvText.trim().split('\n');
  const domains: string[] = [];
  
  for (const line of lines) {
    const parts = line.split(',');
    if (parts.length >= 2) {
      const domain = parts[1].trim().toLowerCase();
      if (domain && !domain.includes('.')) {
        // Skip invalid domains
        continue;
      }
      domains.push(domain);
      if (domains.length >= TARGET_COUNT) break;
    }
  }
  
  console.log(`Parsed ${domains.length} domains from Tranco list`);
  return domains;
}

function generateFallbackDomains(): string[] {
  // Fallback domains for development/offline builds
  return [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
    'linkedin.com', 'wikipedia.org', 'yahoo.com', 'amazon.com', 'reddit.com',
    'netflix.com', 'microsoft.com', 'apple.com', 'github.com', 'stackoverflow.com',
    'cloudflare.com', 'adobe.com', 'salesforce.com', 'dropbox.com', 'slack.com',
    'zoom.us', 'discord.com', 'twitch.tv', 'pinterest.com', 'ebay.com',
    'paypal.com', 'walmart.com', 'target.com', 'bestbuy.com', 'homedepot.com',
    'lowes.com', 'costco.com', 'cvs.com', 'walgreens.com', 'bankofamerica.com',
    'chase.com', 'wellsfargo.com', 'citibank.com', 'capitalone.com', 'amex.com',
    'gmail.com', 'outlook.com', 'yahoo.com', 'proton.me', 'icloud.com',
    'office.com', 'office365.com', 'live.com', 'msn.com', 'bing.com',
    'duckduckgo.com', 'brave.com', 'mozilla.org', 'opera.com', 'vivaldi.com',
    // Add more common domains to reach a reasonable count
    'npmjs.com', 'pypi.org', 'rubygems.org', 'packagist.org', 'crates.io',
    'maven.org', 'gradle.org', 'docker.com', 'kubernetes.io', 'terraform.io',
    'ansible.com', 'jenkins.io', 'gitlab.com', 'bitbucket.org', 'atlassian.com',
    'jira.com', 'confluence.com', 'trello.com', 'asana.com', 'notion.so',
    'figma.com', 'sketch.com', 'invisionapp.com', 'framer.com', 'webflow.com',
    'vercel.com', 'netlify.com', 'render.com', 'railway.app', 'fly.io',
    'heroku.com', 'digitalocean.com', 'linode.com', 'vultr.com', 'aws.amazon.com',
    'cloud.google.com', 'azure.microsoft.com', 'cloudflare.com', 'fastly.com',
    'akamai.com', 'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net',
    'cdnjs.com', 'bootstrapcdn.com', 'fontawesome.com', 'fonts.google.com',
    'fonts.adobe.com', 'typekit.net', 'maps.googleapis.com', 'maps.gstatic.com',
    'youtube-nocookie.com', 'ytimg.com', 'googlevideo.com', 'ggpht.com',
    'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'google-analytics.com',
    'googletagmanager.com', 'doubleclick.net', 'googleadservices.com',
    'facebook.net', 'fbcdn.net', 'instagram.com', 'cdninstagram.com',
    'whatsapp.net', 'whatsapp.com', 'messenger.com', 'telegram.org',
    'signal.org', 'discordapp.com', 'discord.media', 'discord.gg',
    'slack.com', 'slack-edge.com', 'slack-imgs.com', 'slack-files.com',
    'teams.microsoft.com', 'teams.live.com', 'sharepoint.com', 'onedrive.com',
    'office.com', 'outlook.office.com', 'outlook.office365.com',
    'login.microsoftonline.com', 'login.live.com', 'account.microsoft.com',
    'apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.apple.com',
    'apps.apple.com', 'music.apple.com', 'tv.apple.com', 'support.apple.com',
    'developer.apple.com', 'beta.apple.com', 'testflight.apple.com',
  ];
}

async function main() {
  let domains: string[];
  
  try {
    domains = await downloadTrancoList();
  } catch (error) {
    console.warn('Failed to download Tranco list, using fallback domains:', error);
    domains = generateFallbackDomains();
  }
  
  console.log(`Generating Bloom filter for ${domains.length} domains...`);
  
  const config = createBloomFilter(domains, FALSE_POSITIVE_RATE);
  
  console.log('Bloom filter config:');
  console.log(`  Size: ${config.size} bits (${Math.round(config.size / 8 / 1024)} KB)`);
  console.log(`  Hash functions: ${config.hashCount}`);
  console.log(`  Item count: ${config.itemCount}`);
  console.log(`  False positive rate: ~${(config.falsePositiveRate * 100).toFixed(2)}%`);
  console.log(`  Bit density: ${((config.bits.length * 8 / config.size) * 100).toFixed(2)}%`);
  
  // Ensure output directory exists
  const outputDir = dirname(OUTPUT_PATH);
  if (!existsSync(outputDir)) {
    mkdirSync(outputDir, { recursive: true });
  }
  
  // Write config as JSON
  writeFileSync(OUTPUT_PATH, JSON.stringify(config, null, 2));
  console.log(`\nBloom filter written to ${OUTPUT_PATH}`);
  
  // Also generate TypeScript import for direct usage
  const tsOutputPath = resolve(__dirname, '../src/shared/tranco-bloom.ts');
  const tsContent = `/**
 * Auto-generated Tranco top-${TARGET_COUNT} Bloom filter config.
 * Generated at: ${new Date().toISOString()}
 * DO NOT EDIT MANUALLY - Run 'npm run generate:bloom' to regenerate.
 */

import { BloomFilterConfig } from './bloom';

export const trancoBloomConfig: BloomFilterConfig = ${JSON.stringify(config, null, 2)};
`;
  writeFileSync(tsOutputPath, tsContent);
  console.log(`TypeScript config written to ${tsOutputPath}`);
}

main().catch((error) => {
  console.error('Failed to generate Bloom filter:', error);
  process.exit(1);
});