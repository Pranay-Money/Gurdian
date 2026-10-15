/**
 * Default Tranco Bloom Filter Configuration
 * 
 * This is a fallback configuration with a curated list of well-known legitimate domains.
 * In production, this file is generated at build time by `npm run generate:bloom` which downloads
 * the actual Tranco top-1M list and creates an optimized Bloom filter.
 * 
 * The generated file replaces this one with a much larger, more effective filter.
 */

import { BloomFilterConfig } from './bloom';
import { createBloomFilter } from './bloom';

/**
 * Curated list of well-known legitimate domains for fallback.
 * This ensures the extension works out-of-the-box without requiring the build-time generation.
 * Covers major tech, social, banking, email, CDN, and other popular services.
 */
const FALLBACK_DOMAINS = [
  // Major tech & search
  'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'instagram.com',
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
  'yahoo.com', 'aol.com', 'mail.com', 'zoho.com', 'fastmail.com',
  
  // Developer & dev tools
  'npmjs.com', 'pypi.org', 'rubygems.org', 'packagist.org', 'crates.io',
  'maven.org', 'gradle.org', 'docker.com', 'kubernetes.io', 'terraform.io',
  'ansible.com', 'jenkins.io', 'gitlab.com', 'bitbucket.org', 'atlassian.com',
  'jira.com', 'confluence.com', 'trello.com', 'asana.com', 'notion.so',
  'figma.com', 'sketch.com', 'invisionapp.com', 'framer.com', 'webflow.com',
  'vercel.com', 'netlify.com', 'render.com', 'railway.app', 'fly.io',
  'heroku.com', 'digitalocean.com', 'linode.com', 'vultr.com', 'aws.amazon.com',
  'cloud.google.com', 'azure.microsoft.com', 'fastly.com', 'akamai.com',
  
  // CDNs & static assets
  'cdnjs.cloudflare.com', 'unpkg.com', 'jsdelivr.net', 'cdnjs.com',
  'bootstrapcdn.com', 'fontawesome.com', 'fonts.google.com', 'fonts.adobe.com',
  'typekit.net', 'maps.googleapis.com', 'maps.gstatic.com',
  'youtube-nocookie.com', 'ytimg.com', 'googlevideo.com', 'ggpht.com',
  'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'google-analytics.com',
  'googletagmanager.com', 'doubleclick.net', 'googleadservices.com',
  'facebook.net', 'fbcdn.net', 'cdninstagram.com', 'whatsapp.net',
  'messenger.com', 'telegram.org', 'signal.org', 'discordapp.com',
  'discord.media', 'discord.gg', 'slack-edge.com', 'slack-imgs.com',
  'slack-files.com', 'teams.microsoft.com', 'teams.live.com', 'sharepoint.com',
  'onedrive.com', 'outlook.office.com', 'outlook.office365.com',
  'login.microsoftonline.com', 'login.live.com', 'account.microsoft.com',
  
  // Apple ecosystem
  'apple.com', 'icloud.com', 'me.com', 'mac.com', 'itunes.apple.com',
  'apps.apple.com', 'music.apple.com', 'tv.apple.com', 'support.apple.com',
  'developer.apple.com', 'beta.apple.com', 'testflight.apple.com',
  
  // Additional major sites
  'spotify.com', 'soundcloud.com', 'bandcamp.com', 'vimeo.com', 'dailymotion.com',
  'imgur.com', 'giphy.com', 'tenor.com', 'flickr.com', '500px.com',
  'medium.com', 'substack.com', 'wordpress.com', 'blogger.com', 'tumblr.com',
  'quora.com', 'stackexchange.com', 'superuser.com', 'serverfault.com',
  'askubuntu.com', 'mathoverflow.net', 'coursera.org', 'edx.org', 'udemy.com',
  'khanacademy.org', 'mit.edu', 'stanford.edu', 'harvard.edu', 'berkeley.edu',
  'nytimes.com', 'washingtonpost.com', 'wsj.com', 'economist.com', 'bloomberg.com',
  'reuters.com', 'apnews.com', 'bbc.com', 'cnn.com', 'theguardian.com',
  'forbes.com', 'techcrunch.com', 'theverge.com', 'wired.com', 'arstechnica.com',
  'engadget.com', 'gizmodo.com', 'mashable.com', 'digitaltrends.com',
  'cnet.com', 'zdnet.com', 'tomshardware.com', 'anandtech.com', 'pcgamer.com',
  'ign.com', 'gamespot.com', 'kotaku.com', 'polygon.com', 'eurogamer.net',
  'steamcommunity.com', 'store.steampowered.com', 'epicgames.com', 'gog.com',
  'origin.com', 'battle.net', 'uplay.com', 'riotgames.com', 'playstation.com',
  'xbox.com', 'nintendo.com', 'roblox.com', 'minecraft.net', 'leagueoflegends.com',
  'valorant.com', 'overwatch.com', 'fortnite.com', 'pubg.com', 'apexlegends.com',
];

// Generate Bloom filter from fallback domains at module load time
const fallbackConfig = createBloomFilter(FALLBACK_DOMAINS, 0.01);

export const trancoBloomConfig: BloomFilterConfig = fallbackConfig;

/**
 * To generate the real Tranco Bloom filter (recommended for production):
 * 1. Run `npm run generate:bloom`
 * 2. This downloads the Tranco top-1M list
 * 3. Creates an optimized Bloom filter for top-100K domains
 * 4. Outputs to src/shared/tranco-bloom.ts
 * 
 * The generated filter will have:
 * - ~1.5M bits (~187 KB)
 * - ~11 hash functions
 * - ~1% false positive rate
 * - ~100K domains
 */