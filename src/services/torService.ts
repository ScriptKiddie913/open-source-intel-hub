// ============================================================================
// torService.ts
<<<<<<< HEAD
// REAL Dark Web Intelligence — Fully Functional, No Mock Data
=======
// ADVANCED Dark Web Intelligence — Multi-Tool Integration
//
// Combines conceptual techniques from:
//   - TorBot
//   - DarkScrape
//   - FreshOnions
//   - Onioff
//   - TorCrawl
//
// Integrates CLEARNET-ONLY intelligence sources:
//
//   ✔ PSBDMP (Pastebin dump index)
//   ✔ Rentry public API
//   ✔ Pastebin public archive
//   ✔ GitHub public code search
//   ✔ Telegram OSINT (Telemetr + t.me/s)
//   ✔ Dark.fail darknet market status
//
// SERVER-SAFE | VERCEL-READY | NO TOR DAEMON REQUIRED
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface OnionSite {
  url:  string;
  title: string;
  description: string;
  category: string;
  riskLevel: RiskLevel;
  lastSeen: string;
  status: 'online' | 'offline' | 'unknown';
  tags: string[];
  discoveredFrom: string;
  sshFingerprint?: string;
  bitcoinAddresses?: string[];
  emailAddresses?: string[];
  ports?: number[];
  language?: string;
}

export interface LeakSignal {
  id: string;
  title: string;
  indicator: string;
  source: 
    | 'pastebin'
    | 'ghostbin'
    | 'rentry'
    | 'github_gist'
    | 'psbdmp'
<<<<<<< HEAD
    | 'intelx';
  timestamp: string;
  url: string;
  context:  string;
=======
    | 'telegram'
    | 'onionland'
    | 'ahmia'
    | 'paste_rs'
    | 'dpaste'
    | 'intelx';
  timestamp: string;
  url: string;
  context: string;
  metadata?: {
    channelName?: string;
    subscribers?: number;
    views?: number;
    messageId?: number;
    emails?: string[];
    bitcoins?: string[];
    author?: string;
    pasteId?: string;
  };
}

export interface TelegramChannel {
  id: string;
  username: string;
  title: string;
  description: string;
  subscribers: number;
  category: string;
  riskLevel: RiskLevel;
  verified: boolean;
  tags: string[];
}

export interface TelegramMessage {
  id: string;
  channelUsername: string;
  messageId: number;
  text: string;
  date: string;
  views: number;
  forwards: number;
  hasMedia: boolean;
  mediaType?: string;
  link: string;
}

export interface DarkWebMarket {
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  uptime?: number;
  lastChecked: string;
  mirrors?: string[];
  v3Onion?: string;
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = [
<<<<<<< HEAD
  'onion. ws',
=======
  'onion.ws',
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  'onion.pet',
  'onion.ly',
];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;
<<<<<<< HEAD
=======

const EMAIL_REGEX =
  /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;

const BITCOIN_REGEX =
  /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b/g;

const SSH_FINGERPRINT_REGEX =
  /([0-9a-f]{2}:){15}[0-9a-f]{2}/gi;

const TIMEOUTS = {
  ONION_DISCOVERY: 8000,
  PASTE_SCAN: 5000,
  UPTIME_CHECK: 10000,
  TELEGRAM_SCAN: 7000,
  DEEP_SCAN: 12000,
  API_CALL: 6000,
};

const MAX_RESULTS = {
  ONIONS: 30,
  TELEGRAM_CHANNELS: 20,
  TELEGRAM_MESSAGES: 25,
  PASTES: 20,
  GITHUB: 15,
};

const TOR_SEARCH_ENGINES = [
  { name: 'ahmia', type: 'clearnet', url: 'https://ahmia.fi/search/?q=' },
  { name: 'onionland', type: 'clearnet', url: 'https://onionlandsearchengine.net/search?q=' },
] as const;

const INTEL_APIS = {
  psbdmp: 'https://psbdmp.ws/api/search/',
  rentry: 'https://rentry.co/api/search?q=',
  github: 'https://api.github.com/search/code?q=',
} as const;

const USER_AGENT =
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055

/* ============================================================================
   UTILITIES
============================================================================ */

function stripHtml(input: string): string {
<<<<<<< HEAD
  const div = document.createElement('div');
  div.innerHTML = input;
  return div.textContent || div.innerText || '';
=======
  if (!input) return '';
  return input.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
}

function nowISO(): string {
  return new Date().toISOString();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

<<<<<<< HEAD
=======
async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 5000
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }
}

>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
/* ============================================================================
   EXTRACTION
============================================================================ */

function extractEmails(text: string): string[] {
  return unique((text.match(EMAIL_REGEX) || []).map(e => e.toLowerCase()));
}

function extractBitcoinAddresses(text: string): string[] {
  return unique(text.match(BITCOIN_REGEX) || []);
}

function extractSSHFingerprints(text: string): string[] {
  return unique(text.match(SSH_FINGERPRINT_REGEX) || []);
}

function detectLanguage(text: string): string {
  const patterns: Record<string, RegExp> = {
    en: /\b(the|and|is|in|to|of|for|with)\b/gi,
    ru: /[а-яА-ЯёЁ]{3,}/g,
    zh: /[\u4e00-\u9fff]{2,}/g,
    es: /\b(el|la|de|en|y|que)\b/gi,
    fr: /\b(le|la|de|et|est)\b/gi,
    de: /\b(der|die|das|und)\b/gi,
  };

  let best = 'unknown';
  let max = 0;

  for (const [lang, rx] of Object.entries(patterns)) {
    const count = (text.match(rx) || []).length;
    if (count > max) {
      max = count;
      best = lang;
    }
  }

  return best;
}

/* ============================================================================
   RISK + TAGGING
============================================================================ */

function calculateRisk(text:  string): RiskLevel {
  const t = text.toLowerCase();

  if (
<<<<<<< HEAD
    t.includes('malware') ||
    t.includes('exploit') ||
    t.includes('ransom') ||
    t.includes('weapon') ||
    t.includes('drug') ||
    t.includes('child')
  ) {
    return 'critical';
  }

  if (
    t.includes('leak') ||
    t.includes('dump') ||
    t.includes('database') ||
    t.includes('hack') ||
    t.includes('breach')
  ) {
    return 'high';
  }
=======
    ['malware','exploit','ransomware','weapon','csam','hitman'].some(k =>
      t.includes(k)
    )
  ) return 'critical';

  if (
    ['leak','dump','breach','credentials','cvv','fullz'].some(k =>
      t.includes(k)
    )
  ) return 'high';
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055

  if (
    ['market','forum','phishing','fraud','carding'].some(k =>
      t.includes(k)
    )
  ) return 'medium';

  return 'low';
}

function extractTags(text: string): string[] {
<<<<<<< HEAD
  const keywords = [
    'market',
    'forum',
    'leak',
    'dump',
    'database',
    'malware',
    'exploit',
    'credentials',
    'phishing',
    'carding',
    'fraud',
    'drugs',
    'weapons',
    'breach',
    'ransomware',
  ];

  const lower = text. toLowerCase();
  return keywords.filter(k => lower.includes(k)).slice(0, 6);
=======
  const keys = [
    'market','forum','leak','dump','malware','exploit',
    'credentials','phishing','fraud','bitcoin','crypto'
  ];
  const t = text.toLowerCase();
  return keys.filter(k => t.includes(k)).slice(0, 10);
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
}

function categorize(text: string): string {
  const t = text.toLowerCase();
  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
<<<<<<< HEAD
  if (t.includes('leak') || t.includes('dump') || t.includes('breach')) return 'Data Leak';
  if (t.includes('mail')) return 'Email Service';
  if (t.includes('hosting')) return 'Hosting';
  if (t.includes('directory')) return 'Directory';
  if (t.includes('wiki')) return 'Wiki/Info';

=======
  if (t.includes('leak') || t.includes('dump')) return 'Data Leak';
  if (t.includes('bitcoin') || t.includes('crypto')) return 'Cryptocurrency';
  if (t.includes('vpn') || t.includes('hosting')) return 'Hosting';
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  return 'Unknown';
}

/* ============================================================================
<<<<<<< HEAD
   ONION DISCOVERY - AHMIA. FI (Real Tor Search Engine)
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:discover:${query}`;
=======
   ONION DISCOVERY
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:multi:${query}`;
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const collected: OnionSite[] = [];

<<<<<<< HEAD
  try {
    // Method 1: Ahmia.fi API (Real Tor search engine)
    const ahmiaUrl = `https://ahmia.fi/search/? q=${encodeURIComponent(query)}`;
    
    const response = await fetch(ahmiaUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      },
    });

    if (!response.ok) {
      console.error('Ahmia fetch failed:', response.statusText);
      return [];
    }

    const html = await response.text();

    // Extract onion addresses
    const onions = unique((html.match(ONION_REGEX) || [])).slice(0, 50);

    // Extract titles (from <h4> tags in Ahmia results)
    const titleMatches = Array.from(html.matchAll(/<h4[^>]*><a[^>]*>([^<]+)<\/a><\/h4>/gi));
    const titles = titleMatches.map(m => stripHtml(m[1]));

    // Extract descriptions (from <p> after h4)
    const descMatches = Array.from(html. matchAll(/<p class="result-[^"]*">([^<]+)<\/p>/gi));
    const descriptions = descMatches.map(m => stripHtml(m[1]));

    onions.forEach((onion, idx) => {
      const title = titles[idx] || 'Unknown Onion Service';
      const description = descriptions[idx] || 'No description available';
      const context = `${title} ${description}`.trim();

      results.push({
        url: onion,
        title,
        description,
        category: categorize(context),
        riskLevel: calculateRisk(context),
        lastSeen: nowISO(),
        status: 'unknown',
        tags: extractTags(context),
        discoveredFrom: 'ahmia',
      });
    });

    await cacheAPIResponse(cacheKey, results, 60);
    return results;
  } catch (error) {
    console.error('Onion discovery error:', error);
    return [];
=======
  for (const engine of TOR_SEARCH_ENGINES) {
    try {
      const res = await fetchWithTimeout(
        engine.url + encodeURIComponent(query),
        { headers: { 'User-Agent': USER_AGENT } },
        TIMEOUTS.ONION_DISCOVERY
      );

      if (!res.ok) continue;

      const html = await res.text();
      const onions = unique(html.match(ONION_REGEX) || []);

      for (const onion of onions) {
        const idx = html.indexOf(onion);
        const ctx = stripHtml(
          html.substring(Math.max(0, idx - 300), idx + 300)
        );

        collected.push({
          url: onion,
          title: 'Unknown Onion Service',
          description: ctx.slice(0, 200),
          category: categorize(ctx),
          riskLevel: calculateRisk(ctx),
          lastSeen: nowISO(),
          status: 'unknown',
          tags: extractTags(ctx),
          discoveredFrom: engine.name,
          emailAddresses: extractEmails(ctx),
          bitcoinAddresses: extractBitcoinAddresses(ctx),
          sshFingerprint: extractSSHFingerprints(ctx)[0],
          language: detectLanguage(ctx),
        });
      }
    } catch {}
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  }

  const uniqueSites = Array.from(
    new Map(collected.map(s => [s.url, s])).values()
  ).slice(0, MAX_RESULTS.ONIONS);

  await cacheAPIResponse(cacheKey, uniqueSites, 300);
  return uniqueSites;
}

/* ============================================================================
<<<<<<< HEAD
   ONION UPTIME CHECK (Tor2Web Gateway)
============================================================================ */

export async function checkOnionUptime(
  onion: string
): Promise<{
  status: 'online' | 'offline';
  responseTime?:  number;
  checkedAt:  string;
}> {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const proxy = TOR2WEB_PROXIES[0];
    const url = `https://${host}.${proxy}`;

    const start = Date.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

    const response = await fetch(url, {
      method: 'HEAD',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    clearTimeout(timeout);
=======
   ONION UPTIME (VERCEL SAFE)
============================================================================ */

export async function checkOnionUptime(onion: string) {
  if (typeof process !== 'undefined' && process.env && process.env.VERCEL) {
    return { status: 'offline', checkedAt: nowISO() };
  }

  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const url = `https://${host}.${TOR2WEB_PROXIES[0]}`;

    const start = Date.now();
    const res = await fetchWithTimeout(
      url,
      { method: 'HEAD', headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.UPTIME_CHECK
    );
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055

    return {
      status: response.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      httpStatus: res.status,
      checkedAt: nowISO(),
    };
<<<<<<< HEAD
  } catch (error) {
    return {
      status: 'offline',
      checkedAt: nowISO(),
    };
=======
  } catch {
    return { status: 'offline', checkedAt: nowISO() };
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  }
}

/* ============================================================================
<<<<<<< HEAD
   PASTE & LEAK SIGNAL MONITORING
============================================================================ */

// Pastebin Recent Pastes
async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const response = await fetch('https://pastebin.com/archive', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });
=======
   TELEGRAM SEARCH
============================================================================ */

export async function searchTelegramChannels(query: string): Promise<TelegramChannel[]> {
  const cacheKey = `telegram:channels:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const channels: TelegramChannel[] = [];

  try {
    const res = await fetchWithTimeout(
      `https://telemetr.io/en/channels/search?query=${encodeURIComponent(query)}`,
      { headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.TELEGRAM_SCAN
    );
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055

    if (!response. ok) return [];

<<<<<<< HEAD
    const html = await response.text();

    // Extract paste links and titles
    const pasteMatches = Array.from(
      html.matchAll(/<a href="\/([A-Za-z0-9]{8})"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 50);

    pasteMatches. forEach(([_, pasteId, title]) => {
      const cleanTitle = stripHtml(title);
      if (cleanTitle. toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `pb-${pasteId}`,
          title: cleanTitle,
          indicator,
          source: 'pastebin',
          timestamp: nowISO(),
          url: `https://pastebin.com/${pasteId}`,
          context: 'Paste title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Pastebin scan error:', error);
=======
    const html = await res.text();
    const matches = Array.from(
      html.matchAll(
        /<a href="\/en\/channels\/([^"]+)"[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<div class="subscribers[^"]*">([^<]+)<\/div>[\s\S]*?<p[^>]*>([^<]+)<\/p>/g
      )
    );

    for (const m of matches.slice(0, MAX_RESULTS.TELEGRAM_CHANNELS)) {
      const username = m[1].replace('@', '');
      const title = stripHtml(m[2]);
      const subs = parseInt(m[3].replace(/\D/g, '')) || 0;
      const desc = stripHtml(m[4]);
      const ctx = `${title} ${desc}`;

      channels.push({
        id: `tg-${username}`,
        username,
        title,
        description: desc,
        subscribers: subs,
        category: categorize(ctx),
        riskLevel: calculateRisk(ctx),
        verified: title.includes('✓'),
        tags: extractTags(ctx),
      });
    }

    await cacheAPIResponse(cacheKey, channels, 180);
    return channels;
  } catch {
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
    return [];
  }
}

<<<<<<< HEAD
// Psbdmp - Pastebin dump search
async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    const response = await fetch(`https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    if (!response.ok) return [];

    const data = await response.json();

    if (data.data && Array.isArray(data.data)) {
      data.data.slice(0, 20).forEach((paste:  any) => {
        signals.push({
          id: `psbdmp-${paste. id}`,
          title: paste.text || 'Pastebin dump',
          indicator,
          source: 'psbdmp',
          timestamp: paste.time || nowISO(),
          url: `https://pastebin.com/${paste.id}`,
          context: 'Dump search match',
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Psbdmp scan error:', error);
    return [];
  }
}

// GitHub Gists
async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `gists:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals: LeakSignal[] = [];

  try {
    // Using GitHub's public search API
    const response = await fetch(
      `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file+language:text`,
      {
        headers: {
          'Accept': 'application/vnd. github.v3+json',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      }
    );

    if (!response.ok) return [];

    const data = await response.json();

    if (data.items) {
      data.items.slice(0, 20).forEach((item: any) => {
        signals.push({
          id: `gist-${item.sha}`,
          title: item.name || 'GitHub code match',
          indicator,
          source: 'github_gist',
          timestamp: nowISO(),
          url: item.html_url,
          context: `Found in ${item.repository.full_name}`,
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('GitHub Gist scan error:', error);
    return [];
  }
}

// Rentry public notes
async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const signals:  LeakSignal[] = [];

  try {
    const response = await fetch(
      `https://rentry.co/api/search? q=${encodeURIComponent(indicator)}`,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        },
      }
    );

    if (!response. ok) return [];

    const data = await response.json();

    if (data.results && Array.isArray(data.results)) {
      data.results. slice(0, 20).forEach((result: any) => {
        signals.push({
          id: `rentry-${result.id}`,
          title: result.title || 'Rentry note',
          indicator,
          source: 'rentry',
          timestamp: result.created_at || nowISO(),
          url: `https://rentry.co/${result.id}`,
          context: 'Public note match',
        });
      });
    }

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Rentry scan error:', error);
    return [];
  }
}

// Ghostbin
async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
=======
/* ============================================================================
   TELEGRAM MESSAGE SCRAPE
============================================================================ */

export async function scrapeTelegramChannel(
  channelUsername: string,
  limit = 25
): Promise<TelegramMessage[]> {
  const cacheKey = `telegram:messages:${channelUsername}`;
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const messages: TelegramMessage[] = [];

  try {
<<<<<<< HEAD
    const response = await fetch('https://ghostbin.com/browse', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });
=======
    const res = await fetchWithTimeout(
      `https://t.me/s/${channelUsername.replace('@', '')}`,
      { headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.TELEGRAM_SCAN
    );
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055

    if (!response. ok) return [];

<<<<<<< HEAD
    const html = await response.text();

    const pasteMatches = Array.from(
      html.matchAll(/<a href="\/paste\/([A-Za-z0-9]+)"[^>]*>([^<]+)<\/a>/g)
    ).slice(0, 30);

    pasteMatches. forEach(([_, pasteId, title]) => {
      const cleanTitle = stripHtml(title);
      if (cleanTitle.toLowerCase().includes(indicator.toLowerCase())) {
        signals.push({
          id: `gb-${pasteId}`,
          title: cleanTitle,
          indicator,
          source: 'ghostbin',
          timestamp: nowISO(),
          url: `https://ghostbin.com/paste/${pasteId}`,
          context: 'Ghostbin title match',
        });
      }
    });

    await cacheAPIResponse(cacheKey, signals, 30);
    return signals;
  } catch (error) {
    console.error('Ghostbin scan error:', error);
=======
    const html = await res.text();

    const matches = Array.from(
      html.matchAll(
        /data-post="[^/]+\/(\d+)"[\s\S]*?<div class="tgme_widget_message_text[^"]*">([\s\S]*?)<\/div>[\s\S]*?<time datetime="([^"]+)"[\s\S]*?(?:<span class="tgme_widget_message_views">([^<]*)<\/span>)?/g
      )
    );

    for (const m of matches.slice(0, limit)) {
      messages.push({
        id: `tg-${channelUsername}-${m[1]}`,
        channelUsername,
        messageId: parseInt(m[1], 10),
        text: stripHtml(m[2]),
        date: m[3],
        views: parseInt((m[4] || '').replace(/\D/g, ''), 10) || 0,
        forwards: 0,
        hasMedia: /tgme_widget_message_(photo|video)/.test(m[0]),
        link: `https://t.me/${channelUsername}/${m[1]}`,
      });
    }

    await cacheAPIResponse(cacheKey, messages, 60);
    return messages;
  } catch {
    return [];
  }
}

/* ============================================================================
   TELEGRAM INDICATOR SCAN
============================================================================ */

async function scanTelegramMessages(indicator: string): Promise<LeakSignal[]> {
  const signals: LeakSignal[] = [];

  try {
    const channels = await searchTelegramChannels(indicator);

    for (const ch of channels.slice(0, 3)) {
      const msgs = await scrapeTelegramChannel(ch.username, 10);

      for (const msg of msgs) {
        if (msg.text.toLowerCase().includes(indicator.toLowerCase())) {
          signals.push({
            id: msg.id,
            title: msg.text.slice(0, 120),
            indicator,
            source: 'telegram',
            timestamp: msg.date,
            url: msg.link,
            context: `@${ch.username}`,
            metadata: {
              channelName: ch.title,
              subscribers: ch.subscribers,
              views: msg.views,
              emails: extractEmails(msg.text),
              bitcoins: extractBitcoinAddresses(msg.text),
            },
          });
        }
      }
    }
  } catch {}

  return signals;
}

/* ============================================================================
   PSBDMP
============================================================================ */

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `${INTEL_APIS.psbdmp}${encodeURIComponent(indicator)}`,
      { headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.API_CALL
    );

    if (!res.ok) return [];

    const data = await res.json();
    const signals = (data.data || []).slice(0, 15).map((p: any) => ({
      id: `psbdmp-${p.id}`,
      title: p.text || 'Pastebin dump',
      indicator,
      source: 'psbdmp',
      timestamp: p.time || nowISO(),
      url: `https://pastebin.com/${p.id}`,
      context: 'PSBDMP dump',
      metadata: { pasteId: p.id, author: p.author },
    }));

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

/* ============================================================================
   RENTRY
============================================================================ */

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `${INTEL_APIS.rentry}${encodeURIComponent(indicator)}`,
      { headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.API_CALL
    );

    if (!res.ok) return [];

    const data = await res.json();
    const signals = (data.results || []).slice(0, 15).map((r: any) => ({
      id: `rentry-${r.id}`,
      title: r.title || 'Rentry note',
      indicator,
      source: 'rentry',
      timestamp: r.created_at || nowISO(),
      url: `https://rentry.co/${r.id}`,
      context: 'Rentry note',
      metadata: { pasteId: r.id, author: r.author },
    }));

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

/* ============================================================================
   GITHUB SEARCH
============================================================================ */

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `github:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `${INTEL_APIS.github}${encodeURIComponent(indicator)}+in:file&per_page=${MAX_RESULTS.GITHUB}`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': USER_AGENT,
        },
      },
      TIMEOUTS.API_CALL
    );

    if (!res.ok) return [];

    const data = await res.json();
    const signals = (data.items || []).map((i: any) => ({
      id: `gh-${i.sha}`,
      title: i.name || 'GitHub code',
      indicator,
      source: 'github_gist',
      timestamp: nowISO(),
      url: i.html_url,
      context: i.repository?.full_name || 'unknown',
      metadata: { author: i.repository?.owner?.login },
    }));

    await cacheAPIResponse(cacheKey, signals, 180);
    return signals;
  } catch {
    return [];
  }
}

/* ============================================================================
   PASTEBIN ARCHIVE
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      'https://pastebin.com/archive',
      { headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.PASTE_SCAN
    );

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(
      html.matchAll(/href="\/([A-Za-z0-9]{8})">([^<]+)<\/a>/g)
    );

    return matches
      .filter(m => stripHtml(m[2]).toLowerCase().includes(indicator.toLowerCase()))
      .slice(0, MAX_RESULTS.PASTES)
      .map(m => ({
        id: `pb-${m[1]}`,
        title: stripHtml(m[2]),
        indicator,
        source: 'pastebin',
        timestamp: nowISO(),
        url: `https://pastebin.com/${m[1]}`,
        context: 'Pastebin',
        metadata: { pasteId: m[1] },
      }));
  } catch {
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
    return [];
  }
}

/* ============================================================================
   AGGREGATOR - COMBINE ALL SOURCES
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
<<<<<<< HEAD
  const cacheKey = `signals:${indicator}`;
=======
  const cacheKey = `signals:all:${indicator}`;
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
<<<<<<< HEAD
      scanPastebin(indicator),
      scanPsbdmp(indicator),
      scanGitHubGists(indicator),
      scanRentry(indicator),
      scanGhostbin(indicator),
    ])
  )
    .filter((result): result is PromiseFulfilledResult<LeakSignal[]> => result.status === 'fulfilled')
    .flatMap(result => result.value);
=======
      scanPsbdmp(indicator),
      scanRentry(indicator),
      scanGitHubGists(indicator),
      scanPastebin(indicator),
      scanTelegramMessages(indicator),
    ])
  )
    .filter((r): r is PromiseFulfilledResult<LeakSignal[]> => r.status === 'fulfilled')
    .flatMap(r => r.value);
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055

  const uniqueResults = Array.from(new Map(results.map(s => [s.id, s])).values());

  await cacheAPIResponse(cacheKey, uniqueResults, 90);
  return uniqueResults;
}

/* ============================================================================
<<<<<<< HEAD
   ADDITIONAL:  DARKNET MARKET STATUS CHECKER
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<Array<{
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  lastChecked: string;
}>> {
  // Using public Tor status checkers like dark. fail
  try {
    const response = await fetch('https://dark.fail/', {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      },
    });

    if (!response.ok) return [];

    const html = await response.text();
    const markets:  Array<{ name: string; url: string; status: 'online' | 'offline' | 'unknown'; lastChecked: string }> = [];

    // Parse dark.fail HTML for market status
    const marketMatches = Array.from(
      html.matchAll(/<div class="market"[^>]*>.*?<h3>([^<]+)<\/h3>.*?<code>([^<]+)<\/code>.*?<span class="status ([^"]+)">/gs)
    );

    marketMatches.forEach(([_, name, url, status]) => {
      markets.push({
        name: stripHtml(name),
        url: stripHtml(url),
        status:  status. includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    return markets;
  } catch (error) {
    console.error('Market status check error:', error);
=======
   DARK.FAIL
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<DarkWebMarket[]> {
  const cacheKey = 'darknet:markets';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      'https://dark.fail/',
      { headers: { 'User-Agent': USER_AGENT } },
      TIMEOUTS.ONION_DISCOVERY
    );

    if (!res.ok) return [];

    const html = await res.text();
    const markets: DarkWebMarket[] = [];

    const matches = Array.from(
      html.matchAll(
        /<div[^>]*class="[^"]*market[^"]*"[^>]*>[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<code[^>]*>([^<]+)<\/code>[\s\S]*?<span[^>]*class="[^"]*status[^"]*([^"]*)"[^>]*>/g
      )
    );

    for (const m of matches) {
      const name = stripHtml(m[1]);
      const url = stripHtml(m[2]);
      const status =
        m[3].includes('online')
          ? 'online'
          : m[3].includes('offline')
          ? 'offline'
          : 'unknown';

      markets.push({
        name,
        url,
        status,
        lastChecked: nowISO(),
      });
    }

    await cacheAPIResponse(cacheKey, markets, 300);
    return markets;
  } catch {
>>>>>>> 67fafda40324cc9a6bd6884a9e025dba2a448055
    return [];
  }
}
