
// ============================================================================
// torService.ts
// ADVANCED Dark Web Intelligence — Multi-Tool Integration
// Combines: TorBot, DarkScrape, FreshOnions, Onioff, TorCrawl concepts
// SERVER-SAFE | VERCEL-READY | NO TOR DAEMON REQUIRED
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

/* ============================================================================
   TYPES
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface OnionSite {
  url: string;
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
    | 'telegram'
    | 'onionland'
    | 'ahmia'
    | 'torbot'
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
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = ['onion.ws', 'onion.pet', 'onion.ly'];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BITCOIN_REGEX =
  /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b/g;
const SSH_FINGERPRINT_REGEX = /([0-9a-f]{2}:){15}[0-9a-f]{2}/gi;

const TIMEOUTS = {
  ONION_DISCOVERY: 8000,
  PASTE_SCAN: 5000,
  UPTIME_CHECK: 10000,
  TELEGRAM_SCAN: 7000,
  DEEP_SCAN: 12000,
};

const MAX_RESULTS = {
  ONIONS: 30,
  TELEGRAM_CHANNELS: 20,
  TELEGRAM_MESSAGES: 25,
  PASTES: 20,
};

/**
 * NOTE:
 * Torch (.onion) CANNOT be fetched on Vercel.
 * We keep it for attribution but do NOT fetch it.
 */
const TOR_SEARCH_ENGINES = [
  { name: 'ahmia', type: 'clearnet', url: 'https://ahmia.fi/search/?q=' },
  {
    name: 'onionland',
    type: 'clearnet',
    url: 'https://onionlandsearchengine.net/search?q=',
  },
  {
    name: 'torch',
    type: 'onion',
    url: 'http://torch.onion/search?q=',
  },
] as const;

/* ============================================================================
   UTILITIES
============================================================================ */

function stripHtml(input: string): string {
  if (!input) return '';
  return input.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

function nowISO(): string {
  return new Date().toISOString();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 5000
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(id);
  }
}

/* ============================================================================
   ADVANCED EXTRACTION (TorBot / TorCrawl)
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
  const samples: Record<string, RegExp> = {
    en: /\b(the|and|is|in|to|of|for|with|on|at)\b/gi,
    ru: /[а-яА-ЯёЁ]{3,}/g,
    zh: /[\u4e00-\u9fff]{2,}/g,
    es: /\b(el|la|de|en|y|que|es|por|para)\b/gi,
    fr: /\b(le|la|de|et|est|pour|dans|avec)\b/gi,
    de: /\b(der|die|das|und|ist|in|zu|den|mit)\b/gi,
  };

  let best = 'unknown';
  let max = 0;

  for (const [lang, rx] of Object.entries(samples)) {
    const count = (text.match(rx) || []).length;
    if (count > max) {
      max = count;
      best = lang;
    }
  }

  return best;
}

/* ============================================================================
   RISK / TAGGING
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();

  if (
    ['malware', 'exploit', 'ransomware', 'weapon', 'drugs', 'csam', 'hitman'].some(
      k => t.includes(k)
    )
  )
    return 'critical';

  if (
    ['leak', 'dump', 'database', 'breach', 'credentials', 'cvv', 'fullz'].some(
      k => t.includes(k)
    )
  )
    return 'high';

  if (
    ['market', 'forum', 'selling', 'phishing', 'carding', 'fraud'].some(k =>
      t.includes(k)
    )
  )
    return 'medium';

  return 'low';
}

function extractTags(text: string): string[] {
  const keys = [
    'market',
    'forum',
    'leak',
    'dump',
    'malware',
    'exploit',
    'phishing',
    'carding',
    'fraud',
    'bitcoin',
    'crypto',
  ];
  const t = text.toLowerCase();
  return keys.filter(k => t.includes(k)).slice(0, 8);
}

function categorize(text: string): string {
  const t = text.toLowerCase();
  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
  if (t.includes('leak') || t.includes('dump')) return 'Data Leak';
  if (t.includes('bitcoin') || t.includes('wallet')) return 'Cryptocurrency';
  if (t.includes('vpn') || t.includes('hosting')) return 'Hosting';
  return 'Unknown';
}

/* ============================================================================
   MULTI-ENGINE ONION DISCOVERY
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:multi:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const collected: OnionSite[] = [];

  for (const engine of TOR_SEARCH_ENGINES) {
    if (engine.type === 'onion') continue; // cannot fetch on Vercel

    try {
      const res = await fetchWithTimeout(
        engine.url + encodeURIComponent(query),
        { headers: { 'User-Agent': 'Mozilla/5.0' } },
        TIMEOUTS.ONION_DISCOVERY
      );
      if (!res.ok) continue;

      const html = await res.text();
      const onions = unique(html.match(ONION_REGEX) || []);

      onions.forEach(onion => {
        const context = html.slice(
          Math.max(0, html.indexOf(onion) - 200),
          html.indexOf(onion) + 200
        );

        const full = stripHtml(context);

        collected.push({
          url: onion,
          title: 'Unknown Onion Service',
          description: 'Discovered via search engine',
          category: categorize(full),
          riskLevel: calculateRisk(full),
          lastSeen: nowISO(),
          status: 'unknown',
          tags: extractTags(full),
          discoveredFrom: engine.name,
          emailAddresses: extractEmails(full),
          bitcoinAddresses: extractBitcoinAddresses(full),
          sshFingerprint: extractSSHFingerprints(full)[0],
          language: detectLanguage(full),
        });
      });
    } catch {}
  }

  const uniqueSites = Array.from(
    new Map(collected.map(s => [s.url, s])).values()
  ).slice(0, MAX_RESULTS.ONIONS);

  await cacheAPIResponse(cacheKey, uniqueSites, 300);
  return uniqueSites;
}

/* ============================================================================
   DEEP ONION SCAN
============================================================================ */

export async function deepScanOnion(onion: string): Promise<OnionSite | null> {
  const cacheKey = `onion:deep:${onion}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const url = `https://${host}.${TOR2WEB_PROXIES[0]}`;

    const res = await fetchWithTimeout(
      url,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.DEEP_SCAN
    );
    if (!res.ok) return null;

    const html = await res.text();
    const text = stripHtml(html);

    const site: OnionSite = {
      url: onion,
      title: 'Deep Scanned Onion',
      description: text.slice(0, 200),
      category: categorize(text),
      riskLevel: calculateRisk(text),
      lastSeen: nowISO(),
      status: 'online',
      tags: extractTags(text),
      discoveredFrom: 'deep_scan',
      emailAddresses: extractEmails(text),
      bitcoinAddresses: extractBitcoinAddresses(text),
      sshFingerprint: extractSSHFingerprints(text)[0],
      language: detectLanguage(text),
    };

    await cacheAPIResponse(cacheKey, site, 600);
    return site;
  } catch {
    return null;
  }
}

/* ============================================================================
   ONION UPTIME (Onioff-style)
============================================================================ */

export async function checkOnionUptime(onion: string) {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const url = `https://${host}.${TOR2WEB_PROXIES[0]}`;
    const start = Date.now();

    const res = await fetchWithTimeout(
      url,
      { method: 'HEAD', headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.UPTIME_CHECK
    );

    return {
      status: res.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      httpStatus: res.status,
      checkedAt: nowISO(),
    };
  } catch {
    return { status: 'offline', checkedAt: nowISO() };
  }
}

/* ============================================================================
   TELEGRAM OSINT
============================================================================ */

export async function searchTelegramChannels(
  query: string
): Promise<TelegramChannel[]> {
  const cacheKey = `telegram:channels:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const channels: TelegramChannel[] = [];

  try {
    const res = await fetchWithTimeout(
      `https://telemetr.io/en/channels/search?query=${encodeURIComponent(query)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.TELEGRAM_SCAN
    );
    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(
      html.matchAll(
        /\/channels\/([^"]+)[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<div class="subscribers">([^<]+)<\/div>[\s\S]*?<p[^>]*>([^<]+)<\/p>/g
      )
    );

    matches.slice(0, MAX_RESULTS.TELEGRAM_CHANNELS).forEach(m => {
      const username = m[1];
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
        verified: false,
        tags: extractTags(ctx),
      });
    });

    await cacheAPIResponse(cacheKey, channels, 180);
    return channels;
  } catch {
    return [];
  }
}

/* ============================================================================
   TELEGRAM MESSAGE SCAN
============================================================================ */

export async function scrapeTelegramChannel(
  username: string,
  limit = 25
): Promise<TelegramMessage[]> {
  const cacheKey = `telegram:messages:${username}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const messages: TelegramMessage[] = [];

  try {
    const res = await fetchWithTimeout(
      `https://t.me/s/${username}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.TELEGRAM_SCAN
    );
    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(
      html.matchAll(
        /data-post="[^\/]+\/(\d+)"[\s\S]*?<div class="tgme_widget_message_text[^"]*">([\s\S]*?)<\/div>[\s\S]*?<time datetime="([^"]+)"/g
      )
    );

    matches.slice(0, limit).forEach(m => {
      messages.push({
        id: `tg-${username}-${m[1]}`,
        channelUsername: username,
        messageId: Number(m[1]),
        text: stripHtml(m[2]),
        date: m[3],
        views: 0,
        forwards: 0,
        hasMedia: /photo|video/.test(m[0]),
        link: `https://t.me/${username}/${m[1]}`,
      });
    });

    await cacheAPIResponse(cacheKey, messages, 60);
    return messages;
  } catch {
    return [];
  }
}

/* ============================================================================
   AGGREGATOR
============================================================================ */

export async function searchDarkWebSignals(
  indicator: string
): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
      scanTelegramMessages(indicator),
      scanPastebin(indicator),
      scanPsbdmp(indicator),
      scanGitHubGists(indicator),
      scanRentry(indicator),
      scanGhostbin(indicator),
    ])
  )
    .filter(
      (r): r is PromiseFulfilledResult<LeakSignal[]> =>
        r.status === 'fulfilled'
    )
    .flatMap(r => r.value);

  await cacheAPIResponse(cacheKey, results, 90);
  return results;
}

/* ============================================================================
   MARKET STATUS
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<DarkWebMarket[]> {
  const cacheKey = 'darknet:markets';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      'https://dark.fail/',
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.ONION_DISCOVERY
    );
    if (!res.ok) return [];

    const html = await res.text();
    const markets: DarkWebMarket[] = [];

    Array.from(
      html.matchAll(
        /<h3>([^<]+)<\/h3>[\s\S]*?<code>([^<]+)<\/code>[\s\S]*?<span class="status ([^"]+)"/g
      )
    ).forEach(m => {
      markets.push({
        name: stripHtml(m[1]),
        url: stripHtml(m[2]),
        status: m[3].includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    await cacheAPIResponse(cacheKey, markets, 300);
    return markets;
  } catch {
    return [];
  }
}

/* ============================================================================
   INTERNAL TELEGRAM SCAN HELPER
============================================================================ */

async function scanTelegramMessages(
  indicator: string
): Promise<LeakSignal[]> {
  const signals: LeakSignal[] = [];
  const channels = await searchTelegramChannels(indicator);

  for (const ch of channels.slice(0, 3)) {
    const msgs = await scrapeTelegramChannel(ch.username, 10);

    msgs.forEach(msg => {
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
            emails: extractEmails(msg.text),
            bitcoins: extractBitcoinAddresses(msg.text),
          },
        });
      }
    });
  }

  return signals;
}

/* ============================================================================
   PASTE SOURCES
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const res = await fetchWithTimeout(
    'https://pastebin.com/archive',
    { headers: { 'User-Agent': 'Mozilla/5.0' } },
    TIMEOUTS.PASTE_SCAN
  );
  if (!res.ok) return [];

  const html = await res.text();
  const signals: LeakSignal[] = [];

  Array.from(
    html.matchAll(/href="\/([A-Za-z0-9]{8})">([^<]+)<\/a>/g)
  ).forEach(m => {
    if (m[2].toLowerCase().includes(indicator.toLowerCase())) {
      signals.push({
        id: `pb-${m[1]}`,
        title: stripHtml(m[2]),
        indicator,
        source: 'pastebin',
        timestamp: nowISO(),
        url: `https://pastebin.com/${m[1]}`,
        context: 'Pastebin archive',
      });
    }
  });

  return signals;
}

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      `https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );
    if (!res.ok) return [];

    const data = await res.json();
    return (data.data || []).slice(0, 10).map((p: any) => ({
      id: `psbdmp-${p.id}`,
      title: 'Paste dump',
      indicator,
      source: 'psbdmp',
      timestamp: p.time || nowISO(),
      url: `https://pastebin.com/${p.id}`,
      context: 'psbdmp',
    }));
  } catch {
    return [];
  }
}

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      `https://api.github.com/search/code?q=${encodeURIComponent(
        indicator
      )}+in:file`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'Mozilla/5.0',
        },
      },
      TIMEOUTS.PASTE_SCAN
    );
    if (!res.ok) return [];

    const data = await res.json();
    return (data.items || []).map((i: any) => ({
      id: `gh-${i.sha}`,
      title: i.name,
      indicator,
      source: 'github_gist',
      timestamp: nowISO(),
      url: i.html_url,
      context: i.repository?.full_name,
    }));
  } catch {
    return [];
  }
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      `https://rentry.co/api/search?q=${encodeURIComponent(indicator)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );
    if (!res.ok) return [];

    const data = await res.json();
    return (data.results || []).map((r: any) => ({
      id: `rentry-${r.id}`,
      title: r.title,
      indicator,
      source: 'rentry',
      timestamp: r.created_at || nowISO(),
      url: `https://rentry.co/${r.id}`,
      context: 'Rentry',
    }));
  } catch {
    return [];
  }
}

async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout(
      'https://ghostbin.com/browse',
      { headers: { 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.PASTE_SCAN
    );
    if (!res.ok) return [];

    const html = await res.text();
    return Array.from(
      html.matchAll(/href="\/paste\/([A-Za-z0-9]+)">([^<]+)<\/a>/g)
    )
      .filter(m => m[2].toLowerCase().includes(indicator.toLowerCase()))
      .map(m => ({
        id: `gb-${m[1]}`,
        title: stripHtml(m[2]),
        indicator,
        source: 'ghostbin',
        timestamp: nowISO(),
        url: `https://ghostbin.com/paste/${m[1]}`,
        context: 'Ghostbin',
      }));
  } catch {
    return [];
  }
}
