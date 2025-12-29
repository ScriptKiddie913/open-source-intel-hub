// ============================================================================
// torService.ts
// ADVANCED Dark Web Intelligence — Multi-Tool Integration
// Combines:  TorBot, DarkScrape, FreshOnions, Onioff, TorCrawl concepts
// + Intel Techniques APIs:  PSBDMP, Rentry, Pastebin, Ghostbin, GitHub
// + Telegram OSINT via Telemetr & t.me/s/
// + Dark. fail market status
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
  language?:  string;
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
    | 'paste_rs'
    | 'dpaste'
    | 'intelx';
  timestamp: string;
  url: string;
  context: string;
  metadata?:  {
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
  mediaType?:  string;
  link:  string;
}

export interface DarkWebMarket {
  name: string;
  url: string;
  status: 'online' | 'offline' | 'unknown';
  uptime?:  number;
  lastChecked: string;
  mirrors?: string[];
  v3Onion?: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = ['onion.ws', 'onion.pet', 'onion.ly'];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;
const EMAIL_REGEX = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const BITCOIN_REGEX = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bbc1[a-z0-9]{39,59}\b/g;
const SSH_FINGERPRINT_REGEX = /([0-9a-f]{2}: ){15}[0-9a-f]{2}/gi;

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
  GITHUB:  15,
};

const TOR_SEARCH_ENGINES = [
  { name: 'ahmia', type: 'clearnet', url: 'https://ahmia.fi/search/? q=' },
  { name: 'onionland', type: 'clearnet', url: 'https://onionlandsearchengine.net/search? q=' },
] as const;

const INTEL_APIS = {
  psbdmp: 'https://psbdmp.ws/api/search/',
  rentry: 'https://rentry.co/api/search? q=',
  github:  'https://api.github.com/search/code?q=',
} as const;

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
   EXTRACTION FUNCTIONS
============================================================================ */

function extractEmails(text: string): string[] {
  return unique((text. match(EMAIL_REGEX) || []).map(e => e.toLowerCase()));
}

function extractBitcoinAddresses(text: string): string[] {
  return unique(text.match(BITCOIN_REGEX) || []);
}

function extractSSHFingerprints(text:  string): string[] {
  return unique(text.match(SSH_FINGERPRINT_REGEX) || []);
}

function detectLanguage(text: string): string {
  const samples:  Record<string, RegExp> = {
    en: /\b(the|and|is|in|to|of|for|with|on|at)\b/gi,
    ru: /[а-яА-ЯёЁ]{3,}/g,
    zh: /[\u4e00-\u9fff]{2,}/g,
    es: /\b(el|la|de|en|y|que|es|por|para)\b/gi,
    fr:  /\b(le|la|de|et|est|pour|dans|avec)\b/gi,
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
   RISK SCORING & CATEGORIZATION
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();

  const criticalKeywords = [
    'malware', 'exploit', 'ransomware', 'weapon', 'drugs', 'csam',
    'cp', 'hitman', 'murder', 'bomb', 'terrorist'
  ];

  const highKeywords = [
    'leak', 'dump', 'database', 'breach', 'credentials', 'cvv',
    'fullz', 'combolist', 'credit card', 'ssn', 'passport'
  ];

  const mediumKeywords = [
    'market', 'forum', 'selling', 'phishing', 'carding', 'fraud',
    'vendor', 'escrow', 'btc', 'crypto'
  ];

  if (criticalKeywords.some(k => t.includes(k))) return 'critical';
  if (highKeywords.some(k => t.includes(k))) return 'high';
  if (mediumKeywords.some(k => t.includes(k))) return 'medium';

  return 'low';
}

function extractTags(text: string): string[] {
  const keywords = [
    'market', 'forum', 'leak', 'dump', 'database', 'malware', 'exploit',
    'credentials', 'phishing', 'carding', 'fraud', 'breach', 'ransomware',
    'combolist', 'cvv', 'fullz', 'vendor', 'escrow', 'crypto', 'bitcoin',
    'darknet', 'tor', 'vpn', 'hosting', 'email', 'ssh', 'api'
  ];

  const t = text.toLowerCase();
  return keywords.filter(k => t.includes(k)).slice(0, 10);
}

function categorize(text: string): string {
  const t = text.toLowerCase();

  if (t.includes('market') || t.includes('shop') || t.includes('vendor')) return 'Marketplace';
  if (t. includes('forum') || t.includes('board') || t.includes('discussion')) return 'Forum';
  if (t.includes('leak') || t.includes('dump') || t.includes('breach')) return 'Data Leak';
  if (t.includes('mail') || t.includes('email') || t.includes('webmail')) return 'Email Service';
  if (t.includes('hosting') || t.includes('vpn') || t.includes('proxy')) return 'Hosting/VPN';
  if (t.includes('directory') || t.includes('links') || t.includes('index')) return 'Directory';
  if (t.includes('wiki') || t.includes('info') || t.includes('knowledge')) return 'Wiki/Info';
  if (t. includes('channel') || t.includes('group') || t.includes('chat')) return 'Communication';
  if (t.includes('bitcoin') || t.includes('crypto') || t.includes('wallet')) return 'Cryptocurrency';
  if (t.includes('news') || t.includes('blog') || t.includes('article')) return 'News/Blog';
  if (t.includes('file') || t.includes('upload') || t.includes('storage')) return 'File Storage';

  return 'Unknown';
}

/* ============================================================================
   ONION DISCOVERY
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:multi:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const collected: OnionSite[] = [];

  for (const engine of TOR_SEARCH_ENGINES) {
    try {
      const res = await fetchWithTimeout(
        engine.url + encodeURIComponent(query),
        { headers: { 'User-Agent':  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } },
        TIMEOUTS.ONION_DISCOVERY
      );

      if (!res.ok) continue;

      const html = await res.text();
      const onions = unique(html.match(ONION_REGEX) || []);

      onions.forEach(onion => {
        const idx = html.indexOf(onion);
        const context = html.substring(Math.max(0, idx - 300), Math.min(html.length, idx + 300));
        const fullContext = stripHtml(context);

        collected.push({
          url: onion,
          title: 'Unknown Onion Service',
          description: 'Discovered via search engine',
          category: categorize(fullContext),
          riskLevel: calculateRisk(fullContext),
          lastSeen:  nowISO(),
          status: 'unknown',
          tags: extractTags(fullContext),
          discoveredFrom: engine.name,
          emailAddresses: extractEmails(fullContext),
          bitcoinAddresses: extractBitcoinAddresses(fullContext),
          sshFingerprint: extractSSHFingerprints(fullContext)[0],
          language: detectLanguage(fullContext),
        });
      });
    } catch (err) {
      console.error(`Error searching ${engine.name}:`, err);
    }
  }

  const uniqueSites = Array.from(
    new Map(collected.map(s => [s.url, s])).values()
  ).slice(0, MAX_RESULTS. ONIONS);

  await cacheAPIResponse(cacheKey, uniqueSites, 300);
  return uniqueSites;
}

export async function checkOnionUptime(onion: string): Promise<{
  status: 'online' | 'offline';
  responseTime?:  number;
  checkedAt:  string;
  httpStatus?:  number;
}> {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const url = `https://${host}. ${TOR2WEB_PROXIES[0]}`;

    const start = Date.now();
    const res = await fetchWithTimeout(url, { method: 'HEAD' }, TIMEOUTS.UPTIME_CHECK);

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

export async function searchTelegramChannels(query: string): Promise<TelegramChannel[]> {
  const cacheKey = `telegram:channels:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const channels: TelegramChannel[] = [];

  try {
    const url = `https://telemetr.io/en/channels/search?query=${encodeURIComponent(query)}`;
    const res = await fetchWithTimeout(url, { headers: { 'User-Agent':  'Mozilla/5.0' } }, TIMEOUTS.TELEGRAM_SCAN);

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(
      html.matchAll(/<a href="\/en\/channels\/([^"]+)"[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<div class="subscribers[^"]*">([^<]+)<\/div>[\s\S]*?<p[^>]*>([^<]+)<\/p>/g)
    );

    matches.slice(0, MAX_RESULTS.TELEGRAM_CHANNELS).forEach(match => {
      const username = match[1]. replace('@', '');
      const title = stripHtml(match[2]);
      const subs = parseInt(match[3]. replace(/\D/g, '')) || 0;
      const desc = stripHtml(match[4]);
      const ctx = `${title} ${desc}`;

      channels.push({
        id: `tg-${username}`,
        username,
        title,
        description:  desc,
        subscribers: subs,
        category:  categorize(ctx),
        riskLevel: calculateRisk(ctx),
        verified: title. includes('✓'),
        tags: extractTags(ctx),
      });
    });

    await cacheAPIResponse(cacheKey, channels, 180);
    return channels;
  } catch (err) {
    console.error('Telegram search error:', err);
    return [];
  }
}

export async function scrapeTelegramChannel(channelUsername: string, limit = 25): Promise<TelegramMessage[]> {
  const cacheKey = `telegram:messages:${channelUsername}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const messages: TelegramMessage[] = [];

  try {
    const url = `https://t.me/s/${channelUsername. replace('@', '')}`;
    const res = await fetchWithTimeout(url, { headers: { 'User-Agent':  'Mozilla/5.0' } }, TIMEOUTS.TELEGRAM_SCAN);

    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(
      html.matchAll(/data-post="[^/]+\/(\d+)"[\s\S]*? <div class="tgme_widget_message_text[^"]*">([\s\S]*?)<\/div>[\s\S]*? <time datetime="([^"]+)"[\s\S]*?(? : <span class="tgme_widget_message_views">([^<]*)<\/span>)?/g)
    );

    matches.slice(0, limit).forEach(m => {
      messages.push({
        id: `tg-${channelUsername}-${m[1]}`,
        channelUsername,
        messageId: parseInt(m[1]),
        text: stripHtml(m[2]),
        date: m[3],
        views: parseInt((m[4] || '').replace(/\D/g, '')) || 0,
        forwards: 0,
        hasMedia: /tgme_widget_message_(photo|video)/. test(m[0]),
        link: `https://t.me/${channelUsername}/${m[1]}`,
      });
    });

    await cacheAPIResponse(cacheKey, messages, 60);
    return messages;
  } catch (err) {
    console.error('Telegram scrape error:', err);
    return [];
  }
}

async function scanTelegramMessages(indicator: string): Promise<LeakSignal[]> {
  const signals: LeakSignal[] = [];

  try {
    const channels = await searchTelegramChannels(indicator);

    for (const ch of channels. slice(0, 3)) {
      const msgs = await scrapeTelegramChannel(ch.username, 10);

      msgs.forEach(msg => {
        if (msg.text.toLowerCase().includes(indicator.toLowerCase())) {
          signals.push({
            id: msg.id,
            title: msg.text. slice(0, 120),
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
      });
    }
  } catch (err) {
    console.error('Telegram scan error:', err);
  }

  return signals;
}

/* ============================================================================
   INTEL TECHNIQUES APIs
============================================================================ */

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(`${INTEL_APIS.psbdmp}${encodeURIComponent(indicator)}`, {}, TIMEOUTS.API_CALL);
    if (!res.ok) return [];

    const data = await res.json();
    const signals: LeakSignal[] = (data.data || []).slice(0, 15).map((paste: any) => ({
      id: `psbdmp-${paste. id}`,
      title: paste.text || 'Pastebin dump',
      indicator,
      source: 'psbdmp',
      timestamp: paste.time || nowISO(),
      url: `https://pastebin.com/${paste.id}`,
      context: 'PSBDMP dump',
      metadata: { pasteId: paste.id, author: paste.author },
    }));

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(`${INTEL_APIS.rentry}${encodeURIComponent(indicator)}`, {}, TIMEOUTS.API_CALL);
    if (!res.ok) return [];

    const data = await res.json();
    const signals: LeakSignal[] = (data.results || []).slice(0, 15).map((result: any) => ({
      id: `rentry-${result.id}`,
      title: result.title || 'Rentry note',
      indicator,
      source: 'rentry',
      timestamp: result.created_at || nowISO(),
      url: `https://rentry.co/${result.id}`,
      context: 'Rentry note',
      metadata: { pasteId: result.id, author: result.author },
    }));

    await cacheAPIResponse(cacheKey, signals, 120);
    return signals;
  } catch {
    return [];
  }
}

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `github:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout(
      `${INTEL_APIS.github}${encodeURIComponent(indicator)}+in:file&per_page=${MAX_RESULTS.GITHUB}`,
      { headers: { 'Accept': 'application/vnd. github.v3+json', 'User-Agent': 'Mozilla/5.0' } },
      TIMEOUTS.API_CALL
    );
    if (!res.ok) return [];

    const data = await res.json();
    const signals: LeakSignal[] = (data.items || []).map((item: any) => ({
      id: `gh-${item.sha}`,
      title: item.name || 'GitHub code',
      indicator,
      source: 'github_gist',
      timestamp: nowISO(),
      url: item.html_url,
      context: item.repository?.full_name || 'unknown',
      metadata: { author: item.repository?.owner?.login },
    }));

    await cacheAPIResponse(cacheKey, signals, 180);
    return signals;
  } catch {
    return [];
  }
}

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  try {
    const res = await fetchWithTimeout('https://pastebin.com/archive', {}, TIMEOUTS. PASTE_SCAN);
    if (!res.ok) return [];

    const html = await res.text();
    const matches = Array.from(html.matchAll(/href="\/([A-Za-z0-9]{8})">([^<]+)<\/a>/g));

    return matches
      .filter(m => stripHtml(m[2]).toLowerCase().includes(indicator.toLowerCase()))
      .slice(0, MAX_RESULTS. PASTES)
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
    return [];
  }
}

/* ============================================================================
   AGGREGATOR
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `signals:all:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
      scanPsbdmp(indicator),
      scanRentry(indicator),
      scanGitHubGists(indicator),
      scanPastebin(indicator),
      scanTelegramMessages(indicator),
    ])
  )
    .filter((r): r is PromiseFulfilledResult<LeakSignal[]> => r.status === 'fulfilled')
    .flatMap(r => r.value);

  const uniqueResults = Array.from(new Map(results.map(s => [s.id, s])).values());

  await cacheAPIResponse(cacheKey, uniqueResults, 90);
  return uniqueResults;
}

/* ============================================================================
   DARKNET MARKETS
============================================================================ */

export async function checkDarknetMarketStatus(): Promise<DarkWebMarket[]> {
  const cacheKey = 'darknet:markets';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetchWithTimeout('https://dark.fail/', {}, TIMEOUTS. ONION_DISCOVERY);
    if (!res.ok) return [];

    const html = await res.text();
    const markets:  DarkWebMarket[] = [];

    const matches = Array.from(
      html.matchAll(/<div[^>]*class="[^"]*market[^"]*"[^>]*>[\s\S]*?<h3[^>]*>([^<]+)<\/h3>[\s\S]*?<code[^>]*>([^<]+)<\/code>[\s\S]*?<span[^>]*class="[^"]*status[^"]*([^"]*)"[^>]*>/g)
    );

    matches.forEach(m => {
      const name = stripHtml(m[1]);
      const url = stripHtml(m[2]);
      const status = m[3]. includes('online') ? 'online' : m[3].includes('offline') ? 'offline' : 'unknown';

      markets.push({
        name,
        url,
        status:  status as 'online' | 'offline' | 'unknown',
        lastChecked: nowISO(),
      });
    });

    await cacheAPIResponse(cacheKey, markets, 300);
    return markets;
  } catch {
    return [];
  }
}
