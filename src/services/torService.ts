// ============================================================================
// torService.ts
// REAL Dark Web Intelligence Engine
// ✔ Onion discovery (Ahmia)
// ✔ Onion uptime (Tor2Web)
// ✔ Paste monitoring (Pastebin, Psbdmp, Ghostbin, Rentry)
// ✔ GitHub Gist leakage
// ✔ Library of Leaks indexing + downloadable datasets
// ✔ Darknet market status
// ✔ Zero mock data
// ✔ OSINT-legal
// ✔ Vercel compatible
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
    | 'libraryofleaks'
    | 'intelx';
  timestamp: string;
  url: string;
  context: string;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const TOR2WEB_PROXIES = [
  'onion.ws',
  'onion.pet',
  'onion.ly',
];

const ONION_REGEX = /([a-z2-7]{16,56}\.onion)/gi;

/* ============================================================================
   UTILS
============================================================================ */

function nowISO(): string {
  return new Date().toISOString();
}

function stripHtml(input: string): string {
  return input.replace(/<[^>]*>/g, '').trim();
}

function unique<T>(arr: T[]): T[] {
  return Array.from(new Set(arr));
}

/* ============================================================================
   RISK ENGINE
============================================================================ */

function calculateRisk(text: string): RiskLevel {
  const t = text.toLowerCase();

  if (
    t.includes('child') ||
    t.includes('weapon') ||
    t.includes('exploit') ||
    t.includes('malware') ||
    t.includes('ransom')
  ) return 'critical';

  if (
    t.includes('leak') ||
    t.includes('dump') ||
    t.includes('breach') ||
    t.includes('database')
  ) return 'high';

  if (
    t.includes('market') ||
    t.includes('forum') ||
    t.includes('selling')
  ) return 'medium';

  return 'low';
}

function extractTags(text: string): string[] {
  const keys = [
    'leak','dump','breach','database','market','forum',
    'malware','exploit','credentials','phishing',
    'carding','fraud','drugs','weapons','ransomware'
  ];
  const lower = text.toLowerCase();
  return keys.filter(k => lower.includes(k)).slice(0, 6);
}

function categorize(text: string): string {
  const t = text.toLowerCase();
  if (t.includes('market')) return 'Marketplace';
  if (t.includes('forum')) return 'Forum';
  if (t.includes('leak') || t.includes('dump')) return 'Data Leak';
  if (t.includes('mail')) return 'Email Service';
  if (t.includes('hosting')) return 'Hosting';
  if (t.includes('directory')) return 'Directory';
  return 'Unknown';
}

/* ============================================================================
   ONION DISCOVERY — AHMIA
============================================================================ */

export async function discoverOnionSites(query: string): Promise<OnionSite[]> {
  const cacheKey = `onion:discover:${query}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: OnionSite[] = [];

  try {
    const res = await fetch(
      `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`,
      { headers: { 'User-Agent': 'Mozilla/5.0' } }
    );

    if (!res.ok) return [];

    const html = await res.text();
    const onions = unique(html.match(ONION_REGEX) || []).slice(0, 50);

    const titles = Array.from(
      html.matchAll(/<h4[^>]*><a[^>]*>([^<]+)<\/a><\/h4>/gi)
    ).map(m => stripHtml(m[1]));

    const descs = Array.from(
      html.matchAll(/<p class="result-[^"]*">([^<]+)<\/p>/gi)
    ).map(m => stripHtml(m[1]));

    onions.forEach((onion, i) => {
      const context = `${titles[i] || ''} ${descs[i] || ''}`.trim();
      results.push({
        url: onion,
        title: titles[i] || 'Unknown Onion Service',
        description: descs[i] || 'No description',
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
  } catch {
    return [];
  }
}

/* ============================================================================
   ONION UPTIME
============================================================================ */

export async function checkOnionUptime(onion: string) {
  try {
    const host = onion.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const url = `https://${host}.${TOR2WEB_PROXIES[0]}`;

    const start = Date.now();
    const res = await fetch(url, { method: 'HEAD' });

    return {
      status: res.ok ? 'online' : 'offline',
      responseTime: Date.now() - start,
      checkedAt: nowISO(),
    };
  } catch {
    return { status: 'offline', checkedAt: nowISO() };
  }
}

/* ============================================================================
   PASTE MONITORS
============================================================================ */

async function scanPastebin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `pastebin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const res = await fetch('https://pastebin.com/archive');
  if (!res.ok) return [];

  const html = await res.text();
  const signals: LeakSignal[] = [];

  Array.from(
    html.matchAll(/<a href="\/([A-Za-z0-9]{8})"[^>]*>([^<]+)<\/a>/g)
  ).forEach(([_, id, title]) => {
    if (title.toLowerCase().includes(indicator.toLowerCase())) {
      signals.push({
        id: `pb-${id}`,
        title: stripHtml(title),
        indicator,
        source: 'pastebin',
        timestamp: nowISO(),
        url: `https://pastebin.com/${id}`,
        context: 'Paste title match',
      });
    }
  });

  await cacheAPIResponse(cacheKey, signals, 30);
  return signals;
}

async function scanPsbdmp(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `psbdmp:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const res = await fetch(
    `https://psbdmp.ws/api/search/${encodeURIComponent(indicator)}`
  );
  if (!res.ok) return [];

  const data = await res.json();
  const signals: LeakSignal[] = [];

  (data?.data || []).forEach((p: any) => {
    signals.push({
      id: `ps-${p.id}`,
      title: 'Pastebin Dump',
      indicator,
      source: 'psbdmp',
      timestamp: p.time || nowISO(),
      url: `https://pastebin.com/${p.id}`,
      context: 'Dump index match',
    });
  });

  await cacheAPIResponse(cacheKey, signals, 30);
  return signals;
}

async function scanGhostbin(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `ghostbin:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const res = await fetch('https://ghostbin.com/browse');
  if (!res.ok) return [];

  const html = await res.text();
  const signals: LeakSignal[] = [];

  Array.from(
    html.matchAll(/<a href="\/paste\/([^"]+)">([^<]+)<\/a>/g)
  ).forEach(([_, id, title]) => {
    if (title.toLowerCase().includes(indicator.toLowerCase())) {
      signals.push({
        id: `gb-${id}`,
        title: stripHtml(title),
        indicator,
        source: 'ghostbin',
        timestamp: nowISO(),
        url: `https://ghostbin.com/paste/${id}`,
        context: 'Ghostbin title match',
      });
    }
  });

  await cacheAPIResponse(cacheKey, signals, 30);
  return signals;
}

async function scanRentry(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `rentry:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const res = await fetch(
    `https://rentry.co/api/search?q=${encodeURIComponent(indicator)}`
  );
  if (!res.ok) return [];

  const data = await res.json();
  const signals: LeakSignal[] = [];

  (data?.results || []).forEach((r: any) => {
    signals.push({
      id: `re-${r.id}`,
      title: r.title || 'Rentry Note',
      indicator,
      source: 'rentry',
      timestamp: r.created_at || nowISO(),
      url: `https://rentry.co/${r.id}`,
      context: 'Public note match',
    });
  });

  await cacheAPIResponse(cacheKey, signals, 30);
  return signals;
}

async function scanGitHubGists(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `gists:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const res = await fetch(
    `https://api.github.com/search/code?q=${encodeURIComponent(indicator)}+in:file`
  );
  if (!res.ok) return [];

  const data = await res.json();
  const signals: LeakSignal[] = [];

  (data.items || []).forEach((i: any) => {
    signals.push({
      id: `gh-${i.sha}`,
      title: i.name || 'GitHub Code Leak',
      indicator,
      source: 'github_gist',
      timestamp: nowISO(),
      url: i.html_url,
      context: `Repo: ${i.repository.full_name}`,
    });
  });

  await cacheAPIResponse(cacheKey, signals, 30);
  return signals;
}

/* ============================================================================
   LIBRARY OF LEAKS — REAL INDEX + DOWNLOADS
============================================================================ */

async function scanLibraryOfLeaks(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `lol:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const res = await fetch(
    `https://search.libraryofleaks.org/search?q=${encodeURIComponent(indicator)}`
  );
  if (!res.ok) return [];

  const html = await res.text();
  const signals: LeakSignal[] = [];

  Array.from(
    html.matchAll(/<a href="(\/download\/[^"]+)".*?>([^<]+)<\/a>/gi)
  ).forEach(([_, link, title]) => {
    signals.push({
      id: `lol-${link}`,
      title: stripHtml(title),
      indicator,
      source: 'libraryofleaks',
      timestamp: nowISO(),
      url: `https://search.libraryofleaks.org${link}`,
      context: 'Leak dataset (downloadable)',
    });
  });

  await cacheAPIResponse(cacheKey, signals, 60);
  return signals;
}

/* ============================================================================
   AGGREGATOR
============================================================================ */

export async function searchDarkWebSignals(indicator: string): Promise<LeakSignal[]> {
  const cacheKey = `signals:${indicator}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results = (
    await Promise.allSettled([
      scanPastebin(indicator),
      scanPsbdmp(indicator),
      scanGhostbin(indicator),
      scanRentry(indicator),
      scanGitHubGists(indicator),
      scanLibraryOfLeaks(indicator),
    ])
  )
    .filter((r): r is PromiseFulfilledResult<LeakSignal[]> => r.status === 'fulfilled')
    .flatMap(r => r.value);

  await cacheAPIResponse(cacheKey, results, 30);
  return results;
}

/* ============================================================================
   DARKNET MARKET STATUS (dark.fail)
============================================================================ */

export async function checkDarknetMarketStatus() {
  try {
    const res = await fetch('https://dark.fail/');
    if (!res.ok) return [];

    const html = await res.text();
    const markets: any[] = [];

    Array.from(
      html.matchAll(
        /<div class="market".*?<h3>([^<]+)<\/h3>.*?<code>([^<]+)<\/code>.*?<span class="status ([^"]+)"/gs
      )
    ).forEach(([_, name, url, status]) => {
      markets.push({
        name: stripHtml(name),
        url: stripHtml(url),
        status: status.includes('online') ? 'online' : 'offline',
        lastChecked: nowISO(),
      });
    });

    return markets;
  } catch {
    return [];
  }
}
