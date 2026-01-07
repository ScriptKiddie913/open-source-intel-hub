// src/services/enhancedThreatService.ts
import { cacheAPIResponse, getCachedData } from '@/lib/database';

export interface LiveThreatPoint {
  id: string;
  lat: number;
  lon: number;
  country: string;
  city: string;
  threatType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  indicator: string;
  source: string;
  timestamp: string;
  count: number;
}

export interface DarkWebLeak {
  id: string;
  title: string;
  description: string;
  leakDate: string;
  affectedEntities: string[];
  dataTypes: string[];
  recordCount: number;
  source: string;
  sourceUrl?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface UsernameResult {
  platform: string;
  username: string;
  exists: boolean;
  url: string;
  profileData?: {
    displayName?: string;
    bio?: string;
    followers?: number;
    following?: number;
    posts?: number;
    verified?: boolean;
    profileImage?: string;
    joinDate?: string;
  };
  lastChecked: string;
}

// Enhanced real-time threat map data with better geolocation
export async function getEnhancedLiveThreatMap(): Promise<LiveThreatPoint[]> {
  const cacheKey = 'threats:enhanced:map';
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const points: LiveThreatPoint[] = [];
  const geoCache = new Map<string, { lat: number; lon: number; city: string; country: string }>();

  try {
    // Batch geolocation function with rate limiting
    const getGeo = async (ip: string) => {
      if (geoCache.has(ip)) return geoCache.get(ip);
      
      await new Promise(resolve => setTimeout(resolve, 100)); // Rate limit
      
      try {
        const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`);
        if (!response.ok) return null;
        
        const data = await response.json();
        if (data.status === 'success') {
          const geo = {
            country: data.country,
            city: data.city,
            lat: data.lat,
            lon: data.lon,
          };
          geoCache.set(ip, geo);
          return geo;
        }
      } catch {
        return null;
      }
      return null;
    };

    // Feodo Tracker (Botnet C2)
    try {
      const feodoResponse = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json');
      if (feodoResponse.ok) {
        const feodoData = await feodoResponse.json();
        const entries = Array.isArray(feodoData) ? feodoData : (feodoData.value || []);
        
        for (const item of entries) {
          const geo = await getGeo(item.ip_address);
          if (geo) {
            points.push({
              id: `feodo-${item.ip_address}`,
              lat: geo.lat,
              lon: geo.lon,
              country: geo.country,
              city: geo.city,
              threatType: 'Botnet C2',
              severity: 'critical',
              indicator: item.ip_address,
              source: 'Feodo Tracker',
              timestamp: item.first_seen,
              count: 1,
            });
          }
        }
      }
    } catch (e) {
      console.error('Feodo fetch error:', e);
    }

    // ThreatFox IOCs
    try {
      const threatfoxResponse = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'get_iocs', days: 1 }),
      });
      
      if (threatfoxResponse.ok) {
        const threatfoxData = await threatfoxResponse.json();
        
        for (const item of (threatfoxData.data || [])) {
          if (item.ioc_type === 'ip:port' || item.ioc_type === 'ip') {
            const ip = item.ioc.split(':')[0];
            const geo = await getGeo(ip);
            
            if (geo) {
              points.push({
                id: `threatfox-${item.id}`,
                lat: geo.lat,
                lon: geo.lon,
                country: geo.country,
                city: geo.city,
                threatType: item.threat_type || 'Malware',
                severity: item.confidence_level > 80 ? 'high' : 'medium',
                indicator: item.ioc,
                source: 'ThreatFox',
                timestamp: item.first_seen,
                count: 1,
              });
            }
          }
        }
      }
    } catch (e) {
      console.error('ThreatFox fetch error:', e);
    }

    // Aggregate duplicate locations
    const aggregated = new Map<string, LiveThreatPoint>();
    points.forEach(point => {
      const key = `${point.lat.toFixed(1)},${point.lon.toFixed(1)}`;
      if (aggregated.has(key)) {
        const existing = aggregated.get(key)!;
        existing.count++;
      } else {
        aggregated.set(key, { ...point });
      }
    });

    const result = Array.from(aggregated.values());
    await cacheAPIResponse(cacheKey, result, 5); // 5 min cache
    return result;
  } catch (error) {
    console.error('Enhanced threat map error:', error);
    return points;
  }
}

// Real Dark Web & Paste Site monitoring using multiple public sources
export async function scanDarkWebLeaks(query?: string): Promise<DarkWebLeak[]> {
  const cacheKey = `darkweb:${query || 'recent'}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const leaks: DarkWebLeak[] = [];
  const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

  console.log(`[DarkWeb Scan] Starting comprehensive scan for: ${query || 'recent leaks'}`);

  try {
    // 1. Have I Been Pwned pastes (for email queries)
    if (query && query.includes('@')) {
      try {
        const response = await fetch(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(query)}`, {
          headers: { 'User-Agent': 'OSINT-Platform', 'hibp-api-key': '' }
        });
        
        if (response.ok) {
          const pastes = await response.json();
          pastes.forEach((paste: any) => {
            leaks.push({
              id: `hibp-${paste.Id}`,
              title: paste.Title || 'Untitled Paste',
              description: `Found in ${paste.Source}`,
              leakDate: paste.Date,
              affectedEntities: [query],
              dataTypes: ['email', 'paste'],
              recordCount: paste.EmailCount || 1,
              source: paste.Source,
              sourceUrl: paste.Source === 'Pastebin' ? `https://pastebin.com/${paste.Id}` : undefined,
              severity: 'medium',
            });
          });
        }
      } catch (e) {
        console.error('[DarkWeb] HIBP error:', e);
      }
    }

    // 2. Psbdmp.ws - Pastebin dump search (real API)
    if (query) {
      try {
        const psbdmpUrl = `https://psbdmp.ws/api/v3/search/${encodeURIComponent(query)}`;
        const response = await fetch(`${CORS_PROXY}${encodeURIComponent(psbdmpUrl)}`);
        
        if (response.ok) {
          const data = await response.json();
          if (Array.isArray(data)) {
            data.slice(0, 20).forEach((paste: any) => {
              leaks.push({
                id: `psbdmp-${paste.id}`,
                title: `Paste containing "${query}"`,
                description: paste.text?.substring(0, 200) || 'Paste content found',
                leakDate: paste.time || new Date().toISOString(),
                affectedEntities: [query],
                dataTypes: ['paste', 'text'],
                recordCount: 1,
                source: 'Psbdmp',
                sourceUrl: `https://psbdmp.ws/dump/${paste.id}`,
                severity: 'medium',
              });
            });
          }
        }
      } catch (e) {
        console.error('[DarkWeb] Psbdmp error:', e);
      }
    }

    // 3. IntelX (Intelligence X) - Public search
    if (query) {
      try {
        const intelxUrl = `https://2.intelx.io/phonebook/search?term=${encodeURIComponent(query)}&maxresults=20&media=0&target=0&timeout=20`;
        const response = await fetch(intelxUrl, {
          headers: { 'x-key': '9df61df0-84f7-4dc7-b34c-8ccfb8646ace' } // Public demo key
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.selectors && Array.isArray(data.selectors)) {
            data.selectors.slice(0, 15).forEach((item: any, idx: number) => {
              leaks.push({
                id: `intelx-${idx}-${Date.now()}`,
                title: `IntelX: ${item.selectorvalue || query}`,
                description: `Found ${item.selectortypeh || 'data'} in intelligence database`,
                leakDate: item.date || new Date().toISOString(),
                affectedEntities: [item.selectorvalue || query],
                dataTypes: [item.selectortypeh || 'unknown'],
                recordCount: 1,
                source: 'Intelligence X',
                sourceUrl: `https://intelx.io/?s=${encodeURIComponent(query)}`,
                severity: item.bucket === 'pastes' ? 'high' : 'medium',
              });
            });
          }
        }
      } catch (e) {
        console.error('[DarkWeb] IntelX error:', e);
      }
    }

    // 4. Ahmia.fi - Dark web search engine (searches .onion sites)
    if (query) {
      try {
        const ahmiaUrl = `https://ahmia.fi/search/?q=${encodeURIComponent(query)}`;
        const response = await fetch(`${CORS_PROXY}${encodeURIComponent(ahmiaUrl)}`);
        
        if (response.ok) {
          const html = await response.text();
          // Parse search results
          const resultMatches = html.matchAll(/<h4><a href="([^"]+)"[^>]*>([^<]+)<\/a><\/h4>/g);
          let count = 0;
          
          for (const match of resultMatches) {
            if (count >= 15) break;
            const [, url, title] = match;
            
            leaks.push({
              id: `ahmia-${count}-${Date.now()}`,
              title: title.trim() || `Dark Web Result: ${query}`,
              description: `Found on dark web via Ahmia search`,
              leakDate: new Date().toISOString(),
              affectedEntities: [query],
              dataTypes: ['onion', 'darkweb'],
              recordCount: 1,
              source: 'Ahmia (Dark Web)',
              sourceUrl: url.includes('.onion') ? `https://ahmia.fi/search/?q=${encodeURIComponent(query)}` : url,
              severity: 'high',
            });
            count++;
          }
        }
      } catch (e) {
        console.error('[DarkWeb] Ahmia error:', e);
      }
    }

    // 5. DDoSecrets - Leak database search
    if (query) {
      try {
        const ddosUrl = `https://search.ddosecrets.com/api/search?q=${encodeURIComponent(query)}&limit=15`;
        const response = await fetch(`${CORS_PROXY}${encodeURIComponent(ddosUrl)}`);
        
        if (response.ok) {
          const data = await response.json();
          if (data.results && Array.isArray(data.results)) {
            data.results.forEach((item: any, idx: number) => {
              leaks.push({
                id: `ddos-${idx}-${Date.now()}`,
                title: item.title || `DDoSecrets: ${query}`,
                description: item.description || item.snippet || 'Leak data found',
                leakDate: item.date || new Date().toISOString(),
                affectedEntities: [query],
                dataTypes: ['leak', 'database'],
                recordCount: item.size || 1,
                source: 'DDoSecrets',
                sourceUrl: item.url || 'https://ddosecrets.com',
                severity: 'critical',
              });
            });
          }
        }
      } catch (e) {
        console.error('[DarkWeb] DDoSecrets error:', e);
      }
    }

    // 6. Ransomware.live - Recent ransomware victims
    try {
      const ransomUrl = 'https://api.ransomware.live/recentvictims';
      const response = await fetch(`${CORS_PROXY}${encodeURIComponent(ransomUrl)}`);
      
      if (response.ok) {
        const victims = await response.json();
        const filtered = query 
          ? victims.filter((v: any) => 
              v.victim?.toLowerCase().includes(query.toLowerCase()) ||
              v.group?.toLowerCase().includes(query.toLowerCase()) ||
              v.website?.toLowerCase().includes(query.toLowerCase())
            )
          : victims.slice(0, 20);
        
        filtered.slice(0, 15).forEach((victim: any) => {
          leaks.push({
            id: `ransomware-${victim.id || Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            title: `Ransomware Victim: ${victim.victim || 'Unknown'}`,
            description: `Attacked by ${victim.group || 'Unknown group'}. ${victim.description || ''}`,
            leakDate: victim.date || new Date().toISOString(),
            affectedEntities: [victim.victim, victim.website].filter(Boolean),
            dataTypes: ['ransomware', 'extortion'],
            recordCount: 1,
            source: `${victim.group || 'Ransomware'} (via ransomware.live)`,
            sourceUrl: victim.url || `https://ransomware.live/group/${victim.group}`,
            severity: 'critical',
          });
        });
      }
    } catch (e) {
      console.error('[DarkWeb] Ransomware.live error:', e);
    }

    // 7. RansomWatch - Ransomware group monitoring
    try {
      const ransomwatchUrl = 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json';
      const response = await fetch(ransomwatchUrl);
      
      if (response.ok) {
        const posts = await response.json();
        const filtered = query
          ? posts.filter((p: any) => 
              p.post_title?.toLowerCase().includes(query.toLowerCase()) ||
              p.group_name?.toLowerCase().includes(query.toLowerCase())
            )
          : posts.slice(0, 20);
        
        filtered.slice(0, 15).forEach((post: any) => {
          leaks.push({
            id: `ransomwatch-${post.post_title?.replace(/\s/g, '-') || Date.now()}`,
            title: post.post_title || 'Ransomware Post',
            description: `Posted by ${post.group_name || 'Unknown'} ransomware group`,
            leakDate: post.discovered || new Date().toISOString(),
            affectedEntities: [post.post_title].filter(Boolean),
            dataTypes: ['ransomware', 'leak_announcement'],
            recordCount: 1,
            source: `${post.group_name || 'Ransomware'} (via RansomWatch)`,
            sourceUrl: post.post_url || 'https://ransomwatch.telemetry.ltd',
            severity: 'critical',
          });
        });
      }
    } catch (e) {
      console.error('[DarkWeb] RansomWatch error:', e);
    }

    // 8. LeakIX - Exposed services and leaks
    if (query) {
      try {
        const leakixUrl = `https://leakix.net/api/services?q=${encodeURIComponent(query)}&page=0&scope=leak`;
        const response = await fetch(leakixUrl, {
          headers: { 'Accept': 'application/json' }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (Array.isArray(data)) {
            data.slice(0, 10).forEach((item: any) => {
              leaks.push({
                id: `leakix-${item.id || Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                title: `Exposed: ${item.host || item.ip || query}`,
                description: `${item.summary || 'Exposed service detected'}. Port: ${item.port || 'N/A'}`,
                leakDate: item.time || new Date().toISOString(),
                affectedEntities: [item.host, item.ip].filter(Boolean),
                dataTypes: ['exposure', item.protocol || 'service'],
                recordCount: 1,
                source: 'LeakIX',
                sourceUrl: `https://leakix.net/host/${item.ip || item.host}`,
                severity: item.severity === 'critical' ? 'critical' : 'high',
              });
            });
          }
        }
      } catch (e) {
        console.error('[DarkWeb] LeakIX error:', e);
      }
    }

    // 9. Breach Directory (breachdirectory.org)
    if (query && query.includes('@')) {
      try {
        const bdUrl = `https://breachdirectory.org/api/search?term=${encodeURIComponent(query)}`;
        const response = await fetch(`${CORS_PROXY}${encodeURIComponent(bdUrl)}`);
        
        if (response.ok) {
          const data = await response.json();
          if (data.result && Array.isArray(data.result)) {
            data.result.slice(0, 10).forEach((item: any, idx: number) => {
              leaks.push({
                id: `breachdir-${idx}-${Date.now()}`,
                title: `Breach: ${item.sources?.join(', ') || 'Unknown Source'}`,
                description: `Email found in ${item.sources?.length || 1} breaches`,
                leakDate: item.date || new Date().toISOString(),
                affectedEntities: [query],
                dataTypes: ['email', 'breach'],
                recordCount: 1,
                source: 'Breach Directory',
                sourceUrl: 'https://breachdirectory.org',
                severity: 'high',
              });
            });
          }
        }
      } catch (e) {
        console.error('[DarkWeb] Breach Directory error:', e);
      }
    }

    // 10. GitHub Gist search (for leaked credentials/data)
    if (query) {
      try {
        const gistUrl = `https://api.github.com/search/code?q=${encodeURIComponent(query)}+in:file&per_page=10`;
        const response = await fetch(gistUrl, {
          headers: { 'Accept': 'application/vnd.github.v3+json' }
        });
        
        if (response.ok) {
          const data = await response.json();
          if (data.items && Array.isArray(data.items)) {
            data.items.slice(0, 8).forEach((item: any) => {
              leaks.push({
                id: `github-${item.sha || Date.now()}`,
                title: `GitHub: ${item.name || item.path || 'Code match'}`,
                description: `Found in ${item.repository?.full_name || 'repository'}`,
                leakDate: new Date().toISOString(),
                affectedEntities: [query],
                dataTypes: ['code', 'github'],
                recordCount: 1,
                source: 'GitHub',
                sourceUrl: item.html_url,
                severity: 'medium',
              });
            });
          }
        }
      } catch (e) {
        console.error('[DarkWeb] GitHub search error:', e);
      }
    }

    console.log(`[DarkWeb Scan] Completed. Found ${leaks.length} results.`);
    
    if (leaks.length > 0) {
      await cacheAPIResponse(cacheKey, leaks, 30);
    }
    return leaks;
  } catch (error) {
    console.error('Dark web scan error:', error);
    return leaks;
  }
}

// Username enumeration across platforms with REAL verification
// Each platform has specific checks to confirm existence
const PLATFORMS = [
  // === Developer Platforms (Most Reliable - Public APIs) ===
  { 
    name: 'GitHub', 
    url: 'https://api.github.com/users/{username}', 
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://github.com/{username}'
  },
  {
    name: 'GitLab',
    url: 'https://gitlab.com/api/v4/users?username={username}',
    type: 'dev',
    checkType: 'json_array',
    profileUrl: 'https://gitlab.com/{username}'
  },
  {
    name: 'Bitbucket',
    url: 'https://api.bitbucket.org/2.0/users/{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://bitbucket.org/{username}'
  },
  {
    name: 'HackerNews',
    url: 'https://hacker-news.firebaseio.com/v0/user/{username}.json',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://news.ycombinator.com/user?id={username}'
  },
  {
    name: 'Dev.to',
    url: 'https://dev.to/api/users/by_username?url={username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://dev.to/{username}'
  },
  {
    name: 'npm',
    url: 'https://registry.npmjs.org/-/user/org.couchdb.user:{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://www.npmjs.com/~{username}'
  },
  {
    name: 'PyPI',
    url: 'https://pypi.org/user/{username}/',
    type: 'dev',
    checkType: 'status_code',
    profileUrl: 'https://pypi.org/user/{username}'
  },
  {
    name: 'DockerHub',
    url: 'https://hub.docker.com/v2/users/{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://hub.docker.com/u/{username}'
  },
  {
    name: 'Replit',
    url: 'https://replit.com/data/profiles/{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://replit.com/@{username}'
  },
  {
    name: 'Codeberg',
    url: 'https://codeberg.org/api/v1/users/{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://codeberg.org/{username}'
  },
  {
    name: 'SourceForge',
    url: 'https://sourceforge.net/u/{username}/profile/',
    type: 'dev',
    checkType: 'status_code',
    profileUrl: 'https://sourceforge.net/u/{username}'
  },
  {
    name: 'HackerRank',
    url: 'https://www.hackerrank.com/rest/contests/master/hackers/{username}/profile',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://hackerrank.com/{username}'
  },
  {
    name: 'LeetCode',
    url: 'https://leetcode.com/{username}/',
    type: 'dev',
    checkType: 'status_code',
    profileUrl: 'https://leetcode.com/{username}'
  },
  {
    name: 'Codeforces',
    url: 'https://codeforces.com/api/user.info?handles={username}',
    type: 'dev',
    checkType: 'json_status',
    statusField: 'status',
    successValue: 'OK',
    profileUrl: 'https://codeforces.com/profile/{username}'
  },
  
  // === Social Media ===
  { 
    name: 'Reddit', 
    url: 'https://www.reddit.com/user/{username}/about.json', 
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://reddit.com/user/{username}'
  },
  {
    name: 'Mastodon',
    url: 'https://mastodon.social/api/v1/accounts/lookup?acct={username}',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://mastodon.social/@{username}'
  },
  {
    name: 'Lemmy',
    url: 'https://lemmy.world/api/v3/user?username={username}',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://lemmy.world/u/{username}'
  },
  {
    name: 'Gravatar',
    url: 'https://en.gravatar.com/{username}.json',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://gravatar.com/{username}'
  },
  {
    name: 'About.me',
    url: 'https://about.me/api/v2/user/{username}',
    type: 'professional',
    checkType: 'json_api',
    profileUrl: 'https://about.me/{username}'
  },
  {
    name: 'Linktree',
    url: 'https://linktr.ee/{username}',
    type: 'social',
    checkType: 'status_code',
    profileUrl: 'https://linktr.ee/{username}'
  },
  
  // === Messaging & Communication ===
  {
    name: 'Telegram',
    url: 'https://t.me/{username}',
    type: 'messaging',
    checkType: 'html_pattern',
    existsPattern: 'tgme_page_title',
    notExistsPattern: 'tgme_page_error',
    profileUrl: 'https://t.me/{username}'
  },
  {
    name: 'Keybase',
    url: 'https://keybase.io/_/api/1.0/user/lookup.json?username={username}',
    type: 'security',
    checkType: 'json_status',
    statusField: 'status.code',
    successValue: 0,
    profileUrl: 'https://keybase.io/{username}'
  },
  {
    name: 'Signal',
    url: 'https://signal.me/#p/{username}',
    type: 'messaging',
    checkType: 'skip', // Cannot verify programmatically
    profileUrl: 'https://signal.me/#p/{username}'
  },
  
  // === Gaming ===
  {
    name: 'Steam',
    url: 'https://steamcommunity.com/id/{username}',
    type: 'gaming',
    checkType: 'html_pattern',
    existsPattern: 'actual_persona_name',
    notExistsPattern: 'The specified profile could not be found',
    profileUrl: 'https://steamcommunity.com/id/{username}'
  },
  {
    name: 'Lichess',
    url: 'https://lichess.org/api/user/{username}',
    type: 'gaming',
    checkType: 'json_api',
    profileUrl: 'https://lichess.org/@/{username}'
  },
  {
    name: 'Chess.com',
    url: 'https://api.chess.com/pub/player/{username}',
    type: 'gaming',
    checkType: 'json_api',
    profileUrl: 'https://chess.com/member/{username}'
  },
  {
    name: 'Roblox',
    url: 'https://users.roblox.com/v1/users/search?keyword={username}&limit=10',
    type: 'gaming',
    checkType: 'json_field',
    fieldPath: 'data',
    matchField: 'name',
    profileUrl: 'https://www.roblox.com/users/profile?username={username}'
  },
  {
    name: 'Minecraft',
    url: 'https://api.mojang.com/users/profiles/minecraft/{username}',
    type: 'gaming',
    checkType: 'json_api',
    profileUrl: 'https://namemc.com/profile/{username}'
  },
  {
    name: 'osu!',
    url: 'https://osu.ppy.sh/users/{username}',
    type: 'gaming',
    checkType: 'status_code',
    profileUrl: 'https://osu.ppy.sh/users/{username}'
  },
  {
    name: 'Speedrun.com',
    url: 'https://www.speedrun.com/api/v1/users/{username}',
    type: 'gaming',
    checkType: 'json_api',
    profileUrl: 'https://speedrun.com/user/{username}'
  },
  
  // === Media & Content ===
  {
    name: 'Imgur',
    url: 'https://api.imgur.com/account/v1/accounts/{username}?client_id=546c25a59c58ad7',
    type: 'media',
    checkType: 'json_api',
    profileUrl: 'https://imgur.com/user/{username}'
  },
  {
    name: 'Giphy',
    url: 'https://giphy.com/{username}',
    type: 'media',
    checkType: 'status_code',
    profileUrl: 'https://giphy.com/{username}'
  },
  {
    name: 'Flickr',
    url: 'https://www.flickr.com/people/{username}/',
    type: 'media',
    checkType: 'status_code',
    profileUrl: 'https://www.flickr.com/people/{username}'
  },
  {
    name: 'Vimeo',
    url: 'https://vimeo.com/{username}',
    type: 'media',
    checkType: 'status_code',
    profileUrl: 'https://vimeo.com/{username}'
  },
  {
    name: 'Mixcloud',
    url: 'https://api.mixcloud.com/{username}/',
    type: 'music',
    checkType: 'json_api',
    profileUrl: 'https://mixcloud.com/{username}'
  },
  {
    name: 'SoundCloud',
    url: 'https://soundcloud.com/{username}',
    type: 'music',
    checkType: 'status_code',
    profileUrl: 'https://soundcloud.com/{username}'
  },
  {
    name: 'Bandcamp',
    url: 'https://{username}.bandcamp.com',
    type: 'music',
    checkType: 'status_code',
    profileUrl: 'https://{username}.bandcamp.com'
  },
  
  // === Blogging & Writing ===
  {
    name: 'Medium',
    url: 'https://medium.com/@{username}',
    type: 'blogging',
    checkType: 'status_code',
    profileUrl: 'https://medium.com/@{username}'
  },
  {
    name: 'Substack',
    url: 'https://{username}.substack.com',
    type: 'blogging',
    checkType: 'status_code',
    profileUrl: 'https://{username}.substack.com'
  },
  {
    name: 'WordPress',
    url: 'https://{username}.wordpress.com',
    type: 'blogging',
    checkType: 'status_code',
    profileUrl: 'https://{username}.wordpress.com'
  },
  {
    name: 'Blogger',
    url: 'https://{username}.blogspot.com',
    type: 'blogging',
    checkType: 'status_code',
    profileUrl: 'https://{username}.blogspot.com'
  },
  {
    name: 'Hashnode',
    url: 'https://hashnode.com/@{username}',
    type: 'dev',
    checkType: 'status_code',
    profileUrl: 'https://hashnode.com/@{username}'
  },
  
  // === Education ===
  {
    name: 'Duolingo',
    url: 'https://www.duolingo.com/2017-06-30/users?username={username}',
    type: 'education',
    checkType: 'json_array',
    profileUrl: 'https://duolingo.com/profile/{username}'
  },
  {
    name: 'Khan Academy',
    url: 'https://www.khanacademy.org/profile/{username}',
    type: 'education',
    checkType: 'status_code',
    profileUrl: 'https://khanacademy.org/profile/{username}'
  },
  {
    name: 'Codecademy',
    url: 'https://www.codecademy.com/profiles/{username}',
    type: 'education',
    checkType: 'status_code',
    profileUrl: 'https://codecademy.com/profiles/{username}'
  },
  
  // === Art & Design ===
  {
    name: 'DeviantArt',
    url: 'https://www.deviantart.com/{username}',
    type: 'art',
    checkType: 'status_code',
    profileUrl: 'https://deviantart.com/{username}'
  },
  {
    name: 'ArtStation',
    url: 'https://www.artstation.com/users/{username}/profile',
    type: 'art',
    checkType: 'json_api',
    profileUrl: 'https://artstation.com/{username}'
  },
  {
    name: 'Dribbble',
    url: 'https://dribbble.com/{username}',
    type: 'art',
    checkType: 'status_code',
    profileUrl: 'https://dribbble.com/{username}'
  },
  {
    name: 'Behance',
    url: 'https://www.behance.net/{username}',
    type: 'art',
    checkType: 'status_code',
    profileUrl: 'https://behance.net/{username}'
  },
  {
    name: 'Pixiv',
    url: 'https://www.pixiv.net/users/{username}',
    type: 'art',
    checkType: 'status_code',
    profileUrl: 'https://pixiv.net/users/{username}'
  },
  
  // === Professional ===
  {
    name: 'Kaggle',
    url: 'https://www.kaggle.com/{username}',
    type: 'professional',
    checkType: 'status_code',
    profileUrl: 'https://kaggle.com/{username}'
  },
  {
    name: 'AngelList',
    url: 'https://angel.co/u/{username}',
    type: 'professional',
    checkType: 'status_code',
    profileUrl: 'https://angel.co/u/{username}'
  },
  {
    name: 'Crunchbase',
    url: 'https://www.crunchbase.com/person/{username}',
    type: 'professional',
    checkType: 'status_code',
    profileUrl: 'https://crunchbase.com/person/{username}'
  },
  {
    name: 'StackOverflow',
    url: 'https://stackoverflow.com/users/{username}',
    type: 'dev',
    checkType: 'status_code',
    profileUrl: 'https://stackoverflow.com/users/{username}'
  },
  
  // === Crypto & Finance ===
  {
    name: 'Keybase Crypto',
    url: 'https://keybase.io/{username}',
    type: 'crypto',
    checkType: 'status_code',
    profileUrl: 'https://keybase.io/{username}'
  },
  {
    name: 'OpenSea',
    url: 'https://opensea.io/{username}',
    type: 'crypto',
    checkType: 'status_code',
    profileUrl: 'https://opensea.io/{username}'
  },
  
  // === Forums & Communities ===
  {
    name: 'Hacker Forums',
    url: 'https://hackforums.net/member.php?action=profile&username={username}',
    type: 'security',
    checkType: 'status_code',
    profileUrl: 'https://hackforums.net/member.php?username={username}'
  },
  {
    name: 'XDA Developers',
    url: 'https://forum.xda-developers.com/m/{username}',
    type: 'dev',
    checkType: 'status_code',
    profileUrl: 'https://forum.xda-developers.com/m/{username}'
  },
];

const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

export async function enumerateUsername(username: string): Promise<UsernameResult[]> {
  const cacheKey = `username:${username}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: UsernameResult[] = [];
  const batchSize = 8; // Process 8 platforms at a time

  console.log(`[Username Enum] Starting comprehensive scan for: ${username} across ${PLATFORMS.length} platforms`);

  // Check platforms in batches
  for (let i = 0; i < PLATFORMS.length; i += batchSize) {
    const batch = PLATFORMS.slice(i, i + batchSize);
    
    await Promise.all(
      batch.map(async (platform) => {
        if (platform.checkType === 'skip') return;
        
        try {
          const url = platform.url.replace(/{username}/g, encodeURIComponent(username));
          const profileUrl = platform.profileUrl?.replace(/{username}/g, username) || url;
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 10000);
          
          let exists = false;
          let profileData: any = {};
          
          try {
            let response: Response | null = null;
            
            // Try direct fetch first
            try {
              response = await fetch(url, {
                method: 'GET',
                signal: controller.signal,
                headers: { 
                  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) OSINT-Hub/2.0',
                  'Accept': 'application/json, text/html, */*',
                },
              });
            } catch {
              // Try with CORS proxy for blocked requests
              try {
                response = await fetch(`${CORS_PROXY}${encodeURIComponent(url)}`, {
                  signal: controller.signal,
                });
              } catch {
                // Both failed
                response = null;
              }
            }
            
            clearTimeout(timeoutId);
            
            if (!response) return;
            
            // Handle different check types
            switch (platform.checkType) {
              case 'json_api': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    if (data && !data.error && !data.message?.includes('Not Found') && !data.errors) {
                      exists = true;
                      profileData = extractProfileData(data, platform.name);
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'json_array': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    if (Array.isArray(data) && data.length > 0) {
                      exists = true;
                      profileData = extractProfileData(data[0], platform.name);
                    } else if (data.users && data.users.length > 0) {
                      exists = true;
                      profileData = extractProfileData(data.users[0], platform.name);
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'json_status': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    const statusField = platform.statusField || 'status';
                    const statusValue = getNestedValue(data, statusField);
                    if (statusValue === platform.successValue) {
                      exists = true;
                      profileData = extractProfileData(data.them || data.result?.[0] || data, platform.name);
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'json_field': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    const fieldData = getNestedValue(data, platform.fieldPath || 'data');
                    if (Array.isArray(fieldData)) {
                      const match = fieldData.find((item: any) => 
                        item[platform.matchField || 'name']?.toLowerCase() === username.toLowerCase()
                      );
                      if (match) {
                        exists = true;
                        profileData = extractProfileData(match, platform.name);
                      }
                    }
                  } catch { /* JSON parse failed */ }
                }
                break;
              }
              
              case 'status_code': {
                // Simply check if the page returns 200 OK
                if (response.ok && response.status === 200) {
                  // Additional verification - check response isn't a redirect to 404 page
                  const text = await response.text();
                  const is404 = text.toLowerCase().includes('page not found') ||
                               text.toLowerCase().includes('user not found') ||
                               text.toLowerCase().includes('404') ||
                               text.toLowerCase().includes('does not exist') ||
                               text.toLowerCase().includes('no user') ||
                               text.length < 500; // Very small response likely means error
                  
                  if (!is404) {
                    exists = true;
                    // Try to extract profile data from HTML
                    const titleMatch = text.match(/<title>([^<]+)<\/title>/i);
                    const ogTitleMatch = text.match(/<meta[^>]*property="og:title"[^>]*content="([^"]+)"/i);
                    if (ogTitleMatch || titleMatch) {
                      profileData.displayName = (ogTitleMatch?.[1] || titleMatch?.[1])?.split(' - ')[0]?.split(' | ')[0]?.trim();
                    }
                  }
                }
                break;
              }
              
              case 'html_pattern': {
                const html = await response.text();
                const existsPattern = platform.existsPattern || '';
                const notExistsPattern = platform.notExistsPattern || '';
                
                // Check for NOT EXISTS pattern first
                if (notExistsPattern && html.includes(notExistsPattern)) {
                  exists = false;
                } else if (existsPattern && html.includes(existsPattern)) {
                  exists = true;
                  // Try to extract profile data from HTML
                  const titleMatch = html.match(/<title>([^<]+)<\/title>/i);
                  const ogTitleMatch = html.match(/<meta[^>]*property="og:title"[^>]*content="([^"]+)"/i);
                  if (titleMatch || ogTitleMatch) {
                    profileData.displayName = (ogTitleMatch?.[1] || titleMatch?.[1])?.split(' - ')[0]?.split(' | ')[0]?.trim();
                  }
                  const descMatch = html.match(/<meta[^>]*name="description"[^>]*content="([^"]+)"/i);
                  if (descMatch) {
                    profileData.bio = descMatch[1].substring(0, 200);
                  }
                }
                break;
              }
            }
            
            if (exists) {
              console.log(`[Username Enum] ✅ Found: ${platform.name}`);
              results.push({
                platform: platform.name,
                username,
                exists: true,
                url: profileUrl,
                profileData,
                lastChecked: new Date().toISOString(),
              });
            }
          } catch (error) {
            // Request failed - user doesn't exist or blocked
            clearTimeout(timeoutId);
          }
        } catch (error) {
          // Skip on error
        }
      })
    );
    
    // Small delay between batches to avoid rate limiting
    await new Promise(resolve => setTimeout(resolve, 300));
  }

  console.log(`[Username Enum] Completed. Found ${results.length} platforms out of ${PLATFORMS.length} checked.`);
  
  // Sort by platform type for better organization
  results.sort((a, b) => {
    const platformA = PLATFORMS.find(p => p.name === a.platform);
    const platformB = PLATFORMS.find(p => p.name === b.platform);
    return (platformA?.type || '').localeCompare(platformB?.type || '');
  });
  
  if (results.length > 0) {
    await cacheAPIResponse(cacheKey, results, 60); // 1 hour cache
  }
  
  return results;
}

// Helper to get nested object values like "status.code"
function getNestedValue(obj: any, path: string): any {
  return path.split('.').reduce((current, key) => current?.[key], obj);
}

// Extract profile data from API responses
function extractProfileData(data: any, platform: string): Record<string, any> {
  const profile: Record<string, any> = {};
  
  // Common fields
  profile.displayName = data.name || data.login || data.username || data.display_name;
  profile.bio = data.bio || data.description || data.about;
  profile.profileImage = data.avatar_url || data.avatar || data.profile_image || data.icon_url;
  
  // Platform-specific
  if (platform === 'GitHub') {
    profile.followers = data.followers;
    profile.following = data.following;
    profile.repos = data.public_repos;
    profile.joinDate = data.created_at;
  } else if (platform === 'Reddit') {
    profile.karma = data.data?.total_karma || data.total_karma;
    profile.joinDate = data.data?.created_utc ? new Date(data.data.created_utc * 1000).toISOString() : undefined;
  } else if (platform === 'Chess.com' || platform === 'Lichess') {
    profile.rating = data.rating || data.perfs?.blitz?.rating;
    profile.games = data.count?.all || data.games;
  }
  
  return profile;
}

// AI-powered summarization using Perplexity API
export async function summarizeUsernameResults(
  username: string,
  results: UsernameResult[]
): Promise<string> {
  const PERPLEXITY_API_KEY = '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';
  
  try {
    const platformSummary = results
      .map(r => `${r.platform}: ${r.url}`)
      .join('\n');
    
    const response = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${PERPLEXITY_API_KEY}`,
      },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          {
            role: 'system',
            content: 'You are an OSINT analyst. Provide a concise 3-4 sentence summary of a user\'s digital footprint.',
          },
          {
            role: 'user',
            content: `Analyze this username "${username}" found on ${results.length} platforms:\n\n${platformSummary}\n\nProvide a brief OSINT summary focusing on: digital presence, platform types, and potential insights.`,
          },
        ],
        temperature: 0.2,
      }),
    });
    
    const data = await response.json();
    return data?.choices?.[0]?.message?.content || 'Unable to generate summary.';
  } catch (error) {
    console.error('AI summarization error:', error);
    return `Found username "${username}" on ${results.length} platforms including ${results.slice(0, 3).map(r => r.platform).join(', ')}.`;
  }
}
