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
        
        for (const item of feodoData.slice(0, 50)) {
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
        
        for (const item of (threatfoxData.data || []).slice(0, 30)) {
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

// Dark Web monitoring (simulated - replace with real scraper)
export async function scanDarkWebLeaks(query?: string): Promise<DarkWebLeak[]> {
  const cacheKey = `darkweb:${query || 'recent'}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  // NOTE: Replace with real dark web scraper
  // For demo purposes, using public breach data sources
  const leaks: DarkWebLeak[] = [];

  try {
    // Check Have I Been Pwned pastes (public API)
    if (query && query.includes('@')) {
      const response = await fetch(`https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(query)}`, {
        headers: { 'User-Agent': 'OSINT-Platform' }
      });
      
      if (response.ok) {
        const pastes = await response.json();
        pastes.slice(0, 10).forEach((paste: any) => {
          leaks.push({
            id: paste.Id,
            title: paste.Title || 'Untitled Paste',
            description: `Found in ${paste.Source}`,
            leakDate: paste.Date,
            affectedEntities: [query],
            dataTypes: ['email', 'paste'],
            recordCount: paste.EmailCount || 1,
            source: paste.Source,
            severity: 'medium',
          });
        });
      }
    }

    // Simulated dark web marketplace monitoring
    const simulatedLeaks: DarkWebLeak[] = [
      {
        id: 'leak-1',
        title: 'Corporate Database Leak',
        description: 'Employee credentials from Fortune 500 company',
        leakDate: new Date(Date.now() - 86400000 * 2).toISOString(),
        affectedEntities: ['Enterprise Corp'],
        dataTypes: ['credentials', 'personal_data', 'financial'],
        recordCount: 45000,
        source: 'Dark Web Forum',
        severity: 'critical',
      },
      {
        id: 'leak-2',
        title: 'Healthcare Data Breach',
        description: 'Patient records and medical histories',
        leakDate: new Date(Date.now() - 86400000 * 5).toISOString(),
        affectedEntities: ['Medical Center'],
        dataTypes: ['medical_records', 'pii', 'insurance'],
        recordCount: 120000,
        source: 'Dark Marketplace',
        severity: 'critical',
      },
      {
        id: 'leak-3',
        title: 'Social Media Scrape',
        description: 'Public profile data aggregation',
        leakDate: new Date(Date.now() - 86400000 * 7).toISOString(),
        affectedEntities: ['Multiple Platforms'],
        dataTypes: ['profiles', 'emails', 'phone_numbers'],
        recordCount: 500000,
        source: 'Data Broker',
        severity: 'medium',
      },
    ];

    leaks.push(...simulatedLeaks);
    await cacheAPIResponse(cacheKey, leaks, 30);
    return leaks;
  } catch (error) {
    console.error('Dark web scan error:', error);
    return leaks;
  }
}

// Username enumeration across platforms with REAL verification
// Each platform has specific checks to confirm existence
const PLATFORMS = [
  // Social Media - with verification patterns
  { 
    name: 'GitHub', 
    url: 'https://api.github.com/users/{username}', 
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://github.com/{username}'
  },
  { 
    name: 'Reddit', 
    url: 'https://www.reddit.com/user/{username}/about.json', 
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://reddit.com/user/{username}'
  },
  {
    name: 'GitLab',
    url: 'https://gitlab.com/api/v4/users?username={username}',
    type: 'dev',
    checkType: 'json_array',
    profileUrl: 'https://gitlab.com/{username}'
  },
  {
    name: 'HackerNews',
    url: 'https://hacker-news.firebaseio.com/v0/user/{username}.json',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://news.ycombinator.com/user?id={username}'
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
    name: 'Dev.to',
    url: 'https://dev.to/api/users/by_username?url={username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://dev.to/{username}'
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
    name: 'PyPI',
    url: 'https://pypi.org/pypi/{username}/json',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://pypi.org/user/{username}'
  },
  {
    name: 'npm',
    url: 'https://registry.npmjs.org/-/user/org.couchdb.user:{username}',
    type: 'dev',
    checkType: 'json_api',
    profileUrl: 'https://www.npmjs.com/~{username}'
  },
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
    name: 'Duolingo',
    url: 'https://www.duolingo.com/2017-06-30/users?username={username}',
    type: 'education',
    checkType: 'json_array',
    profileUrl: 'https://duolingo.com/profile/{username}'
  },
  {
    name: 'Gravatar',
    url: 'https://en.gravatar.com/{username}.json',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://gravatar.com/{username}'
  },
  {
    name: 'Imgur',
    url: 'https://api.imgur.com/account/v1/accounts/{username}?client_id=546c25a59c58ad7',
    type: 'media',
    checkType: 'json_api',
    profileUrl: 'https://imgur.com/user/{username}'
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
    name: 'Mastodon',
    url: 'https://mastodon.social/api/v1/accounts/lookup?acct={username}',
    type: 'social',
    checkType: 'json_api',
    profileUrl: 'https://mastodon.social/@{username}'
  },
  {
    name: 'Spotify',
    url: 'https://open.spotify.com/user/{username}',
    type: 'music',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: 'Page not found',
    profileUrl: 'https://open.spotify.com/user/{username}'
  },
  {
    name: 'About.me',
    url: 'https://about.me/{username}',
    type: 'professional',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://about.me/{username}'
  },
  {
    name: 'ProductHunt',
    url: 'https://api.producthunt.com/v2/api/graphql',
    type: 'dev',
    checkType: 'skip', // Requires auth
    profileUrl: 'https://producthunt.com/@{username}'
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
    url: 'https://replit.com/@{username}',
    type: 'dev',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://replit.com/@{username}'
  },
  {
    name: 'CodePen',
    url: 'https://codepen.io/{username}',
    type: 'dev',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404 - Page Not Found',
    profileUrl: 'https://codepen.io/{username}'
  },
  {
    name: 'Twitch',
    url: 'https://api.twitch.tv/helix/users?login={username}',
    type: 'gaming',
    checkType: 'skip', // Requires OAuth
    profileUrl: 'https://twitch.tv/{username}'
  },
  {
    name: 'Pinterest',
    url: 'https://pinterest.com/{username}',
    type: 'social',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: 'This page isn',
    profileUrl: 'https://pinterest.com/{username}'
  },
  {
    name: 'Medium',
    url: 'https://medium.com/@{username}',
    type: 'blogging',
    checkType: 'html_pattern',
    existsPattern: 'og:title',
    notExistsPattern: '404',
    profileUrl: 'https://medium.com/@{username}'
  },
];

const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

export async function enumerateUsername(username: string): Promise<UsernameResult[]> {
  const cacheKey = `username:${username}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  const results: UsernameResult[] = [];
  const batchSize = 5;

  console.log(`[Username Enum] Starting scan for: ${username}`);

  // Check platforms in batches
  for (let i = 0; i < PLATFORMS.length; i += batchSize) {
    const batch = PLATFORMS.slice(i, i + batchSize);
    
    await Promise.all(
      batch.map(async (platform) => {
        if (platform.checkType === 'skip') return;
        
        try {
          const url = platform.url.replace('{username}', encodeURIComponent(username));
          const profileUrl = platform.profileUrl?.replace('{username}', username) || url;
          
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), 8000);
          
          let exists = false;
          let profileData: any = {};
          
          try {
            // Try direct fetch first, then CORS proxy
            let response: Response | null = null;
            
            try {
              response = await fetch(url, {
                method: 'GET',
                signal: controller.signal,
                headers: { 'User-Agent': 'OSINT-Hub/1.0' },
              });
            } catch {
              // Try with CORS proxy
              response = await fetch(`${CORS_PROXY}${encodeURIComponent(url)}`, {
                signal: controller.signal,
              });
            }
            
            clearTimeout(timeoutId);
            
            if (!response) return;
            
            // Handle different check types
            switch (platform.checkType) {
              case 'json_api': {
                if (response.ok) {
                  try {
                    const data = await response.json();
                    if (data && !data.error && !data.message?.includes('Not Found')) {
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
                      profileData = extractProfileData(data.them || data, platform.name);
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
                  if (titleMatch) {
                    profileData.displayName = titleMatch[1].split(' - ')[0].trim();
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
    
    // Small delay between batches
    await new Promise(resolve => setTimeout(resolve, 200));
  }

  console.log(`[Username Enum] Completed. Found ${results.length} platforms.`);
  
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
