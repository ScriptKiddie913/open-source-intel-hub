/**
 * Username Enumeration Service
 * Provides functionality to check username availability across multiple platforms
 */

export interface Platform {
  id: string;
  name: string;
  url: string;
  category: string;
  checkUrl: string;
  errorType: 'status' | 'content' | 'redirect';
  errorIndicator?: string;
  successIndicator?: string;
  headers?: Record<string, string>;
  method?: 'GET' | 'POST';
  rateLimit?: number;
  requiresAuth?: boolean;
}

export interface UsernameResult {
  platform: string;
  platformName: string;
  url: string;
  exists: boolean;
  available: boolean;
  status: 'found' | 'not_found' | 'error' | 'rate_limited' | 'pending';
  responseTime?: number;
  timestamp: string;
  error?: string;
  category: string;
}

export interface EnumerationStats {
  total: number;
  found: number;
  notFound: number;
  errors: number;
  rateLimited: number;
  pending: number;
  successRate: number;
  averageResponseTime: number;
}

/**
 * Comprehensive list of platforms for username enumeration
 */
export const PLATFORMS: Platform[] = [
  // Social Media
  {
    id: 'github',
    name: 'GitHub',
    url: 'https://github.com',
    category: 'Development',
    checkUrl: 'https://github.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'twitter',
    name: 'Twitter/X',
    url: 'https://twitter.com',
    category: 'Social Media',
    checkUrl: 'https://twitter.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 100
  },
  {
    id: 'instagram',
    name: 'Instagram',
    url: 'https://instagram.com',
    category: 'Social Media',
    checkUrl: 'https://www.instagram.com/{username}/',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'facebook',
    name: 'Facebook',
    url: 'https://facebook.com',
    category: 'Social Media',
    checkUrl: 'https://www.facebook.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 100
  },
  {
    id: 'linkedin',
    name: 'LinkedIn',
    url: 'https://linkedin.com',
    category: 'Professional',
    checkUrl: 'https://www.linkedin.com/in/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'reddit',
    name: 'Reddit',
    url: 'https://reddit.com',
    category: 'Social Media',
    checkUrl: 'https://www.reddit.com/user/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'tiktok',
    name: 'TikTok',
    url: 'https://tiktok.com',
    category: 'Social Media',
    checkUrl: 'https://www.tiktok.com/@{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'youtube',
    name: 'YouTube',
    url: 'https://youtube.com',
    category: 'Social Media',
    checkUrl: 'https://www.youtube.com/@{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 100
  },
  {
    id: 'snapchat',
    name: 'Snapchat',
    url: 'https://snapchat.com',
    category: 'Social Media',
    checkUrl: 'https://www.snapchat.com/add/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'pinterest',
    name: 'Pinterest',
    url: 'https://pinterest.com',
    category: 'Social Media',
    checkUrl: 'https://www.pinterest.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 100
  },
  
  // Development Platforms
  {
    id: 'gitlab',
    name: 'GitLab',
    url: 'https://gitlab.com',
    category: 'Development',
    checkUrl: 'https://gitlab.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'bitbucket',
    name: 'Bitbucket',
    url: 'https://bitbucket.org',
    category: 'Development',
    checkUrl: 'https://bitbucket.org/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'stackoverflow',
    name: 'Stack Overflow',
    url: 'https://stackoverflow.com',
    category: 'Development',
    checkUrl: 'https://stackoverflow.com/users/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 100
  },
  {
    id: 'codepen',
    name: 'CodePen',
    url: 'https://codepen.io',
    category: 'Development',
    checkUrl: 'https://codepen.io/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'replit',
    name: 'Replit',
    url: 'https://replit.com',
    category: 'Development',
    checkUrl: 'https://replit.com/@{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'dev.to',
    name: 'DEV.to',
    url: 'https://dev.to',
    category: 'Development',
    checkUrl: 'https://dev.to/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'hackernews',
    name: 'Hacker News',
    url: 'https://news.ycombinator.com',
    category: 'Development',
    checkUrl: 'https://news.ycombinator.com/user?id={username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  
  // Gaming
  {
    id: 'steam',
    name: 'Steam',
    url: 'https://steamcommunity.com',
    category: 'Gaming',
    checkUrl: 'https://steamcommunity.com/id/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'twitch',
    name: 'Twitch',
    url: 'https://twitch.tv',
    category: 'Gaming',
    checkUrl: 'https://www.twitch.tv/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'discord',
    name: 'Discord',
    url: 'https://discord.com',
    category: 'Gaming',
    checkUrl: 'https://discord.com/users/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50,
    requiresAuth: true
  },
  {
    id: 'playstation',
    name: 'PlayStation Network',
    url: 'https://psnprofiles.com',
    category: 'Gaming',
    checkUrl: 'https://psnprofiles.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'xbox',
    name: 'Xbox Live',
    url: 'https://xboxgamertag.com',
    category: 'Gaming',
    checkUrl: 'https://xboxgamertag.com/search/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  
  // Professional & Business
  {
    id: 'medium',
    name: 'Medium',
    url: 'https://medium.com',
    category: 'Professional',
    checkUrl: 'https://medium.com/@{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'behance',
    name: 'Behance',
    url: 'https://behance.net',
    category: 'Professional',
    checkUrl: 'https://www.behance.net/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'dribbble',
    name: 'Dribbble',
    url: 'https://dribbble.com',
    category: 'Professional',
    checkUrl: 'https://dribbble.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'fiverr',
    name: 'Fiverr',
    url: 'https://fiverr.com',
    category: 'Professional',
    checkUrl: 'https://www.fiverr.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'upwork',
    name: 'Upwork',
    url: 'https://upwork.com',
    category: 'Professional',
    checkUrl: 'https://www.upwork.com/freelancers/~{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  
  // Content & Media
  {
    id: 'spotify',
    name: 'Spotify',
    url: 'https://spotify.com',
    category: 'Media',
    checkUrl: 'https://open.spotify.com/user/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'soundcloud',
    name: 'SoundCloud',
    url: 'https://soundcloud.com',
    category: 'Media',
    checkUrl: 'https://soundcloud.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'vimeo',
    name: 'Vimeo',
    url: 'https://vimeo.com',
    category: 'Media',
    checkUrl: 'https://vimeo.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'flickr',
    name: 'Flickr',
    url: 'https://flickr.com',
    category: 'Media',
    checkUrl: 'https://www.flickr.com/people/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'patreon',
    name: 'Patreon',
    url: 'https://patreon.com',
    category: 'Media',
    checkUrl: 'https://www.patreon.com/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  
  // Forums & Communities
  {
    id: 'quora',
    name: 'Quora',
    url: 'https://quora.com',
    category: 'Community',
    checkUrl: 'https://www.quora.com/profile/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'tumblr',
    name: 'Tumblr',
    url: 'https://tumblr.com',
    category: 'Social Media',
    checkUrl: 'https://{username}.tumblr.com',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'wordpress',
    name: 'WordPress',
    url: 'https://wordpress.com',
    category: 'Community',
    checkUrl: 'https://{username}.wordpress.com',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  },
  {
    id: 'telegram',
    name: 'Telegram',
    url: 'https://t.me',
    category: 'Messaging',
    checkUrl: 'https://t.me/{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 50
  },
  {
    id: 'mastodon',
    name: 'Mastodon',
    url: 'https://mastodon.social',
    category: 'Social Media',
    checkUrl: 'https://mastodon.social/@{username}',
    errorType: 'status',
    method: 'GET',
    rateLimit: 60
  }
];

/**
 * Check if a username exists on a specific platform
 */
export async function checkUsername(
  username: string,
  platform: Platform
): Promise<UsernameResult> {
  const startTime = Date.now();
  const url = platform.checkUrl.replace('{username}', username);
  
  const result: UsernameResult = {
    platform: platform.id,
    platformName: platform.name,
    url,
    exists: false,
    available: true,
    status: 'pending',
    timestamp: new Date().toISOString(),
    category: platform.category
  };

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    const response = await fetch(url, {
      method: platform.method || 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        ...platform.headers
      },
      signal: controller.signal,
      redirect: 'follow'
    });

    clearTimeout(timeoutId);

    const responseTime = Date.now() - startTime;
    result.responseTime = responseTime;

    // Check based on platform's error type
    switch (platform.errorType) {
      case 'status':
        if (response.status === 200) {
          result.exists = true;
          result.available = false;
          result.status = 'found';
        } else if (response.status === 404) {
          result.exists = false;
          result.available = true;
          result.status = 'not_found';
        } else if (response.status === 429) {
          result.status = 'rate_limited';
          result.error = 'Rate limit exceeded';
        } else {
          result.status = 'error';
          result.error = `HTTP ${response.status}`;
        }
        break;

      case 'content':
        const text = await response.text();
        if (platform.successIndicator && text.includes(platform.successIndicator)) {
          result.exists = true;
          result.available = false;
          result.status = 'found';
        } else if (platform.errorIndicator && text.includes(platform.errorIndicator)) {
          result.exists = false;
          result.available = true;
          result.status = 'not_found';
        } else {
          result.status = 'error';
          result.error = 'Unable to determine status';
        }
        break;

      case 'redirect':
        if (response.redirected) {
          result.exists = true;
          result.available = false;
          result.status = 'found';
        } else {
          result.exists = false;
          result.available = true;
          result.status = 'not_found';
        }
        break;
    }
  } catch (error) {
    result.status = 'error';
    result.responseTime = Date.now() - startTime;
    
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        result.error = 'Request timeout';
      } else {
        result.error = error.message;
      }
    } else {
      result.error = 'Unknown error occurred';
    }
  }

  return result;
}

/**
 * Enumerate a username across all platforms
 */
export async function enumerateUsername(
  username: string,
  platforms: Platform[] = PLATFORMS,
  onProgress?: (result: UsernameResult) => void
): Promise<UsernameResult[]> {
  const results: UsernameResult[] = [];
  
  // Process platforms in batches to avoid overwhelming the browser
  const batchSize = 5;
  
  for (let i = 0; i < platforms.length; i += batchSize) {
    const batch = platforms.slice(i, i + batchSize);
    const batchPromises = batch.map(platform => 
      checkUsername(username, platform).then(result => {
        if (onProgress) {
          onProgress(result);
        }
        return result;
      })
    );
    
    const batchResults = await Promise.all(batchPromises);
    results.push(...batchResults);
    
    // Small delay between batches to be respectful
    if (i + batchSize < platforms.length) {
      await new Promise(resolve => setTimeout(resolve, 500));
    }
  }
  
  return results;
}

/**
 * Calculate statistics from enumeration results
 */
export function calculateStats(results: UsernameResult[]): EnumerationStats {
  const stats: EnumerationStats = {
    total: results.length,
    found: 0,
    notFound: 0,
    errors: 0,
    rateLimited: 0,
    pending: 0,
    successRate: 0,
    averageResponseTime: 0
  };

  let totalResponseTime = 0;
  let responseTimeCount = 0;

  results.forEach(result => {
    switch (result.status) {
      case 'found':
        stats.found++;
        break;
      case 'not_found':
        stats.notFound++;
        break;
      case 'error':
        stats.errors++;
        break;
      case 'rate_limited':
        stats.rateLimited++;
        break;
      case 'pending':
        stats.pending++;
        break;
    }

    if (result.responseTime !== undefined) {
      totalResponseTime += result.responseTime;
      responseTimeCount++;
    }
  });

  const completed = stats.total - stats.pending;
  stats.successRate = completed > 0 ? ((stats.found + stats.notFound) / completed) * 100 : 0;
  stats.averageResponseTime = responseTimeCount > 0 ? totalResponseTime / responseTimeCount : 0;

  return stats;
}

/**
 * Get all available platforms
 */
export function getAvailablePlatforms(): Platform[] {
  return [...PLATFORMS];
}

/**
 * Get platforms grouped by category
 */
export function getPlatformCategories(): Record<string, Platform[]> {
  const categories: Record<string, Platform[]> = {};
  
  PLATFORMS.forEach(platform => {
    if (!categories[platform.category]) {
      categories[platform.category] = [];
    }
    categories[platform.category].push(platform);
  });
  
  return categories;
}

/**
 * Filter platforms by category
 */
export function getPlatformsByCategory(category: string): Platform[] {
  return PLATFORMS.filter(platform => platform.category === category);
}

/**
 * Search platforms by name or ID
 */
export function searchPlatforms(query: string): Platform[] {
  const lowerQuery = query.toLowerCase();
  return PLATFORMS.filter(platform => 
    platform.id.toLowerCase().includes(lowerQuery) ||
    platform.name.toLowerCase().includes(lowerQuery)
  );
}

/**
 * Get a single platform by ID
 */
export function getPlatformById(id: string): Platform | undefined {
  return PLATFORMS.find(platform => platform.id === id);
}

/**
 * Validate username format
 */
export function validateUsername(username: string): { valid: boolean; error?: string } {
  if (!username || username.trim().length === 0) {
    return { valid: false, error: 'Username cannot be empty' };
  }
  
  if (username.length < 2) {
    return { valid: false, error: 'Username must be at least 2 characters' };
  }
  
  if (username.length > 50) {
    return { valid: false, error: 'Username must be less than 50 characters' };
  }
  
  // Basic alphanumeric check with some special characters
  const validPattern = /^[a-zA-Z0-9_-]+$/;
  if (!validPattern.test(username)) {
    return { valid: false, error: 'Username can only contain letters, numbers, underscores, and hyphens' };
  }
  
  return { valid: true };
}

export default {
  PLATFORMS,
  checkUsername,
  enumerateUsername,
  calculateStats,
  getAvailablePlatforms,
  getPlatformCategories,
  getPlatformsByCategory,
  searchPlatforms,
  getPlatformById,
  validateUsername
};
