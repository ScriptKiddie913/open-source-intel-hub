import type { VercelRequest, VercelResponse } from '@vercel/node';

// Library of Leaks API Proxy
// Handles CORS and forwards requests to the Aleph API

const LIBRARY_OF_LEAKS_BASE = 'https://search.libraryofleaks.org';

// Generate a session ID for API requests (UUID v4 format)
function generateSessionId(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { q, limit = '30', schema = 'Thing' } = req.query;

  if (!q || typeof q !== 'string') {
    return res.status(400).json({ error: 'Query parameter "q" is required' });
  }

  try {
    const sessionId = generateSessionId();
    const params = new URLSearchParams({
      'filter:schemata': schema as string,
      highlight: 'true',
      limit: limit as string,
      q: q,
    });

    const apiUrl = `${LIBRARY_OF_LEAKS_BASE}/api/2/entities?${params.toString()}`;
    
    console.log(`[Library of Leaks Proxy] Fetching: ${apiUrl}`);

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
        'Sec-CH-UA': '"Not_A Brand";v="99", "Chromium";v="142"',
        'Sec-CH-UA-Mobile': '?0',
        'Sec-CH-UA-Platform': '"Windows"',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Referer': `${LIBRARY_OF_LEAKS_BASE}/`,
        'X-Aleph-Session': sessionId,
      },
    });

    if (!response.ok) {
      console.error(`[Library of Leaks Proxy] API error: ${response.status} ${response.statusText}`);
      return res.status(response.status).json({ 
        error: `Library of Leaks API returned ${response.status}`,
        statusText: response.statusText,
      });
    }

    const data = await response.json();
    
    console.log(`[Library of Leaks Proxy] Found ${data.total || 0} results for "${q}"`);

    return res.status(200).json(data);
  } catch (error) {
    console.error('[Library of Leaks Proxy] Error:', error);
    return res.status(500).json({ 
      error: 'Failed to fetch from Library of Leaks',
      details: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
