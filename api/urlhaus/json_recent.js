export default async function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  
  try {
    console.log('[Vercel/URLhaus] Proxying request to abuse.ch...');
    
    const response = await fetch('https://urlhaus.abuse.ch/downloads/json_recent/', {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0',
      },
    });
    
    if (!response.ok) {
      throw new Error(`URLhaus API responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    // URLhaus returns { "timestamp": "...", "query_status": "ok", "urls": [...] } OR just { "query_status": "no_results" }
    // OR sometimes the download endpoint returns a different structure.
    // Let's check the endpoint response format if possible, but assuming standard JSON response.
    // The previous code in mispFeedService handles the download format:
    // "API returns object with numeric keys, each containing an array with one entry"
    // Wait, let's double check mispFeedService.ts logic.
    
    console.log('[Vercel/URLhaus] Successfully fetched data');
    
    res.status(200).json(data);
  } catch (error) {
    console.error('[Vercel/URLhaus] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch URLhaus data', details: error.message });
  }
}
