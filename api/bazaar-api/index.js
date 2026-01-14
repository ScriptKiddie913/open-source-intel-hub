// Vercel serverless function to proxy MalwareBazaar API
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
  
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  
  try {
    console.log('[Vercel/MalwareBazaar] Proxying POST request to abuse.ch...');
    
    const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0',
      },
      body: req.body || 'query=get_recent&selector=100',
    });
    
    if (!response.ok) {
      throw new Error(`MalwareBazaar API responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('[Vercel/MalwareBazaar] Successfully fetched data, status:', data?.query_status);
    
    res.status(200).json(data);
  } catch (error) {
    console.error('[Vercel/MalwareBazaar] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch MalwareBazaar data', details: error.message });
  }
}