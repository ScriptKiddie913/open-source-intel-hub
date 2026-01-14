// Vercel serverless function to proxy ThreatFox API
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
    console.log('[Vercel/ThreatFox] Proxying POST request to abuse.ch...');
    
    const response = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0',
      },
      body: JSON.stringify(req.body || { query: 'get_iocs', days: 30 }),
    });
    
    if (!response.ok) {
      throw new Error(`ThreatFox API responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('[Vercel/ThreatFox] Successfully fetched data, status:', data?.query_status);
    
    res.status(200).json(data);
  } catch (error) {
    console.error('[Vercel/ThreatFox] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch ThreatFox data', details: error.message });
  }
}