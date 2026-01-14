// Vercel serverless function to proxy Feodo Tracker API
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
    console.log('[Vercel/Feodo] Proxying request to abuse.ch...');
    
    const response = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json', {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0',
      },
    });
    
    if (!response.ok) {
      throw new Error(`Feodo API responded with status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('[Vercel/Feodo] Successfully fetched data, entries:', data?.length || 0);
    
    res.status(200).json(data);
  } catch (error) {
    console.error('[Vercel/Feodo] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch Feodo data', details: error.message });
  }
}