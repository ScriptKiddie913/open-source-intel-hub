export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
  
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }
  
  try {
    console.log('[Vercel/Blocklist] Proxying request...');
    const response = await fetch('https://api.blocklist.de/getlast.php?time=86400', {
      headers: { 'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0' },
    });
    
    if (!response.ok) throw new Error(`Blocklist API status: ${response.status}`);
    
    const text = await response.text();
    console.log('[Vercel/Blocklist] Successfully fetched data');
    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send(text);
  } catch (error) {
    console.error('[Vercel/Blocklist] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch Blocklist data', details: error.message });
  }
}
