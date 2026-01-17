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
    console.log('[Vercel/PhishTank] Proxying request...');
    const response = await fetch('https://data.phishtank.com/data/online-valid.csv', {
      headers: { 'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0' },
    });
    
    if (!response.ok) throw new Error(`PhishTank API status: ${response.status}`);
    
    const text = await response.text();
    console.log('[Vercel/PhishTank] Successfully fetched data');
    res.setHeader('Content-Type', 'text/csv');
    res.status(200).send(text);
  } catch (error) {
    console.error('[Vercel/PhishTank] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch PhishTank data', details: error.message });
  }
}
