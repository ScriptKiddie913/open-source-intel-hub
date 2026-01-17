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
    console.log('[Vercel/SSLBL] Proxying request to abuse.ch...');
    const response = await fetch('https://sslbl.abuse.ch/blacklist/sslipblacklist.json', {
      headers: { 'User-Agent': 'Mozilla/5.0 OSINT-Hub/1.0' },
    });
    
    if (!response.ok) throw new Error(`SSLBL API status: ${response.status}`);
    
    const data = await response.json();
    console.log('[Vercel/SSLBL] Successfully fetched data');
    res.status(200).json(data);
  } catch (error) {
    console.error('[Vercel/SSLBL] Error:', error.message);
    res.status(500).json({ error: 'Failed to fetch SSLBL data', details: error.message });
  }
}
