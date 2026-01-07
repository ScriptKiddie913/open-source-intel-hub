// Cryptocurrency Address Scanner Service
// Multiple free blockchain APIs for crypto address analysis

export interface CryptoScanResult {
  success: boolean;
  address: string;
  blockchain: string;
  balance: number;
  transactions: number;
  firstSeen: string | null;
  lastSeen: string | null;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  riskScore: number;
  flags: string[];
  tags: string[];
  relatedAddresses: string[];
  exchangeInfo?: {
    name: string;
    isExchange: boolean;
    isKnown: boolean;
  };
  sources: Record<string, any>;
  timestamp: string;
}

export interface BlockchainTransaction {
  hash: string;
  from: string;
  to: string;
  amount: number;
  timestamp: string;
  blockHeight?: number;
}

const CORS_PROXY = 'https://api.allorigins.win/raw?url=';

// Enhanced fetch with timeout for crypto APIs
async function fetchCryptoAPI(url: string, options: RequestInit = {}, timeout = 15000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'OSINT-Hub/1.0 (Cryptocurrency Intelligence Scanner)',
        'Accept': 'application/json',
        'Cache-Control': 'no-cache',
        ...options.headers,
      },
    });
    clearTimeout(id);
    return response;
  } catch (error: any) {
    clearTimeout(id);
    if (error.name === 'AbortError') {
      throw new Error('Request timeout - blockchain API not responding');
    }
    throw error;
  }
}

// Helper to detect cryptocurrency type
function detectCryptoType(address: string): string {
  // Bitcoin
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(address) || /^bc1[a-z0-9]{39,59}$/.test(address)) {
    return 'bitcoin';
  }
  // Ethereum
  if (/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return 'ethereum';
  }
  // Litecoin
  if (/^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/.test(address)) {
    return 'litecoin';
  }
  // Bitcoin Cash
  if (/^[qp][a-z0-9]{41}$/.test(address)) {
    return 'bitcoin-cash';
  }
  // Dogecoin
  if (/^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/.test(address)) {
    return 'dogecoin';
  }
  // Monero
  if (/^[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/.test(address)) {
    return 'monero';
  }
  return 'unknown';
}

// Query BlockCypher API (Free tier)
async function queryBlockCypher(address: string, crypto: string): Promise<any> {
  try {
    console.log(`[BlockCypher] Querying ${crypto}: ${address}`);
    
    let network = '';
    switch (crypto) {
      case 'bitcoin':
        network = 'btc/main';
        break;
      case 'litecoin':
        network = 'ltc/main';
        break;
      case 'dogecoin':
        network = 'doge/main';
        break;
      default:
        return { error: 'Unsupported cryptocurrency for BlockCypher' };
    }
    
    const response = await fetchCryptoAPI(`https://api.blockcypher.com/v1/${network}/addrs/${address}/balance`);
    
    if (response.status === 404) {
      return { found: false, message: 'Address not found' };
    }
    
    if (!response.ok) {
      return { error: `BlockCypher API error: ${response.status}` };
    }
    
    const data = await response.json();
    
    return {
      found: true,
      balance: data.balance || 0,
      unconfirmed_balance: data.unconfirmed_balance || 0,
      final_balance: data.final_balance || 0,
      n_tx: data.n_tx || 0,
      unconfirmed_n_tx: data.unconfirmed_n_tx || 0,
      final_n_tx: data.final_n_tx || 0,
      total_received: data.total_received || 0,
      total_sent: data.total_sent || 0,
    };
  } catch (error) {
    console.error('[BlockCypher] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query Etherscan API (Free tier) for Ethereum
async function queryEtherscan(address: string): Promise<any> {
  try {
    console.log(`[Etherscan] Querying Ethereum: ${address}`);
    
    // Get balance
    const balanceResponse = await fetch(`https://api.etherscan.io/api?module=account&action=balance&address=${address}&tag=latest&apikey=YourApiKeyToken`);
    
    if (!balanceResponse.ok) {
      return { error: `Etherscan API error: ${balanceResponse.status}` };
    }
    
    const balanceData = await balanceResponse.json();
    
    if (balanceData.status !== '1') {
      return { found: false, message: 'Address not found or invalid' };
    }
    
    // Get transaction count
    const txCountResponse = await fetch(`https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address=${address}&tag=latest&apikey=YourApiKeyToken`);
    const txCountData = await txCountResponse.json();
    
    return {
      found: true,
      balance: parseInt(balanceData.result) / Math.pow(10, 18), // Convert wei to ETH
      transactionCount: parseInt(txCountData.result || '0', 16),
    };
  } catch (error) {
    console.error('[Etherscan] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query blockchain.info API for Bitcoin
async function queryBlockchainInfo(address: string): Promise<any> {
  try {
    console.log(`[Blockchain.info] Querying Bitcoin: ${address}`);
    
    const response = await fetchCryptoAPI(`https://blockchain.info/rawaddr/${address}?limit=10`);
    
    if (response.status === 500) {
      return { found: false, message: 'Address not found' };
    }
    
    if (!response.ok) {
      return { error: `Blockchain.info API error: ${response.status}` };
    }
    
    const data = await response.json();
    
    return {
      found: true,
      balance: data.final_balance / 100000000, // Convert satoshi to BTC
      totalReceived: data.total_received / 100000000,
      totalSent: data.total_sent / 100000000,
      transactionCount: data.n_tx,
      transactions: data.txs?.slice(0, 10).map((tx: any) => ({
        hash: tx.hash,
        time: new Date(tx.time * 1000).toISOString(),
        result: tx.result / 100000000,
        balance: tx.balance / 100000000,
      })) || [],
    };
  } catch (error) {
    console.error('[Blockchain.info] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query Crystal Blockchain (free public data)
async function queryCrystalBlockchain(address: string, crypto: string): Promise<any> {
  try {
    console.log(`[Crystal] Checking ${crypto}: ${address}`);
    
    // Use Crystal's public risk scoring (demo endpoint)
    const response = await fetch(`${CORS_PROXY}${encodeURIComponent(`https://api.crystalblockchain.com/api/v1/addresses/${address}/risk-score`)}`);
    
    if (!response.ok) {
      return { found: false };
    }
    
    const data = await response.json();
    
    return {
      found: true,
      riskScore: data.risk_score || 0,
      riskLevel: data.risk_level || 'unknown',
      categories: data.categories || [],
      cluster: data.cluster_info || null,
    };
  } catch (error) {
    console.error('[Crystal] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Query Chainalysis Reactor (public sanctions list)
async function queryChainAnalysis(address: string): Promise<any> {
  try {
    console.log(`[Chainalysis] Checking sanctions: ${address}`);
    
    // Check against OFAC sanctions list (public data)
    const response = await fetch(`${CORS_PROXY}${encodeURIComponent('https://www.treasury.gov/ofac/downloads/sanctions/1.0/sdn_advanced.xml')}`);
    
    if (!response.ok) {
      return { found: false };
    }
    
    const xml = await response.text();
    const isListed = xml.toLowerCase().includes(address.toLowerCase());
    
    return {
      found: isListed,
      sanctioned: isListed,
      source: 'OFAC SDN List',
    };
  } catch (error) {
    console.error('[Chainalysis] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Check against known exchange addresses
async function checkKnownExchanges(address: string, crypto: string): Promise<any> {
  try {
    console.log(`[Exchange Check] Checking ${crypto}: ${address}`);
    
    // Static list of known exchange patterns and addresses
    const knownExchanges: Record<string, string[]> = {
      bitcoin: [
        '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', // Binance
        '3FupZp77ySr7jwoLYBUzwUvJdz2yCXzRwP', // Kraken
        // Add more known addresses
      ],
      ethereum: [
        '0x742d35cc6e5d5a7e1e1c3c69c9c08c4c4c7c7c7c', // Example
        // Add more known addresses
      ],
    };
    
    const exchangeAddresses = knownExchanges[crypto] || [];
    const isKnownExchange = exchangeAddresses.includes(address);
    
    return {
      found: isKnownExchange,
      isExchange: isKnownExchange,
      name: isKnownExchange ? 'Known Exchange' : 'Unknown',
    };
  } catch (error) {
    console.error('[Exchange Check] Error:', error);
    return { error: error instanceof Error ? error.message : 'Query failed' };
  }
}

// Calculate risk score based on multiple factors
function calculateCryptoRisk(sources: Record<string, any>, address: string, crypto: string): {
  riskScore: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  flags: string[];
  tags: string[];
} {
  let riskScore = 0;
  const flags: string[] = [];
  const tags: string[] = [];
  
  // Check sanctions
  if (sources.chainalysis?.sanctioned) {
    riskScore += 100;
    flags.push('OFAC Sanctioned');
    tags.push('sanctioned');
  }
  
  // Check Crystal risk score
  if (sources.crystal?.riskScore) {
    riskScore += Math.min(sources.crystal.riskScore, 50);
    if (sources.crystal.riskScore > 80) {
      flags.push('High Risk (Crystal)');
    }
    tags.push(...(sources.crystal.categories || []));
  }
  
  // Check transaction patterns
  const txCount = sources.blockcypher?.n_tx || sources.etherscan?.transactionCount || sources.blockchain?.transactionCount || 0;
  const balance = sources.blockcypher?.balance || sources.etherscan?.balance || sources.blockchain?.balance || 0;
  
  // High transaction volume with low balance (potential mixer/tumbler)
  if (txCount > 1000 && balance < 0.1) {
    riskScore += 30;
    flags.push('High Transaction Volume, Low Balance');
    tags.push('potential-mixer');
  }
  
  // Very high transaction count
  if (txCount > 10000) {
    riskScore += 20;
    flags.push('Very High Transaction Count');
    tags.push('high-activity');
  }
  
  // Check if it's a known exchange (reduces risk)
  if (sources.exchange?.isExchange) {
    riskScore = Math.max(0, riskScore - 20);
    tags.push('exchange');
  }
  
  // Determine risk level
  let riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  if (riskScore >= 80) riskLevel = 'critical';
  else if (riskScore >= 60) riskLevel = 'high';
  else if (riskScore >= 40) riskLevel = 'medium';
  else if (riskScore >= 20) riskLevel = 'low';
  else riskLevel = 'clean';
  
  return {
    riskScore: Math.min(riskScore, 100),
    riskLevel,
    flags,
    tags,
  };
}

// Main crypto scanner function
export async function scanCryptoAddress(address: string): Promise<CryptoScanResult> {
  const crypto = detectCryptoType(address);
  
  if (crypto === 'unknown') {
    return {
      success: false,
      address,
      blockchain: 'unknown',
      balance: 0,
      transactions: 0,
      firstSeen: null,
      lastSeen: null,
      risk: 'clean',
      riskScore: 0,
      flags: ['Invalid or unsupported address format'],
      tags: [],
      relatedAddresses: [],
      sources: {},
      timestamp: new Date().toISOString(),
    };
  }
  
  console.log(`[CryptoScanner] Starting scan for ${crypto} address: ${address}`);
  
  const sources: Record<string, any> = {};
  const errors: string[] = [];
  
  try {
    // Query multiple sources in parallel
    const queries = [
      // Blockchain data
      crypto === 'bitcoin' ? queryBlockchainInfo(address) : null,
      crypto === 'ethereum' ? queryEtherscan(address) : null,
      ['bitcoin', 'litecoin', 'dogecoin'].includes(crypto) ? queryBlockCypher(address, crypto) : null,
      
      // Risk analysis
      queryCrystalBlockchain(address, crypto),
      queryChainAnalysis(address),
      checkKnownExchanges(address, crypto),
    ].filter(Boolean);
    
    const results = await Promise.allSettled(queries as Promise<any>[]);
    
    // Process results
    if (crypto === 'bitcoin' && results[0]?.status === 'fulfilled') {
      sources.blockchain = (results[0] as any).value;
    }
    if (crypto === 'ethereum' && results[1]?.status === 'fulfilled') {
      sources.etherscan = (results[1] as any).value;
    }
    if (['bitcoin', 'litecoin', 'dogecoin'].includes(crypto) && results[2]?.status === 'fulfilled') {
      sources.blockcypher = (results[2] as any).value;
    }
    
    // Risk analysis results
    const crystalIndex = crypto === 'bitcoin' ? 3 : crypto === 'ethereum' ? 3 : 3;
    if (results[crystalIndex]?.status === 'fulfilled') {
      sources.crystal = (results[crystalIndex] as any).value;
    }
    if (results[crystalIndex + 1]?.status === 'fulfilled') {
      sources.chainalysis = (results[crystalIndex + 1] as any).value;
    }
    if (results[crystalIndex + 2]?.status === 'fulfilled') {
      sources.exchange = (results[crystalIndex + 2] as any).value;
    }
    
    // Extract basic information
    const balance = sources.blockchain?.balance || sources.etherscan?.balance || sources.blockcypher?.balance || 0;
    const transactions = sources.blockchain?.transactionCount || sources.etherscan?.transactionCount || sources.blockcypher?.n_tx || 0;
    
    // Calculate risk
    const riskAssessment = calculateCryptoRisk(sources, address, crypto);
    
    // Get transaction timestamps
    let firstSeen: string | null = null;
    let lastSeen: string | null = null;
    
    if (sources.blockchain?.transactions?.length > 0) {
      const sortedTxs = sources.blockchain.transactions.sort((a: any, b: any) => new Date(a.time).getTime() - new Date(b.time).getTime());
      firstSeen = sortedTxs[0].time;
      lastSeen = sortedTxs[sortedTxs.length - 1].time;
    }
    
    return {
      success: true,
      address,
      blockchain: crypto,
      balance,
      transactions,
      firstSeen,
      lastSeen,
      risk: riskAssessment.riskLevel,
      riskScore: riskAssessment.riskScore,
      flags: riskAssessment.flags,
      tags: riskAssessment.tags,
      relatedAddresses: [],
      exchangeInfo: sources.exchange?.found ? {
        name: sources.exchange.name,
        isExchange: sources.exchange.isExchange,
        isKnown: true,
      } : undefined,
      sources,
      timestamp: new Date().toISOString(),
    };
    
  } catch (error) {
    console.error('[CryptoScanner] Fatal error:', error);
    return {
      success: false,
      address,
      blockchain: crypto,
      balance: 0,
      transactions: 0,
      firstSeen: null,
      lastSeen: null,
      risk: 'clean',
      riskScore: 0,
      flags: [`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`],
      tags: [],
      relatedAddresses: [],
      sources,
      timestamp: new Date().toISOString(),
    };
  }
}

// Get risk color for UI
export function getCryptoRiskColor(level: string): string {
  switch (level) {
    case 'critical': return 'text-red-500';
    case 'high': return 'text-orange-500';
    case 'medium': return 'text-yellow-500';
    case 'low': return 'text-blue-500';
    default: return 'text-green-500';
  }
}

// Get risk background color for UI
export function getCryptoRiskBgColor(level: string): string {
  switch (level) {
    case 'critical': return 'bg-red-500/20 border-red-500';
    case 'high': return 'bg-orange-500/20 border-orange-500';
    case 'medium': return 'bg-yellow-500/20 border-yellow-500';
    case 'low': return 'bg-blue-500/20 border-blue-500';
    default: return 'bg-green-500/20 border-green-500';
  }
}
