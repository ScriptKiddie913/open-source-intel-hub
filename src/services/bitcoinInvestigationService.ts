// ============================================================================
// bitcoinInvestigationService.ts
// BITCOIN & CRYPTOCURRENCY INVESTIGATION MODULE
// ============================================================================
// Features:
// - Address balance and transaction history
// - Transaction tracing and flow analysis
// - Wallet clustering and entity identification
// - Risk scoring and threat intelligence
// - Exchange identification
// - Mixer/Tumbler detection
// ============================================================================

import { cacheAPIResponse, getCachedData } from '@/lib/database';

const CACHE_TTL = 15; // minutes

// ============================================================================
// TYPES
// ============================================================================

export interface BitcoinAddress {
  address: string;
  format: 'legacy' | 'segwit' | 'bech32';
  balance: number;
  balanceUSD: number;
  totalReceived: number;
  totalSent: number;
  txCount: number;
  firstSeen: string;
  lastSeen: string;
  isExchange: boolean;
  exchangeName?: string;
  riskScore: number;
  riskFactors: string[];
  labels: string[];
}

export interface BitcoinTransaction {
  txid: string;
  blockHeight: number;
  timestamp: string;
  confirmations: number;
  fee: number;
  feeRate: number;
  size: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  totalInput: number;
  totalOutput: number;
  isCoinbase: boolean;
  isSuspicious: boolean;
  suspiciousReasons: string[];
}

export interface TxInput {
  address: string;
  value: number;
  prevTxid: string;
  prevIndex: number;
}

export interface TxOutput {
  address: string;
  value: number;
  index: number;
  spent: boolean;
  spentTxid?: string;
}

export interface AddressCluster {
  clusterId: string;
  addresses: string[];
  totalBalance: number;
  totalTxCount: number;
  entityType: 'exchange' | 'mixer' | 'ransomware' | 'darknet' | 'gambling' | 'unknown';
  entityName?: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  firstActivity: string;
  lastActivity: string;
}

export interface TransactionFlow {
  sourceAddress: string;
  targetAddress: string;
  amount: number;
  txid: string;
  timestamp: string;
  hops: number;
  pathRisk: number;
}

export interface CryptoInvestigationResult {
  address: BitcoinAddress;
  recentTransactions: BitcoinTransaction[];
  connectedAddresses: string[];
  cluster?: AddressCluster;
  flows: TransactionFlow[];
  riskAssessment: {
    score: number;
    level: 'critical' | 'high' | 'medium' | 'low';
    factors: string[];
    recommendations: string[];
  };
  relatedThreats: {
    ransomwareConnection: boolean;
    darknetConnection: boolean;
    sanctionedEntity: boolean;
    mixerUsage: boolean;
    knownScam: boolean;
    details: string[];
  };
}

// ============================================================================
// KNOWN ENTITIES DATABASE
// ============================================================================

const KNOWN_EXCHANGES: Record<string, string> = {
  'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh': 'Binance',
  '1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s': 'Binance',
  '3M219KR5vEneNb47ewrPfWyb5jQ2DjxRP6': 'Binance',
  'bc1qgdjqv0av3q56jvd82tkdjpy7gdp9ut8tlqmgrpmv24sq90ecnvqqjwvw97': 'Bitfinex',
  '1Kr6QSydW9bFQG1mXiPNNu6WpJGmUa9i1g': 'Bitfinex',
  '3JZq4atUahhuA9rLhXLMhhTo133J9rF97j': 'Coinbase',
  'bc1q4c8n5t00jmj8temxdgcc3t32nkg2wjwz24lywv': 'Coinbase',
  '1P5ZEDWTKTFGxQjZphgWPQUpe554WKDfHQ': 'Coinbase',
  '16ftSEQ4ctQFDtVZiUBusQUjRrGhM3JYwe': 'Kraken',
  '3FHNBLobJnbCTFTVakh5TXmEneyf5PT61B': 'Kraken',
  '1FH6ehAd5ZFXCM1cLGzHxK1s4dGdq1JusM': 'Huobi',
};

const KNOWN_RANSOMWARE: Set<string> = new Set([
  '1Mz7153HMuxXTuR2R1t78mGSdzaAtNbBWX', // WannaCry
  '13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94', // WannaCry
  '12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw', // WannaCry
  'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', // Example ransomware
]);

const KNOWN_DARKNET: Set<string> = new Set([
  '1HQ3Go3ggs8pFnXuHVHRytPCq5fGG8Hbhx', // Silk Road
]);

const KNOWN_MIXERS: Set<string> = new Set([
  'bc1qns9f7yfx3ry9lj6yzrkwlmjr8gfpmkhpnew08m', // Example mixer
]);

// ============================================================================
// API FUNCTIONS
// ============================================================================

/**
 * Get Bitcoin address information from blockchain.info
 */
export async function getAddressInfo(address: string): Promise<BitcoinAddress | null> {
  const cacheKey = `btc:address:${address}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    console.log(`[Bitcoin] Fetching address info for ${address}`);
    
    // Use blockchain.info API (free, no auth required)
    const response = await fetch(
      `https://blockchain.info/rawaddr/${address}?limit=10`,
      { headers: { 'Accept': 'application/json' } }
    );

    if (!response.ok) {
      if (response.status === 404) {
        console.log(`[Bitcoin] Address not found: ${address}`);
        return null;
      }
      throw new Error(`Blockchain API error: ${response.status}`);
    }

    const data = await response.json();
    
    // Get current BTC price for USD conversion
    const btcPrice = await getBTCPrice();
    
    // Calculate risk score
    const { riskScore, riskFactors } = calculateRiskScore(address, data);
    
    // Determine address format
    const format = address.startsWith('bc1') ? 'bech32' : 
                   address.startsWith('3') ? 'segwit' : 'legacy';
    
    // Check if known exchange
    const exchangeName = KNOWN_EXCHANGES[address];
    
    const addressInfo: BitcoinAddress = {
      address,
      format,
      balance: data.final_balance / 100000000, // Convert satoshis to BTC
      balanceUSD: (data.final_balance / 100000000) * btcPrice,
      totalReceived: data.total_received / 100000000,
      totalSent: data.total_sent / 100000000,
      txCount: data.n_tx,
      firstSeen: data.txs?.length > 0 
        ? new Date(data.txs[data.txs.length - 1].time * 1000).toISOString()
        : 'Unknown',
      lastSeen: data.txs?.length > 0 
        ? new Date(data.txs[0].time * 1000).toISOString()
        : 'Unknown',
      isExchange: !!exchangeName,
      exchangeName,
      riskScore,
      riskFactors,
      labels: getAddressLabels(address),
    };

    await cacheAPIResponse(cacheKey, addressInfo, CACHE_TTL);
    return addressInfo;
  } catch (error) {
    console.error('[Bitcoin] Address lookup error:', error);
    return null;
  }
}

/**
 * Get transaction details
 */
export async function getTransaction(txid: string): Promise<BitcoinTransaction | null> {
  const cacheKey = `btc:tx:${txid}`;
  const cached = await getCachedData(cacheKey);
  if (cached) return cached;

  try {
    console.log(`[Bitcoin] Fetching transaction: ${txid}`);
    
    const response = await fetch(
      `https://blockchain.info/rawtx/${txid}`,
      { headers: { 'Accept': 'application/json' } }
    );

    if (!response.ok) {
      throw new Error(`Blockchain API error: ${response.status}`);
    }

    const data = await response.json();
    
    // Check for suspicious patterns
    const { isSuspicious, suspiciousReasons } = analyzeTransaction(data);
    
    const tx: BitcoinTransaction = {
      txid: data.hash,
      blockHeight: data.block_height || 0,
      timestamp: new Date(data.time * 1000).toISOString(),
      confirmations: data.block_height ? await getBlockHeight() - data.block_height : 0,
      fee: data.fee || 0,
      feeRate: data.fee && data.size ? Math.round(data.fee / data.size) : 0,
      size: data.size,
      inputs: data.inputs.map((inp: any) => ({
        address: inp.prev_out?.addr || 'Unknown',
        value: (inp.prev_out?.value || 0) / 100000000,
        prevTxid: inp.prev_out?.tx_index?.toString() || '',
        prevIndex: inp.prev_out?.n || 0,
      })),
      outputs: data.out.map((out: any, idx: number) => ({
        address: out.addr || 'Unknown',
        value: out.value / 100000000,
        index: idx,
        spent: out.spent,
        spentTxid: out.spending_outpoints?.[0]?.tx_index?.toString(),
      })),
      totalInput: data.inputs.reduce((sum: number, inp: any) => 
        sum + ((inp.prev_out?.value || 0) / 100000000), 0),
      totalOutput: data.out.reduce((sum: number, out: any) => 
        sum + (out.value / 100000000), 0),
      isCoinbase: data.inputs.some((inp: any) => !inp.prev_out),
      isSuspicious,
      suspiciousReasons,
    };

    await cacheAPIResponse(cacheKey, tx, CACHE_TTL);
    return tx;
  } catch (error) {
    console.error('[Bitcoin] Transaction lookup error:', error);
    return null;
  }
}

/**
 * Get recent transactions for an address
 */
export async function getAddressTransactions(
  address: string, 
  limit: number = 10
): Promise<BitcoinTransaction[]> {
  try {
    const response = await fetch(
      `https://blockchain.info/rawaddr/${address}?limit=${limit}`,
      { headers: { 'Accept': 'application/json' } }
    );

    if (!response.ok) {
      return [];
    }

    const data = await response.json();
    const transactions: BitcoinTransaction[] = [];

    for (const tx of data.txs || []) {
      const { isSuspicious, suspiciousReasons } = analyzeTransaction(tx);
      
      transactions.push({
        txid: tx.hash,
        blockHeight: tx.block_height || 0,
        timestamp: new Date(tx.time * 1000).toISOString(),
        confirmations: tx.block_height ? await getBlockHeight() - tx.block_height : 0,
        fee: tx.fee || 0,
        feeRate: tx.fee && tx.size ? Math.round(tx.fee / tx.size) : 0,
        size: tx.size || 0,
        inputs: tx.inputs?.map((inp: any) => ({
          address: inp.prev_out?.addr || 'Unknown',
          value: (inp.prev_out?.value || 0) / 100000000,
          prevTxid: inp.prev_out?.tx_index?.toString() || '',
          prevIndex: inp.prev_out?.n || 0,
        })) || [],
        outputs: tx.out?.map((out: any, idx: number) => ({
          address: out.addr || 'Unknown',
          value: out.value / 100000000,
          index: idx,
          spent: out.spent,
          spentTxid: out.spending_outpoints?.[0]?.tx_index?.toString(),
        })) || [],
        totalInput: tx.inputs?.reduce((sum: number, inp: any) => 
          sum + ((inp.prev_out?.value || 0) / 100000000), 0) || 0,
        totalOutput: tx.out?.reduce((sum: number, out: any) => 
          sum + (out.value / 100000000), 0) || 0,
        isCoinbase: tx.inputs?.some((inp: any) => !inp.prev_out) || false,
        isSuspicious,
        suspiciousReasons,
      });
    }

    return transactions;
  } catch (error) {
    console.error('[Bitcoin] Transaction history error:', error);
    return [];
  }
}

/**
 * Full investigation for a Bitcoin address
 */
export async function investigateAddress(address: string): Promise<CryptoInvestigationResult | null> {
  try {
    console.log(`[Bitcoin] Starting investigation for ${address}`);
    
    const [addressInfo, transactions] = await Promise.all([
      getAddressInfo(address),
      getAddressTransactions(address, 20),
    ]);

    if (!addressInfo) {
      return null;
    }

    // Extract connected addresses from transactions
    const connectedAddresses = new Set<string>();
    const flows: TransactionFlow[] = [];

    for (const tx of transactions) {
      // Input addresses (senders)
      for (const input of tx.inputs) {
        if (input.address !== address && input.address !== 'Unknown') {
          connectedAddresses.add(input.address);
          flows.push({
            sourceAddress: input.address,
            targetAddress: address,
            amount: input.value,
            txid: tx.txid,
            timestamp: tx.timestamp,
            hops: 1,
            pathRisk: calculateAddressRisk(input.address),
          });
        }
      }

      // Output addresses (receivers)
      for (const output of tx.outputs) {
        if (output.address !== address && output.address !== 'Unknown') {
          connectedAddresses.add(output.address);
          flows.push({
            sourceAddress: address,
            targetAddress: output.address,
            amount: output.value,
            txid: tx.txid,
            timestamp: tx.timestamp,
            hops: 1,
            pathRisk: calculateAddressRisk(output.address),
          });
        }
      }
    }

    // Check for threat connections
    const relatedThreats = {
      ransomwareConnection: KNOWN_RANSOMWARE.has(address) || 
        flows.some(f => KNOWN_RANSOMWARE.has(f.sourceAddress) || KNOWN_RANSOMWARE.has(f.targetAddress)),
      darknetConnection: KNOWN_DARKNET.has(address) ||
        flows.some(f => KNOWN_DARKNET.has(f.sourceAddress) || KNOWN_DARKNET.has(f.targetAddress)),
      sanctionedEntity: false, // Would need OFAC list
      mixerUsage: KNOWN_MIXERS.has(address) ||
        flows.some(f => KNOWN_MIXERS.has(f.sourceAddress) || KNOWN_MIXERS.has(f.targetAddress)),
      knownScam: false, // Would need scam database
      details: [] as string[],
    };

    if (relatedThreats.ransomwareConnection) {
      relatedThreats.details.push('Connected to known ransomware address');
    }
    if (relatedThreats.darknetConnection) {
      relatedThreats.details.push('Connected to known darknet marketplace');
    }
    if (relatedThreats.mixerUsage) {
      relatedThreats.details.push('Mixer/tumbler usage detected');
    }

    // Calculate overall risk assessment
    const riskLevel = addressInfo.riskScore >= 80 ? 'critical' :
                      addressInfo.riskScore >= 60 ? 'high' :
                      addressInfo.riskScore >= 40 ? 'medium' : 'low';

    const recommendations: string[] = [];
    if (riskLevel === 'critical' || riskLevel === 'high') {
      recommendations.push('Flag this address for immediate review');
      recommendations.push('Do not process transactions from this address');
      recommendations.push('Report to relevant authorities if linked to criminal activity');
    }
    if (relatedThreats.mixerUsage) {
      recommendations.push('Enhanced due diligence required - mixer usage detected');
    }
    if (addressInfo.txCount > 1000) {
      recommendations.push('High-volume address - may be service or exchange');
    }

    return {
      address: addressInfo,
      recentTransactions: transactions,
      connectedAddresses: Array.from(connectedAddresses),
      flows,
      riskAssessment: {
        score: addressInfo.riskScore,
        level: riskLevel,
        factors: addressInfo.riskFactors,
        recommendations,
      },
      relatedThreats,
    };
  } catch (error) {
    console.error('[Bitcoin] Investigation error:', error);
    return null;
  }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function getBTCPrice(): Promise<number> {
  try {
    const response = await fetch('https://blockchain.info/ticker');
    if (!response.ok) return 0;
    const data = await response.json();
    return data.USD?.last || 0;
  } catch {
    return 0;
  }
}

async function getBlockHeight(): Promise<number> {
  try {
    const response = await fetch('https://blockchain.info/latestblock');
    if (!response.ok) return 0;
    const data = await response.json();
    return data.height || 0;
  } catch {
    return 0;
  }
}

function calculateRiskScore(address: string, data: any): { riskScore: number; riskFactors: string[] } {
  const factors: string[] = [];
  let score = 0;

  // Check known bad addresses
  if (KNOWN_RANSOMWARE.has(address)) {
    score += 50;
    factors.push('Known ransomware address');
  }
  if (KNOWN_DARKNET.has(address)) {
    score += 40;
    factors.push('Known darknet marketplace');
  }
  if (KNOWN_MIXERS.has(address)) {
    score += 30;
    factors.push('Known mixer/tumbler');
  }

  // Transaction pattern analysis
  if (data.n_tx > 1000) {
    score += 10;
    factors.push('High transaction volume');
  }

  // Large balance without activity
  const balanceBTC = data.final_balance / 100000000;
  if (balanceBTC > 100 && data.n_tx < 10) {
    score += 15;
    factors.push('Large balance with low activity');
  }

  // Many small outputs (potential tumbling)
  const avgOutput = data.total_sent / data.n_tx / 100000000;
  if (avgOutput < 0.01 && data.n_tx > 50) {
    score += 20;
    factors.push('Many small transactions (potential mixing)');
  }

  // New address with large transactions
  if (data.txs?.length > 0) {
    const firstTx = data.txs[data.txs.length - 1];
    const addressAge = Date.now() - (firstTx.time * 1000);
    const daysSinceFirst = addressAge / (1000 * 60 * 60 * 24);
    
    if (daysSinceFirst < 7 && balanceBTC > 10) {
      score += 15;
      factors.push('New address with large balance');
    }
  }

  return { riskScore: Math.min(score, 100), riskFactors: factors };
}

function calculateAddressRisk(address: string): number {
  if (KNOWN_RANSOMWARE.has(address)) return 100;
  if (KNOWN_DARKNET.has(address)) return 90;
  if (KNOWN_MIXERS.has(address)) return 80;
  if (KNOWN_EXCHANGES[address]) return 10;
  return 30; // Unknown = medium risk
}

function analyzeTransaction(tx: any): { isSuspicious: boolean; suspiciousReasons: string[] } {
  const reasons: string[] = [];
  let suspicious = false;

  // Check for peel chain pattern (one large input, two outputs: large + small)
  if (tx.inputs?.length === 1 && tx.out?.length === 2) {
    const values = tx.out.map((o: any) => o.value).sort((a: number, b: number) => b - a);
    if (values[0] > values[1] * 10) {
      reasons.push('Peel chain pattern detected');
      suspicious = true;
    }
  }

  // Many small outputs (potential coinjoin or tumbling)
  if (tx.out?.length > 10) {
    const smallOutputs = tx.out.filter((o: any) => o.value < 100000); // < 0.001 BTC
    if (smallOutputs.length > tx.out.length * 0.5) {
      reasons.push('Many small outputs (potential mixing)');
      suspicious = true;
    }
  }

  // Check for known bad addresses
  for (const input of tx.inputs || []) {
    if (KNOWN_RANSOMWARE.has(input.prev_out?.addr)) {
      reasons.push('Input from ransomware address');
      suspicious = true;
    }
    if (KNOWN_MIXERS.has(input.prev_out?.addr)) {
      reasons.push('Input from mixer');
      suspicious = true;
    }
  }

  for (const output of tx.out || []) {
    if (KNOWN_RANSOMWARE.has(output.addr)) {
      reasons.push('Output to ransomware address');
      suspicious = true;
    }
    if (KNOWN_MIXERS.has(output.addr)) {
      reasons.push('Output to mixer');
      suspicious = true;
    }
  }

  return { isSuspicious: suspicious, suspiciousReasons: reasons };
}

function getAddressLabels(address: string): string[] {
  const labels: string[] = [];
  
  if (KNOWN_EXCHANGES[address]) {
    labels.push(`Exchange: ${KNOWN_EXCHANGES[address]}`);
  }
  if (KNOWN_RANSOMWARE.has(address)) {
    labels.push('Ransomware');
  }
  if (KNOWN_DARKNET.has(address)) {
    labels.push('Darknet');
  }
  if (KNOWN_MIXERS.has(address)) {
    labels.push('Mixer');
  }

  return labels;
}

// ============================================================================
// EXPORTS
// ============================================================================

export const bitcoinService = {
  getAddressInfo,
  getTransaction,
  getAddressTransactions,
  investigateAddress,
  getBTCPrice,
};
