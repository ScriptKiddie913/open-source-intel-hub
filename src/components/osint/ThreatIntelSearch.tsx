import { useState } from 'react';
import { Search, Shield, AlertTriangle, Globe, Hash, Mail, Loader2, Bitcoin, Activity, DollarSign, Eye, Clock, Target, Database } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { queryThreatIntel, ThreatIntelResult, getRiskColor, getRiskBgColor } from '@/services/threatIntelService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

// ============================================================================
// CRYPTO ABUSE TYPES & FUNCTIONS
// ============================================================================

interface CryptoAbuseReport {
  source: string;
  category: string;
  description: string;
  date: string;
  amount?: number;
  family?: string;
  confidence?: number;
  url?: string;
}

interface CryptoAbuseResult {
  address: string;
  network: 'bitcoin' | 'ethereum' | 'tron' | 'unknown';
  isAbuse: boolean;
  abuseType: string;
  confidence: number;
  reports: CryptoAbuseReport[];
  totalReports: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'info';
  metadata: {
    balance?: number;
    totalReceived?: number;
    totalSent?: number;
    transactionCount?: number;
    firstSeen?: string;
    lastSeen?: string;
    labels?: string[];
  };
}

// Detect cryptocurrency wallet address and return its type
function detectCryptoWallet(input: string): 'bitcoin' | 'ethereum' | 'tron' | null {
  const trimmed = input.trim();
  
  // Bitcoin address patterns
  if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(trimmed) || // Legacy P2PKH/P2SH
      /^bc1[a-z0-9]{39,59}$/.test(trimmed)) { // Bech32
    return 'bitcoin';
  }
  
  // Ethereum address pattern
  if (/^0x[a-fA-F0-9]{40}$/.test(trimmed)) {
    return 'ethereum';
  }
  
  // Tron address pattern
  if (/^T[A-Za-z1-9]{33}$/.test(trimmed)) {
    return 'tron';
  }
  
  return null;
}

// Check cryptocurrency address for abuse reports
async function checkCryptoAbuse(
  address: string, 
  network: 'bitcoin' | 'ethereum' | 'tron'
): Promise<CryptoAbuseResult> {
  console.log(`[CryptoAbuse] Checking ${network} address: ${address}`);
  
  const result: CryptoAbuseResult = {
    address,
    network,
    isAbuse: false,
    abuseType: '',
    confidence: 0,
    reports: [],
    totalReports: 0,
    riskLevel: 'info',
    metadata: {},
  };
  
  const promises: Promise<void>[] = [];
  
  // BitcoinAbuse API check
  if (network === 'bitcoin') {
    promises.push(
      (async () => {
        try {
          console.log('[BitcoinAbuse] Checking abuse reports...');
          const response = await fetch(`https://www.bitcoinabuse.com/api/reports/check?address=${address}`);
          if (response.ok) {
            const data = await response.json();
            if (data.count > 0 && data.reports) {
              result.isAbuse = true;
              result.totalReports += data.count;
              data.reports.forEach((report: any) => {
                result.reports.push({
                  source: 'BitcoinAbuse',
                  category: report.abuse_type || 'Unknown',
                  description: report.description || '',
                  date: report.date || '',
                  url: 'https://www.bitcoinabuse.com',
                });
              });
            }
          }
        } catch (err) {
          console.warn('[BitcoinAbuse] API error:', err);
        }
      })()
    );
  }
  
  // Ransomwhere check
  if (network === 'bitcoin') {
    promises.push(
      (async () => {
        try {
          console.log('[Ransomwhere] Checking ransomware database...');
          const response = await fetch('https://ransomwhe.re/export.json');
          if (response.ok) {
            const data = await response.json();
            const match = data.find((item: any) => item.address === address);
            if (match) {
              result.isAbuse = true;
              result.totalReports += 1;
              result.reports.push({
                source: 'Ransomwhere',
                category: 'Ransomware',
                description: `Ransomware family: ${match.family || 'Unknown'}`,
                date: match.date || '',
                amount: match.amount,
                family: match.family,
                url: 'https://ransomwhe.re',
              });
            }
          }
        } catch (err) {
          console.warn('[Ransomwhere] API error:', err);
        }
      })()
    );
  }
  
  // Blockchain analysis
  promises.push(
    (async () => {
      try {
        if (network === 'bitcoin') {
          console.log('[Blockchain] Fetching Bitcoin address info...');
          const response = await fetch(`https://blockchain.info/rawaddr/${address}`);
          if (response.ok) {
            const data = await response.json();
            result.metadata = {
              balance: data.final_balance / 100000000, // Convert satoshis to BTC
              totalReceived: data.total_received / 100000000,
              totalSent: data.total_sent / 100000000,
              transactionCount: data.n_tx,
            };
          }
        }
      } catch (err) {
        console.warn('[Blockchain] Analysis error:', err);
      }
    })()
  );
  
  // Wait for all checks to complete
  await Promise.allSettled(promises);
  
  // Determine abuse type and risk level
  if (result.reports.length > 0) {
    const categories = result.reports.map(r => r.category.toLowerCase());
    
    if (categories.some(c => c.includes('ransomware'))) {
      result.abuseType = 'Ransomware';
      result.riskLevel = 'critical';
      result.confidence = 95;
    } else if (categories.some(c => c.includes('scam') || c.includes('fraud'))) {
      result.abuseType = 'Scam/Fraud';
      result.riskLevel = 'high';
      result.confidence = 85;
    } else if (categories.some(c => c.includes('phishing'))) {
      result.abuseType = 'Phishing';
      result.riskLevel = 'high';
      result.confidence = 80;
    } else {
      result.abuseType = 'Suspicious Activity';
      result.riskLevel = 'medium';
      result.confidence = 60;
    }
    
    // Increase confidence based on number of reports
    result.confidence = Math.min(99, result.confidence + (result.totalReports * 5));
  }
  
  return result;
}

export function ThreatIntelSearch() {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<'ip' | 'domain' | 'url' | 'hash' | 'crypto'>('ip');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatIntelResult | null>(null);
  const [cryptoResult, setCryptoResult] = useState<CryptoAbuseResult | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) {
      toast.error('Please enter a target to search');
      return;
    }

    setLoading(true);
    setResult(null);
    setCryptoResult(null);

    try {
      if (searchType === 'crypto') {
        // Handle crypto abuse search
        const cryptoType = detectCryptoWallet(query.trim());
        if (!cryptoType) {
          toast.error('Invalid cryptocurrency address format');
          return;
        }

        console.log(`\n${'='.repeat(60)}`);
        console.log(`[CryptoAbuse] SCANNING WALLET: "${query}"`);
        console.log(`[CryptoAbuse] NETWORK: ${cryptoType.toUpperCase()}`);
        console.log(`${'='.repeat(60)}\n`);
        
        const startTime = Date.now();
        const abuseResult = await checkCryptoAbuse(query.trim(), cryptoType);
        setCryptoResult(abuseResult);
        
        const searchTime = Date.now() - startTime;
        
        if (abuseResult.isAbuse) {
          toast.error(
            `⚠️ ABUSE DETECTED: ${abuseResult.abuseType} (${abuseResult.totalReports} reports) - ${(searchTime / 1000).toFixed(1)}s`
          );
        } else {
          toast.success(
            `✅ Address appears clean - No abuse reports found in ${(searchTime / 1000).toFixed(1)}s`
          );
        }
      } else {
        // Handle regular threat intel search
        const data = await queryThreatIntel(searchType, query.trim());
        setResult(data);
        
        if (data.errors && data.errors.length > 0) {
          toast.warning(`Some sources failed: ${data.errors.join(', ')}`);
        } else {
          toast.success('Threat intelligence retrieved successfully');
        }
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to query threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ip': return <Globe className="h-4 w-4" />;
      case 'domain': return <Globe className="h-4 w-4" />;
      case 'url': return <Globe className="h-4 w-4" />;
      case 'hash': return <Hash className="h-4 w-4" />;
      case 'crypto': return <Bitcoin className="h-4 w-4" />;
      default: return <Search className="h-4 w-4" />;
    }
  };

  return (
    <div className="space-y-6">
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <Shield className="h-5 w-5 text-primary" />
            VirusTotal & Threat Intelligence Search
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={searchType} onValueChange={(v) => setSearchType(v as any)}>
            <TabsList className="grid w-full grid-cols-5">
              <TabsTrigger value="ip" className="flex items-center gap-2">
                <Globe className="h-4 w-4" /> IP
              </TabsTrigger>
              <TabsTrigger value="domain" className="flex items-center gap-2">
                <Globe className="h-4 w-4" /> Domain
              </TabsTrigger>
              <TabsTrigger value="url" className="flex items-center gap-2">
                <Globe className="h-4 w-4" /> URL
              </TabsTrigger>
              <TabsTrigger value="hash" className="flex items-center gap-2">
                <Hash className="h-4 w-4" /> Hash
              </TabsTrigger>
              <TabsTrigger value="crypto" className="flex items-center gap-2">
                <Bitcoin className="h-4 w-4" /> Crypto
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <div className="flex gap-2">
            <Input
              placeholder={
                searchType === 'crypto' 
                  ? 'Enter Bitcoin/Ethereum/Tron wallet address...'
                  : `Enter ${searchType} to analyze...`
              }
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              className="flex-1 bg-background border-border"
            />
            <Button onClick={handleSearch} disabled={loading} className="min-w-[120px]">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  {getTypeIcon(searchType)}
                  <span className="ml-2">{searchType === 'crypto' ? 'Check' : 'Analyze'}</span>
                </>
              )}
            </Button>
          </div>

          <div className="text-xs text-muted-foreground">
            {searchType === 'crypto' 
              ? 'Sources: BitcoinAbuse, Ransomwhere, Chainabuse, Blockchain.info' 
              : 'Sources: VirusTotal, Abuse.ch (Feodo, SSL Blacklist), CIRCL Hashlookup, Spamhaus DROP'
            }
          </div>
        </CardContent>
      </Card>

      {/* Regular Threat Intel Results */}
      {result && (
        <div className="space-y-4">{/* AI-Formatted Summary */}
          {result.formatted && (
            <Card className={`border ${getRiskBgColor(result.formatted.riskLevel)}`}>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <AlertTriangle className={`h-5 w-5 ${getRiskColor(result.formatted.riskLevel)}`} />
                    Threat Assessment
                  </span>
                  <Badge variant="outline" className={getRiskColor(result.formatted.riskLevel)}>
                    Risk Score: {result.formatted.riskScore}/100
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="text-sm">
                  <strong>Summary:</strong> {result.formatted.summary}
                </div>

                {/* Detections Table */}
                {result.formatted.detections && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Detection Results</h4>
                    <div className="grid grid-cols-4 gap-2">
                      <div className="bg-red-500/10 border border-red-500/30 rounded p-2 text-center">
                        <div className="text-lg font-bold text-red-500">{result.formatted.detections.malicious}</div>
                        <div className="text-xs text-muted-foreground">Malicious</div>
                      </div>
                      <div className="bg-orange-500/10 border border-orange-500/30 rounded p-2 text-center">
                        <div className="text-lg font-bold text-orange-500">{result.formatted.detections.suspicious}</div>
                        <div className="text-xs text-muted-foreground">Suspicious</div>
                      </div>
                      <div className="bg-green-500/10 border border-green-500/30 rounded p-2 text-center">
                        <div className="text-lg font-bold text-green-500">{result.formatted.detections.clean}</div>
                        <div className="text-xs text-muted-foreground">Clean</div>
                      </div>
                      <div className="bg-muted/50 border border-border rounded p-2 text-center">
                        <div className="text-lg font-bold">{result.formatted.detections.undetected}</div>
                        <div className="text-xs text-muted-foreground">Undetected</div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Indicators Table */}
                {result.formatted.indicators && result.formatted.indicators.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Threat Indicators</h4>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Type</TableHead>
                          <TableHead>Value</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Severity</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {result.formatted.indicators.map((indicator, idx) => (
                          <TableRow key={idx}>
                            <TableCell className="font-medium">{indicator.type}</TableCell>
                            <TableCell className="font-mono text-xs max-w-[200px] truncate">
                              {indicator.value}
                            </TableCell>
                            <TableCell>{indicator.source}</TableCell>
                            <TableCell>
                              <Badge variant="outline" className={getRiskColor(indicator.severity)}>
                                {indicator.severity}
                              </Badge>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                )}

                {/* Categories */}
                {result.formatted.categories && result.formatted.categories.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Categories</h4>
                    <div className="flex flex-wrap gap-2">
                      {result.formatted.categories.map((cat, idx) => (
                        <Badge key={idx} variant="secondary">{cat}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {result.formatted.recommendations && result.formatted.recommendations.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Recommendations</h4>
                    <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
                      {result.formatted.recommendations.map((rec, idx) => (
                        <li key={idx}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Metadata */}
                {result.formatted.metadata && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-2 border-t border-border">
                    {result.formatted.metadata.country && (
                      <div>
                        <div className="text-xs text-muted-foreground">Country</div>
                        <div className="text-sm font-medium">{result.formatted.metadata.country}</div>
                      </div>
                    )}
                    {result.formatted.metadata.asn && (
                      <div>
                        <div className="text-xs text-muted-foreground">ASN</div>
                        <div className="text-sm font-medium">{result.formatted.metadata.asn}</div>
                      </div>
                    )}
                    {result.formatted.metadata.owner && (
                      <div>
                        <div className="text-xs text-muted-foreground">Owner</div>
                        <div className="text-sm font-medium">{result.formatted.metadata.owner}</div>
                      </div>
                    )}
                    {result.formatted.metadata.lastAnalysis && (
                      <div>
                        <div className="text-xs text-muted-foreground">Last Analysis</div>
                        <div className="text-sm font-medium">
                          {new Date(result.formatted.metadata.lastAnalysis).toLocaleDateString()}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Raw Data Display */}
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="text-sm">Raw API Response</CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-background p-4 rounded-lg overflow-auto max-h-[400px] text-xs">
                {JSON.stringify(result.raw, null, 2)}
              </pre>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Crypto Abuse Results */}
      {cryptoResult && (
        <div className="space-y-4">
          {/* Crypto Overview Card */}
          <Card className={cn(
            'border-2',
            cryptoResult.riskLevel === 'critical' ? 'border-red-500/50 bg-red-500/5' :
            cryptoResult.riskLevel === 'high' ? 'border-orange-500/50 bg-orange-500/5' :
            cryptoResult.riskLevel === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
            'border-green-500/50 bg-green-500/5'
          )}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Bitcoin className="h-5 w-5" />
                  Cryptocurrency Abuse Analysis
                  <Badge className={cn(
                    'ml-2',
                    cryptoResult.riskLevel === 'critical' ? 'bg-red-500' :
                    cryptoResult.riskLevel === 'high' ? 'bg-orange-500' :
                    cryptoResult.riskLevel === 'medium' ? 'bg-yellow-500' :
                    'bg-green-500'
                  )}>
                    {cryptoResult.isAbuse ? `${cryptoResult.abuseType} - ${cryptoResult.riskLevel.toUpperCase()}` : 'CLEAN'}
                  </Badge>
                </CardTitle>
                <Badge variant="outline">
                  Confidence: {cryptoResult.confidence}%
                </Badge>
              </div>
              <div className="text-sm text-muted-foreground">
                <span className="font-medium">{cryptoResult.network.toUpperCase()}</span> Address: {cryptoResult.address}
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-red-500">{cryptoResult.totalReports}</div>
                  <div className="text-xs text-muted-foreground">Abuse Reports</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-orange-500">{cryptoResult.confidence}%</div>
                  <div className="text-xs text-muted-foreground">Confidence</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-500">{cryptoResult.metadata?.transactionCount || '—'}</div>
                  <div className="text-xs text-muted-foreground">Transactions</div>
                </div>
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-500">
                    {cryptoResult.metadata?.balance ? cryptoResult.metadata.balance.toFixed(6) : '—'}
                  </div>
                  <div className="text-xs text-muted-foreground">Balance ({cryptoResult.network.toUpperCase()})</div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Abuse Reports */}
          {cryptoResult.reports.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-red-500" />
                  Abuse Reports ({cryptoResult.reports.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {cryptoResult.reports.map((report, i) => (
                    <div key={i} className="p-4 border rounded bg-muted/50">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <Badge variant="outline">{report.source}</Badge>
                          <Badge className={cn(
                            report.category.toLowerCase().includes('ransomware') ? 'bg-red-500' :
                            report.category.toLowerCase().includes('scam') ? 'bg-orange-500' :
                            'bg-yellow-500'
                          )}>
                            {report.category}
                          </Badge>
                        </div>
                        <div className="text-xs text-muted-foreground">{report.date}</div>
                      </div>
                      <div className="text-sm mb-2">{report.description}</div>
                      {report.amount && (
                        <div className="text-xs text-muted-foreground">
                          Amount: {report.amount} BTC
                        </div>
                      )}
                      {report.family && (
                        <div className="text-xs text-muted-foreground">
                          Family: {report.family}
                        </div>
                      )}
                      {report.url && (
                        <a href={report.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-500 hover:underline flex items-center gap-1 mt-1">
                          View Source <Database className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Blockchain Metadata */}
          {cryptoResult.metadata && Object.keys(cryptoResult.metadata).length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5" />
                  Blockchain Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {cryptoResult.metadata.totalReceived && (
                    <div className="p-3 border rounded">
                      <div className="text-sm font-medium">Total Received</div>
                      <div className="text-lg font-bold">{cryptoResult.metadata.totalReceived.toFixed(6)} {cryptoResult.network.toUpperCase()}</div>
                    </div>
                  )}
                  {cryptoResult.metadata.totalSent && (
                    <div className="p-3 border rounded">
                      <div className="text-sm font-medium">Total Sent</div>
                      <div className="text-lg font-bold">{cryptoResult.metadata.totalSent.toFixed(6)} {cryptoResult.network.toUpperCase()}</div>
                    </div>
                  )}
                  {cryptoResult.metadata.labels && cryptoResult.metadata.labels.length > 0 && (
                    <div className="p-3 border rounded col-span-full">
                      <div className="text-sm font-medium mb-2">Labels</div>
                      <div className="flex flex-wrap gap-2">
                        {cryptoResult.metadata.labels.map((label, i) => (
                          <Badge key={i} variant="outline">{label}</Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
