
import { useState, ChangeEvent } from 'react';
import { Search, Shield, AlertTriangle, Globe, Hash, Mail, Loader2, Bitcoin, Activity, DollarSign, Eye, Clock, Target, Database, Camera, Upload, Image as ImageIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { queryThreatIntel, ThreatIntelResult, getRiskColor, getRiskBgColor } from '@/services/threatIntelService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { DarkLookups } from './DarkLookups';

// ============================================================================
// CRYPTO ABUSE TYPES & FUNCTIONS
// ============================================================================

interface CryptoAbuseResult {
  address: string;
  network: 'bitcoin' | 'ethereum' | 'tron' | 'unknown';
  summary: string;
  threatLevel: string;
  confidence: number;
  timestamp?: string;
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
  console.log(`[CryptoAbuse] Analyzing ${network} address: ${address}`);
  
  try {
    const response = await fetch('https://greasshostte.app.n8n.cloud/webhook/soc-osint-analysis', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        chatInput: `Bitcoin details ${address}`
      })
    });

    if (!response.ok) {
      throw new Error(`API returned status ${response.status}`);
    }

    const data = await response.json();
    console.log('[CryptoAbuse] API Response:', data);

    if (!data.output || !data.output.summary) {
      throw new Error('Invalid response format from API');
    }

    const result: CryptoAbuseResult = {
      address,
      network,
      summary: data.output.summary,
      threatLevel: data.output.threatLevel || 'unknown',
      confidence: data.output.confidence || 0,
      timestamp: data.output.timestamp,
    };

    console.log(`[CryptoAbuse] ✅ Analysis complete - Threat Level: ${result.threatLevel}, Confidence: ${result.confidence}%`);
    return result;

  } catch (err) {
    console.error('[CryptoAbuse] ❌ Analysis failed:', err);
    throw new Error(err instanceof Error ? err.message : 'Failed to analyze cryptocurrency address');
  }
}

export function ThreatIntelSearch() {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<'ip' | 'domain' | 'url' | 'hash' | 'crypto' | 'crimewall' | 'darklookups'>('ip');
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
          setLoading(false);
          toast.error('Invalid cryptocurrency address format. Supported: Bitcoin (1.../3.../bc1...), Ethereum (0x...), Tron (T...)');
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
        
        toast.success(
          `✅ Analysis complete - ${abuseResult.threatLevel.toUpperCase()} threat level (${abuseResult.confidence}% confidence) - ${(searchTime / 1000).toFixed(1)}s`
        );
      } else if (searchType !== 'crimewall') {
        // Handle regular threat intel search (excluding crimewall which has its own handler)
        const validType = searchType as 'ip' | 'domain' | 'url' | 'hash' | 'email';
        const data = await queryThreatIntel(validType, query.trim());
        setResult(data);
        
        if (data.errors && data.errors.length > 0) {
          toast.warning(`Some sources failed: ${data.errors.join(', ')}`);
        } else {
          toast.success('Threat intelligence retrieved successfully');
        }
      }
    } catch (error) {
      console.error('[Search] Error:', error);
      toast.error(error instanceof Error ? error.message : 'Search failed. Check console for details.');
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
      case 'crimewall': return <Camera className="h-4 w-4" />;
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
            <TabsList className="grid w-full grid-cols-7">
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
              <TabsTrigger value="crimewall" className="flex items-center gap-2">
                <Camera className="h-4 w-4" /> CrimeWall
              </TabsTrigger>
              <TabsTrigger value="darklookups" className="flex items-center gap-2">
                <Database className="h-4 w-4" /> DarkLookups
              </TabsTrigger>
            </TabsList>
          </Tabs>

          {searchType === 'darklookups' ? (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Database className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold">Dark Lookups - Breach Database</h3>
                    <p className="text-sm text-muted-foreground">
                      Check if your email has been compromised in known data breaches
                    </p>
                  </div>
                </div>
              </div>

              <Card className="border-primary/20 bg-card/50 backdrop-blur overflow-hidden">
                <CardContent className="p-0">
                  <div className="relative w-full" style={{ height: '800px' }}>
                    <iframe
                      src="https://breach-guard-7cd9915d.base44.app/"
                      className="w-full h-full border-0"
                      style={{
                        marginTop: '-60px',
                        height: 'calc(100% + 60px)',
                      }}
                      title="Breach Guard Database"
                      sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
                    />
                  </div>
                </CardContent>
              </Card>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="border-primary/20">
                  <CardHeader>
                    <CardTitle className="text-base">What We Check</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm text-muted-foreground space-y-2">
                    <p>• Known data breaches and leaks</p>
                    <p>• Exposed passwords and credentials</p>
                    <p>• Dark web monitoring results</p>
                    <p>• Historical breach databases</p>
                  </CardContent>
                </Card>

                <Card className="border-primary/20">
                  <CardHeader>
                    <CardTitle className="text-base">Privacy Notice</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm text-muted-foreground space-y-2">
                    <p>• Queries are not logged or stored</p>
                    <p>• Secure encrypted connections</p>
                    <p>• No data shared with third parties</p>
                    <p>• Results shown only to you</p>
                  </CardContent>
                </Card>
              </div>
            </div>
          ) : searchType !== 'crimewall' ? (
            <>
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
                  ? 'AI-powered blockchain intelligence analysis | Example: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT' 
                  : 'Sources: VirusTotal, Abuse.ch (Feodo, SSL Blacklist), CIRCL Hashlookup, Spamhaus DROP'
                }
              </div>
            </>
          ) : (
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-primary/10 rounded-lg">
                    <Camera className="h-5 w-5 text-primary" />
                  </div>
                  <div>
                    <h3 className="text-lg font-semibold">CrimeWall - Visual Intelligence</h3>
                    <p className="text-sm text-muted-foreground">
                      Upload images to check against criminal databases and detect scam usage, manipulation, and reuse
                    </p>
                  </div>
                </div>
              </div>

              <Card className="border-primary/20 bg-card/50 backdrop-blur overflow-hidden">
                <CardContent className="p-0">
                  <div className="relative w-full" style={{ height: '800px' }}>
                    <iframe
                      src="https://osint-vision-3e595c85.base44.app/"
                      className="w-full h-full border-0"
                      style={{
                        marginTop: '-60px',
                        height: 'calc(100% + 60px)',
                      }}
                      title="OSINT Vision - CrimeWall"
                      sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
                    />
                  </div>
                </CardContent>
              </Card>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Card className="border-primary/20">
                  <CardHeader>
                    <CardTitle className="text-base">Criminal Database Analysis</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm text-muted-foreground space-y-2">
                    <p>• Interpol criminal databases</p>
                    <p>• FBI and international agencies</p>
                    <p>• Scam and fraud detection</p>
                    <p>• Image manipulation analysis</p>
                  </CardContent>
                </Card>

                <Card className="border-primary/20">
                  <CardHeader>
                    <CardTitle className="text-base">Image Intelligence</CardTitle>
                  </CardHeader>
                  <CardContent className="text-sm text-muted-foreground space-y-2">
                    <p>• Reverse image search</p>
                    <p>• Digital fingerprinting</p>
                    <p>• Metadata extraction</p>
                    <p>• Reuse detection across web</p>
                  </CardContent>
                </Card>
              </div>
            </div>
          )}
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
          {/* Crypto Analysis Summary Card */}
          <Card className={cn(
            'border-2',
            cryptoResult.threatLevel === 'critical' ? 'border-red-500/50 bg-red-500/5' :
            cryptoResult.threatLevel === 'high' ? 'border-orange-500/50 bg-orange-500/5' :
            cryptoResult.threatLevel === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
            'border-green-500/50 bg-green-500/5'
          )}>
            <CardHeader>
              <div className="flex items-center justify-between flex-wrap gap-3">
                <CardTitle className="flex items-center gap-2">
                  <Bitcoin className="h-5 w-5" />
                  Cryptocurrency Intelligence Analysis
                  <Badge className={cn(
                    'ml-2',
                    cryptoResult.threatLevel === 'critical' ? 'bg-red-500' :
                    cryptoResult.threatLevel === 'high' ? 'bg-orange-500' :
                    cryptoResult.threatLevel === 'medium' ? 'bg-yellow-500' :
                    'bg-green-500'
                  )}>
                    {cryptoResult.threatLevel.toUpperCase()}
                  </Badge>
                </CardTitle>
                <Badge variant="outline" className="text-sm">
                  Confidence: {cryptoResult.confidence}%
                </Badge>
              </div>
              <div className="text-sm text-muted-foreground mt-2">
                <span className="font-medium">{cryptoResult.network.toUpperCase()}</span> Address: 
                <span className="font-mono ml-1">{cryptoResult.address}</span>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* AI Analysis Summary */}
              <div className="p-4 bg-muted/50 rounded-lg border">
                <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  Intelligence Summary
                </h3>
                <p className="text-sm leading-relaxed text-foreground whitespace-pre-wrap">
                  {cryptoResult.summary}
                </p>
              </div>

              {/* Metadata Footer */}
              {cryptoResult.timestamp && (
                <div className="flex items-center justify-between text-xs text-muted-foreground pt-3 border-t">
                  <div className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    <span>Analysis timestamp: {cryptoResult.timestamp}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <Target className="h-3 w-3" />
                    <span>Powered by AI Intelligence</span>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
