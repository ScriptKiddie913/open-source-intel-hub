import { useState } from 'react';
import { Search, Shield, AlertTriangle, Globe, Hash, Mail, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { queryThreatIntel, ThreatIntelResult, getRiskColor, getRiskBgColor } from '@/services/threatIntelService';
import { toast } from 'sonner';

export function ThreatIntelSearch() {
  const [query, setQuery] = useState('');
  const [searchType, setSearchType] = useState<'ip' | 'domain' | 'url' | 'hash'>('ip');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatIntelResult | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) {
      toast.error('Please enter a target to search');
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const data = await queryThreatIntel(searchType, query.trim());
      setResult(data);
      
      if (data.errors && data.errors.length > 0) {
        toast.warning(`Some sources failed: ${data.errors.join(', ')}`);
      } else {
        toast.success('Threat intelligence retrieved successfully');
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
            <TabsList className="grid w-full grid-cols-4">
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
            </TabsList>
          </Tabs>

          <div className="flex gap-2">
            <Input
              placeholder={`Enter ${searchType} to analyze...`}
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
                  <Search className="h-4 w-4 mr-2" />
                  Analyze
                </>
              )}
            </Button>
          </div>

          <div className="text-xs text-muted-foreground">
            Sources: VirusTotal, Abuse.ch (Feodo, SSL Blacklist), CIRCL Hashlookup, Spamhaus DROP
          </div>
        </CardContent>
      </Card>

      {result && (
        <div className="space-y-4">
          {/* AI-Formatted Summary */}
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
    </div>
  );
}
