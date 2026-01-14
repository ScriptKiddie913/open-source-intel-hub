import { useState, useEffect } from 'react';
import { Shield, Search, Loader2, ExternalLink, AlertTriangle, Clock, Code, FileText } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  searchCVE, 
  getCVEDetails, 
  getRecentCVEs, 
  searchExploitDB,
  getSeverityColor,
  getSeverityBg,
  CVEData,
  ExploitData 
} from '@/services/cveService';
import { saveSearchHistory } from '@/services/userDataService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function CVEExplorer() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'search' | 'recent' | 'exploits'>('recent');
  const [cveResults, setCveResults] = useState<CVEData[]>([]);
  const [exploitResults, setExploitResults] = useState<ExploitData[]>([]);
  const [selectedCVE, setSelectedCVE] = useState<CVEData | null>(null);

  useEffect(() => {
    if (activeTab === 'recent') {
      loadRecentCVEs();
    }
  }, [activeTab]);

  const loadRecentCVEs = async () => {
    setLoading(true);
    try {
      const cves = await getRecentCVEs(7, 30);
      setCveResults(cves);
    } catch (error) {
      toast.error('Failed to load recent CVEs');
    } finally {
      setLoading(false);
    }
  };

  const handleSearchCVE = async () => {
    if (!query.trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setLoading(true);
    setCveResults([]);
    setSelectedCVE(null);

    try {
      if (query.match(/^CVE-\d{4}-\d{4,}$/i)) {
        // Direct CVE lookup
        const cve = await getCVEDetails(query.toUpperCase());
        if (cve) {
          setCveResults([cve]);
          setSelectedCVE(cve);
          
          // Save to Supabase search history (for logged-in users)
          await saveSearchHistory(query.toUpperCase(), 'cve', 1, {
            severity: cve.cvss?.severity,
            cvssScore: cve.cvss?.score,
          });
        } else {
          toast.error('CVE not found');
        }
      } else {
        // Search
        const results = await searchCVE(query, 30);
        setCveResults(results);
        toast.success(`Found ${results.length} CVEs`);

        // Save to Supabase search history (for logged-in users)
        await saveSearchHistory(query, 'cve', results.length, {
          resultsCount: results.length,
        });
      }
    } catch (error) {
      toast.error('CVE search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSearchExploits = async () => {
    if (!query.trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setLoading(true);
    setExploitResults([]);

    try {
      const results = await searchExploitDB(query, 50);
      setExploitResults(results);
      toast.success(`Found ${results.length} exploits`);

      // Save to Supabase search history (for logged-in users)
      await saveSearchHistory(query, 'exploit', results.length, {
        resultsCount: results.length,
      });
    } catch (error) {
      toast.error('Exploit search failed');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectCVE = async (cve: CVEData) => {
    setSelectedCVE(cve);
    if (!cve.exploitAvailable) {
      // Try to fetch exploit details
      try {
        const details = await getCVEDetails(cve.id);
        if (details) {
          setSelectedCVE(details);
        }
      } catch (error) {
        console.error('Failed to fetch CVE details:', error);
      }
    }
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">CVE & Exploit Database</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Search vulnerabilities, CVEs, and public exploits
        </p>
      </div>

      {/* Search Bar */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    activeTab === 'exploits' ? handleSearchExploits() : handleSearchCVE();
                  }
                }}
                placeholder={
                  activeTab === 'exploits' 
                    ? 'Search exploits (e.g., "wordpress", "CVE-2021-44228")'
                    : 'Search CVEs (e.g., "CVE-2021-44228", "log4j")'
                }
                className="pl-10 bg-background"
              />
            </div>
            <Button 
              onClick={activeTab === 'exploits' ? handleSearchExploits : handleSearchCVE}
              disabled={loading}
              className="min-w-[100px]"
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Search className="h-4 w-4 mr-2" />
                  Search
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
        <TabsList className="bg-secondary/50 border border-border">
          <TabsTrigger value="recent" className="flex items-center gap-2">
            <Clock className="h-4 w-4" />
            Recent CVEs
          </TabsTrigger>
          <TabsTrigger value="search" className="flex items-center gap-2">
            <Shield className="h-4 w-4" />
            CVE Search
          </TabsTrigger>
          <TabsTrigger value="exploits" className="flex items-center gap-2">
            <Code className="h-4 w-4" />
            Exploits
          </TabsTrigger>
        </TabsList>

        {/* Recent CVEs */}
        <TabsContent value="recent" className="mt-4">
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {cveResults.map((cve) => (
                <CVECard key={cve.id} cve={cve} onSelect={handleSelectCVE} />
              ))}
            </div>
          )}
        </TabsContent>

        {/* CVE Search */}
        <TabsContent value="search" className="mt-4">
          {selectedCVE ? (
            <CVEDetails cve={selectedCVE} onBack={() => setSelectedCVE(null)} />
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {cveResults.map((cve) => (
                <CVECard key={cve.id} cve={cve} onSelect={handleSelectCVE} />
              ))}
              {cveResults.length === 0 && !loading && (
                <div className="text-center py-12 text-muted-foreground">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-30" />
                  <p>Search for CVEs by ID or keywords</p>
                </div>
              )}
            </div>
          )}
        </TabsContent>

        {/* Exploits */}
        <TabsContent value="exploits" className="mt-4">
          <div className="grid grid-cols-1 gap-4">
            {exploitResults.map((exploit) => (
              <ExploitCard key={exploit.id} exploit={exploit} />
            ))}
            {exploitResults.length === 0 && !loading && (
              <div className="text-center py-12 text-muted-foreground">
                <Code className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p>Search for public exploits</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function CVECard({ cve, onSelect }: { cve: CVEData; onSelect: (cve: CVEData) => void }) {
  return (
    <Card 
      className={cn(
        'bg-card border hover:border-primary/50 transition-all cursor-pointer',
        getSeverityBg(cve.cvss.severity)
      )}
      onClick={() => onSelect(cve)}
    >
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-lg', getSeverityBg(cve.cvss.severity))}>
              <Shield className={cn('h-5 w-5', getSeverityColor(cve.cvss.severity))} />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-mono font-bold text-foreground">{cve.id}</h3>
                {cve.exploitAvailable && (
                  <Badge variant="destructive" className="text-xs">
                    <AlertTriangle className="h-3 w-3 mr-1" />
                    Exploit Available
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Published: {new Date(cve.published).toLocaleDateString()}
              </p>
            </div>
          </div>
          <div className="text-right">
            <div className={cn('text-2xl font-bold font-mono', getSeverityColor(cve.cvss.severity))}>
              {cve.cvss.score.toFixed(1)}
            </div>
            <div className="text-xs text-muted-foreground">{cve.cvss.severity}</div>
          </div>
        </div>

        <p className="text-sm text-foreground line-clamp-2 mb-3">
          {cve.description}
        </p>

        <div className="flex flex-wrap gap-2">
          {cve.cwe.slice(0, 3).map((cwe, i) => (
            <Badge key={i} variant="outline" className="text-xs">
              {cwe}
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function CVEDetails({ cve, onBack }: { cve: CVEData; onBack: () => void }) {
  return (
    <div className="space-y-4">
      <Button variant="outline" onClick={onBack} size="sm">
        ← Back to results
      </Button>

      <Card className={cn('bg-card border', getSeverityBg(cve.cvss.severity))}>
        <CardHeader>
          <div className="flex items-start justify-between">
            <div>
              <CardTitle className="font-mono">{cve.id}</CardTitle>
              <p className="text-sm text-muted-foreground mt-1">
                Published: {new Date(cve.published).toLocaleDateString()} | 
                Modified: {new Date(cve.modified).toLocaleDateString()}
              </p>
            </div>
            <div className="text-right">
              <div className={cn('text-3xl font-bold font-mono', getSeverityColor(cve.cvss.severity))}>
                {cve.cvss.score.toFixed(1)}
              </div>
              <div className="text-sm text-muted-foreground">{cve.cvss.severity}</div>
              {cve.exploitAvailable && (
                <Badge variant="destructive" className="mt-2">
                  <AlertTriangle className="h-3 w-3 mr-1" />
                  Exploit Available
                </Badge>
              )}
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold text-foreground mb-2">Description</h3>
            <p className="text-sm text-foreground">{cve.description}</p>
          </div>

          <div>
            <h3 className="font-semibold text-foreground mb-2">CVSS Vector</h3>
            <code className="text-xs bg-secondary p-2 rounded block font-mono">
              {cve.cvss.vector}
            </code>
          </div>

          {cve.cwe.length > 0 && (
            <div>
              <h3 className="font-semibold text-foreground mb-2">Weakness Types</h3>
              <div className="flex flex-wrap gap-2">
                {cve.cwe.map((cwe, i) => (
                  <Badge key={i} variant="secondary">{cwe}</Badge>
                ))}
              </div>
            </div>
          )}

          {cve.references.length > 0 && (
            <div>
              <h3 className="font-semibold text-foreground mb-2">References</h3>
              <div className="space-y-1">
                {cve.references.map((ref, i) => (
                  <a 
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs text-primary hover:underline"
                  >
                    <ExternalLink className="h-3 w-3" />
                    {ref}
                  </a>
                ))}
              </div>
            </div>
          )}

          {cve.exploitDetails && (
            <div className="p-4 rounded-lg bg-destructive/10 border border-destructive/30">
              <h3 className="font-semibold text-destructive mb-2 flex items-center gap-2">
                <Code className="h-4 w-4" />
                Exploit Details
              </h3>
              <div className="space-y-2 text-sm">
                <p><strong>Title:</strong> {cve.exploitDetails.title}</p>
                <p><strong>Author:</strong> {cve.exploitDetails.author}</p>
                <p><strong>Type:</strong> {cve.exploitDetails.type}</p>
                <p><strong>Platform:</strong> {cve.exploitDetails.platform}</p>
                <a 
                  href={cve.exploitDetails.sourceUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-primary hover:underline"
                >
                  <ExternalLink className="h-3 w-3" />
                  View on Exploit-DB
                </a>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function ExploitCard({ exploit }: { exploit: ExploitData }) {
  return (
    <Card className="bg-card border hover:border-primary/50 transition-all">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10">
              <Code className="h-5 w-5 text-primary" />
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-semibold text-foreground">{exploit.title}</h3>
                {exploit.verified && (
                  <Badge variant="secondary" className="text-xs">Verified</Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                EDB-ID: {exploit.edbId} | {exploit.date}
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs text-muted-foreground mb-3">
          <span>Type: <strong>{exploit.type}</strong></span>
          <span>Platform: <strong>{exploit.platform}</strong></span>
          <span>Author: <strong>{exploit.author}</strong></span>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex flex-wrap gap-2">
            {exploit.cve?.slice(0, 3).map((cve, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {cve}
              </Badge>
            ))}
          </div>
          <a
            href={exploit.sourceUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 text-xs text-primary hover:underline"
          >
            <ExternalLink className="h-3 w-3" />
            View Source
          </a>
        </div>
      </CardContent>
    </Card>
  );
}
