// src/components/osint/CVEExplorer.tsx
import { useState, useEffect } from 'react';
import {
  Bug,
  Search,
  Loader2,
  Shield,
  Code,
  ExternalLink,
  Download,
  AlertTriangle,
  Calendar,
  TrendingUp,
  Copy,
  Github,
  FileCode,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  searchCVEs,
  getRecentCVEs,
  searchExploits,
  searchGitHubPOCs,
  getExploitCode,
  getSeverityColor,
  type CVE,
  type Exploit,
} from '@/services/cveService';

export function CVEExplorer() {
  const [activeTab, setActiveTab] = useState<'search' | 'recent' | 'exploits'>('recent');
  
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<CVE[]>([]);
  const [recentCVEs, setRecentCVEs] = useState<CVE[]>([]);
  const [exploits, setExploits] = useState<Exploit[]>([]);
  
  const [loading, setLoading] = useState(false);
  const [selectedCVE, setSelectedCVE] = useState<CVE | null>(null);
  const [selectedExploit, setSelectedExploit] = useState<Exploit | null>(null);
  const [exploitCode, setExploitCode] = useState<string | null>(null);

  useEffect(() => {
    loadRecentCVEs();
  }, []);

  const loadRecentCVEs = async () => {
    setLoading(true);
    try {
      const cves = await getRecentCVEs(7, 30);
      setRecentCVEs(cves);
    } catch (error) {
      toast.error('Failed to load recent CVEs');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      toast.error('Enter a CVE ID or keyword');
      return;
    }

    setLoading(true);
    try {
      const isCVEId = /^CVE-\d{4}-\d{4,}$/i.test(searchQuery. trim());
      
      const results = await searchCVEs(
        isCVEId 
          ? { cveId: searchQuery.trim().toUpperCase() }
          : { keyword: searchQuery.trim() }
      );

      setSearchResults(results);
      
      if (results.length === 0) {
        toast.info('No CVEs found');
      } else {
        toast.success(`Found ${results.length} CVEs`);
      }
    } catch (error) {
      toast.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  const loadExploits = async () => {
    setLoading(true);
    try {
      const exp = await searchExploits();
      setExploits(exp);
    } catch (error) {
      toast.error('Failed to load exploits');
    } finally {
      setLoading(false);
    }
  };

  const viewCVEDetails = async (cve: CVE) => {
    setSelectedCVE(cve);
    
    // Load GitHub POCs
    if (cve.exploits.length === 0) {
      const githubPocs = await searchGitHubPOCs(cve.id);
      cve.exploits = [... cve.exploits, ...githubPocs];
    }
  };

  const viewExploitCode = async (exploit: Exploit) => {
    setSelectedExploit(exploit);
    setExploitCode(null);
    
    if (exploit.edbId) {
      const code = await getExploitCode(exploit.edbId);
      setExploitCode(code);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Shield className="h-8 w-8 text-primary" />
            CVE & Exploit Explorer
          </h1>
          <p className="text-muted-foreground mt-2">
            Search CVEs, view exploits, and find POCs from NVD, ExploitDB, and GitHub
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={loadRecentCVEs}>
          <TrendingUp className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      <Card className="border-primary/30">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Search by CVE ID (CVE-2024-1234) or keyword..."
                className="pl-10"
              />
            </div>
            <Button onClick={handleSearch} disabled={loading}>
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="recent">Recent CVEs</TabsTrigger>
          <TabsTrigger value="search">Search Results</TabsTrigger>
          <TabsTrigger value="exploits" onClick={() => exploits.length === 0 && loadExploits()}>
            Exploits
          </TabsTrigger>
        </TabsList>

        <TabsContent value="recent" className="space-y-4 mt-6">
          {loading && (
            <div className="flex justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}

          {!loading && recentCVEs.map(cve => (
            <CVECard key={cve.id} cve={cve} onClick={() => viewCVEDetails(cve)} />
          ))}
        </TabsContent>

        <TabsContent value="search" className="space-y-4 mt-6">
          {! loading && searchResults.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <Search className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">No search results.  Try searching for a CVE or keyword.</p>
              </CardContent>
            </Card>
          )}

          {searchResults.map(cve => (
            <CVECard key={cve. id} cve={cve} onClick={() => viewCVEDetails(cve)} />
          ))}
        </TabsContent>

        <TabsContent value="exploits" className="space-y-4 mt-6">
          {exploits.map(exploit => (
            <ExploitCard key={exploit.id} exploit={exploit} onClick={() => viewExploitCode(exploit)} />
          ))}
        </TabsContent>
      </Tabs>

      {/* CVE Details Dialog */}
      {selectedCVE && (
        <Dialog open={!!selectedCVE} onOpenChange={() => setSelectedCVE(null)}>
          <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <div className="flex items-center justify-between">
                <DialogTitle className="text-2xl">{selectedCVE.id}</DialogTitle>
                <Badge variant="outline" className={cn('text-lg px-4 py-1', getSeverityColor(selectedCVE.cvss.severity))}>
                  {selectedCVE.cvss.severity} {selectedCVE.cvss.score}
                </Badge>
              </div>
            </DialogHeader>

            <div className="space-y-6">
              <div>
                <h3 className="font-semibold mb-2">Description</h3>
                <p className="text-sm text-muted-foreground">{selectedCVE.description}</p>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h3 className="font-semibold mb-2">Published</h3>
                  <p className="text-sm">{new Date(selectedCVE.published).toLocaleDateString()}</p>
                </div>
                <div>
                  <h3 className="font-semibold mb-2">Modified</h3>
                  <p className="text-sm">{new Date(selectedCVE.modified).toLocaleDateString()}</p>
                </div>
              </div>

              {selectedCVE.cvss.vector && (
                <div>
                  <h3 className="font-semibold mb-2">CVSS Vector</h3>
                  <code className="text-xs bg-secondary p-2 rounded block">{selectedCVE.cvss.vector}</code>
                </div>
              )}

              {selectedCVE.cwe && selectedCVE.cwe.length > 0 && (
                <div>
                  <h3 className="font-semibold mb-2">CWE</h3>
                  <div className="flex flex-wrap gap-2">
                    {selectedCVE.cwe.map(cwe => (
                      <Badge key={cwe} variant="outline">{cwe}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {selectedCVE.affected. length > 0 && (
                <div>
                  <h3 className="font-semibold mb-2">Affected Products</h3>
                  <div className="space-y-2">
                    {selectedCVE.affected. slice(0, 5).map((aff, idx) => (
                      <div key={idx} className="text-sm bg-secondary p-2 rounded">
                        <strong>{aff.vendor}</strong> {aff.product} {aff.versions.join(', ')}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedCVE.exploits.length > 0 && (
                <div>
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-red-500" />
                    Available Exploits & POCs ({selectedCVE.exploits. length})
                  </h3>
                  <div className="space-y-2">
                    {selectedCVE.exploits.map(exploit => (
                      <Card key={exploit.id} className="cursor-pointer hover:border-primary/50" onClick={() => viewExploitCode(exploit)}>
                        <CardContent className="pt-4">
                          <div className="flex items-start justify-between">
                            <div className="flex-1">
                              <h4 className="font-semibold text-sm">{exploit.title}</h4>
                              <p className="text-xs text-muted-foreground mt-1">{exploit.author}</p>
                            </div>
                            <Badge variant="secondary" className="text-xs">
                              {exploit. source === 'github' ? <Github className="h-3 w-3 mr-1" /> : null}
                              {exploit.source}
                            </Badge>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </div>
              )}

              {selectedCVE.references.length > 0 && (
                <div>
                  <h3 className="font-semibold mb-2">References</h3>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {selectedCVE.references.map((ref, idx) => (
                      <a
                        key={idx}
                        href={ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-primary hover:underline flex items-center gap-1 break-all"
                      >
                        <ExternalLink className="h-3 w-3 shrink-0" />
                        {ref.url}
                      </a>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Exploit Code Dialog */}
      {selectedExploit && (
        <Dialog open={!!selectedExploit} onOpenChange={() => { setSelectedExploit(null); setExploitCode(null); }}>
          <DialogContent className="max-w-5xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Code className="h-5 w-5" />
                {selectedExploit.title}
              </DialogTitle>
            </DialogHeader>

            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="text-sm">
                  <strong>Author:</strong> {selectedExploit.author}
                </div>
                <div className="flex gap-2">
                  <Badge variant="secondary">{selectedExploit.type}</Badge>
                  <Badge variant="secondary">{selectedExploit.platform}</Badge>
                </div>
              </div>

              <div className="flex gap-2">
                <Button variant="outline" size="sm" asChild>
                  <a href={selectedExploit.url} target="_blank" rel="noopener noreferrer">
                    <ExternalLink className="h-4 w-4 mr-2" />
                    View on {selectedExploit.source}
                  </a>
                </Button>
                {exploitCode && (
                  <Button variant="outline" size="sm" onClick={() => copyToClipboard(exploitCode)}>
                    <Copy className="h-4 w-4 mr-2" />
                    Copy Code
                  </Button>
                )}
              </div>

              {exploitCode ?  (
                <div>
                  <h3 className="font-semibold mb-2">Exploit Code</h3>
                  <pre className="text-xs bg-secondary p-4 rounded overflow-x-auto max-h-96">
                    <code>{exploitCode}</code>
                  </pre>
                </div>
              ) : selectedExploit.edbId ?  (
                <div className="flex justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <FileCode className="h-12 w-12 mx-auto mb-2 opacity-50" />
                  <p>Exploit code not available.  Visit the source URL to view. </p>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}

function CVECard({ cve, onClick }: { cve:  CVE; onClick: () => void }) {
  return (
    <Card className="cursor-pointer hover:border-primary/50 transition-all" onClick={onClick}>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between mb-3">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <h3 className="font-semibold text-lg">{cve.id}</h3>
              <Badge variant="outline" className={cn(getSeverityColor(cve.cvss.severity))}>
                {cve.cvss.severity} {cve.cvss.score}
              </Badge>
              {cve.exploits.length > 0 && (
                <Badge variant="destructive" className="text-xs">
                  <AlertTriangle className="h-3 w-3 mr-1" />
                  {cve. exploits.length} Exploit{cve.exploits. length > 1 ? 's' : ''}
                </Badge>
              )}
            </div>
            <p className="text-sm text-muted-foreground line-clamp-2">{cve.description}</p>
          </div>
        </div>

        <div className="flex items-center gap-6 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Calendar className="h-3 w-3" />
            {new Date(cve.published).toLocaleDateString()}
          </span>
          {cve.cwe && cve.cwe.length > 0 && (
            <span className="flex items-center gap-1">
              <Bug className="h-3 w-3" />
              {cve.cwe[0]}
            </span>
          )}
          {cve.affected.length > 0 && (
            <span>
              {cve.affected[0].vendor} {cve. affected[0].product}
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function ExploitCard({ exploit, onClick }: { exploit: Exploit; onClick: () => void }) {
  return (
    <Card className="cursor-pointer hover:border-primary/50 transition-all" onClick={onClick}>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between mb-3">
          <div className="flex-1">
            <h3 className="font-semibold">{exploit.title}</h3>
            <p className="text-xs text-muted-foreground mt-1">by {exploit.author}</p>
          </div>
          <div className="flex gap-2">
            <Badge variant="secondary">{exploit.type}</Badge>
            <Badge variant="outline">{exploit.source}</Badge>
          </div>
        </div>

        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span>{exploit.platform}</span>
          <span className="flex items-center gap-1">
            <Calendar className="h-3 w-3" />
            {new Date(exploit.date).toLocaleDateString()}
          </span>
          {exploit.cveId && (
            <span className="font-mono">{exploit.cveId}</span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
