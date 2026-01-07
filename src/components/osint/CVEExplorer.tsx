import { useState, useEffect } from 'react';
import { Shield, Search, Loader2, ExternalLink, AlertTriangle, Clock, Code, FileText, Github, Star, GitFork, Globe, Link2 } from 'lucide-react';
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
  searchGitHubPoC,
  getSeverityColor,
  getSeverityBg,
  CVEData,
  ExploitData,
  GitHubPoC 
} from '@/services/cveService';
import { saveSearchHistory } from '@/services/userDataService';
import { clearCacheByPrefix } from '@/lib/database';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function CVEExplorer() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<'search' | 'recent' | 'exploits' | 'github'>('recent');
  const [cveResults, setCveResults] = useState<CVEData[]>([]);
  const [exploitResults, setExploitResults] = useState<ExploitData[]>([]);
  const [githubResults, setGithubResults] = useState<GitHubPoC[]>([]);
  const [selectedCVE, setSelectedCVE] = useState<CVEData | null>(null);

  // Clear bad CVE cache on mount (one-time cleanup for github- prefixed fake CVEs)
  useEffect(() => {
    const cleanupBadCache = async () => {
      try {
        await clearCacheByPrefix('cve:');
        console.log('[CVE] Cleared CVE cache');
      } catch (e) {
        console.warn('[CVE] Failed to clear cache:', e);
      }
    };
    cleanupBadCache();
  }, []);

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
            severity: cve.cvss.severity,
            cvssScore: cve.cvss.score,
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

  const handleSearchGitHub = async () => {
    if (!query.trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setLoading(true);
    setGithubResults([]);

    try {
      const results = await searchGitHubPoC(query, 30);
      setGithubResults(results);
      toast.success(`Found ${results.length} GitHub repositories`);

      await saveSearchHistory(query, 'github-poc', results.length, {
        resultsCount: results.length,
      });
    } catch (error) {
      toast.error('GitHub search failed');
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
                    if (activeTab === 'exploits') handleSearchExploits();
                    else if (activeTab === 'github') handleSearchGitHub();
                    else handleSearchCVE();
                  }
                }}
                placeholder={
                  activeTab === 'exploits' 
                    ? 'Search exploits (e.g., "wordpress", "CVE-2021-44228")'
                    : activeTab === 'github'
                    ? 'Search GitHub PoCs (e.g., "log4j exploit", "CVE-2024")'
                    : 'Search CVEs (e.g., "CVE-2021-44228", "log4j")'
                }
                className="pl-10 bg-background"
              />
            </div>
            <Button 
              onClick={activeTab === 'exploits' ? handleSearchExploits : activeTab === 'github' ? handleSearchGitHub : handleSearchCVE}
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
          <TabsTrigger value="github" className="flex items-center gap-2">
            <Github className="h-4 w-4" />
            GitHub PoCs
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

        {/* GitHub PoCs */}
        <TabsContent value="github" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {githubResults.map((poc) => (
              <GitHubPoCCard key={poc.fullName} poc={poc} />
            ))}
            {githubResults.length === 0 && !loading && (
              <div className="col-span-2 text-center py-12 text-muted-foreground">
                <Github className="h-12 w-12 mx-auto mb-4 opacity-30" />
                <p>Search for GitHub proof-of-concept repositories</p>
                <p className="text-xs mt-2">Try searching for CVE IDs or vulnerability names</p>
              </div>
            )}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function CVECard({ cve, onSelect }: { cve: CVEData; onSelect: (cve: CVEData) => void }) {
  // Generate source links for the CVE - only official sources
  const sourceLinks = {
    nvd: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    mitre: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`,
    exploitdb: `https://www.exploit-db.com/search?cve=${cve.id}`,
  };

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

        <div className="flex items-center justify-between">
          <div className="flex flex-wrap gap-2">
            {cve.cwe.slice(0, 3).map((cwe, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {cwe}
              </Badge>
            ))}
          </div>
          
          {/* Quick source links */}
          <div className="flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
            <a
              href={sourceLinks.nvd}
              target="_blank"
              rel="noopener noreferrer"
              className="p-1 hover:bg-secondary rounded text-muted-foreground hover:text-primary"
              title="View on NVD"
            >
              <Globe className="h-4 w-4" />
            </a>
            <a
              href={sourceLinks.exploitdb}
              target="_blank"
              rel="noopener noreferrer"
              className="p-1 hover:bg-secondary rounded text-muted-foreground hover:text-primary"
              title="Search on Exploit-DB"
            >
              <Code className="h-4 w-4" />
            </a>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function CVEDetails({ cve, onBack }: { cve: CVEData; onBack: () => void }) {
  const [githubPoCs, setGithubPoCs] = useState<GitHubPoC[]>([]);
  const [loadingPoCs, setLoadingPoCs] = useState(false);

  useEffect(() => {
    const fetchPoCs = async () => {
      if (cve.id.startsWith('CVE-')) {
        setLoadingPoCs(true);
        try {
          const pocs = await searchGitHubPoC(cve.id, 5);
          setGithubPoCs(pocs);
        } catch (e) {
          console.error('Failed to fetch GitHub PoCs:', e);
        } finally {
          setLoadingPoCs(false);
        }
      }
    };
    fetchPoCs();
  }, [cve.id]);

  // Generate all source links - only official sources, no GitHub search (real repos shown separately)
  const sourceLinks = [
    { name: 'NVD (NIST)', url: `https://nvd.nist.gov/vuln/detail/${cve.id}`, icon: Globe },
    { name: 'MITRE', url: `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`, icon: Shield },
    { name: 'Exploit-DB', url: `https://www.exploit-db.com/search?cve=${cve.id}`, icon: Code },
    { name: 'Vulmon', url: `https://vulmon.com/vulnerabilitydetails?qid=${cve.id}`, icon: Link2 },
    { name: 'CIRCL', url: `https://cve.circl.lu/cve/${cve.id}`, icon: Globe },
  ];

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

          {/* Quick Source Links */}
          <div>
            <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
              <Link2 className="h-4 w-4" />
              Source Links
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {sourceLinks.map((link) => (
                <a
                  key={link.name}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 p-2 rounded-lg bg-secondary/50 hover:bg-secondary text-sm text-foreground hover:text-primary transition-colors"
                >
                  <link.icon className="h-4 w-4" />
                  {link.name}
                  <ExternalLink className="h-3 w-3 ml-auto opacity-50" />
                </a>
              ))}
            </div>
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
                  <a
                    key={i}
                    href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1"
                  >
                    <Badge variant="secondary" className="hover:bg-primary/20 cursor-pointer">
                      {cwe}
                      <ExternalLink className="h-3 w-3 ml-1" />
                    </Badge>
                  </a>
                ))}
              </div>
            </div>
          )}

          {cve.references.length > 0 && (
            <div>
              <h3 className="font-semibold text-foreground mb-2">References</h3>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {cve.references.map((ref, i) => (
                  <a 
                    key={i}
                    href={ref}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs text-primary hover:underline"
                  >
                    <ExternalLink className="h-3 w-3 flex-shrink-0" />
                    <span className="truncate">{ref}</span>
                  </a>
                ))}
              </div>
            </div>
          )}

          {/* GitHub PoC Repositories */}
          <div>
            <h3 className="font-semibold text-foreground mb-2 flex items-center gap-2">
              <Github className="h-4 w-4" />
              GitHub PoC Repositories
            </h3>
            {loadingPoCs ? (
              <div className="flex items-center gap-2 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                Searching GitHub...
              </div>
            ) : githubPoCs.length > 0 ? (
              <div className="space-y-2">
                {githubPoCs.map((poc) => (
                  <a
                    key={poc.fullName}
                    href={poc.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-start gap-3 p-3 rounded-lg bg-secondary/30 hover:bg-secondary/50 transition-colors"
                  >
                    <Github className="h-5 w-5 text-muted-foreground flex-shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-medium text-foreground truncate">{poc.fullName}</span>
                        <ExternalLink className="h-3 w-3 text-muted-foreground flex-shrink-0" />
                      </div>
                      {poc.description && (
                        <p className="text-xs text-muted-foreground line-clamp-2">{poc.description}</p>
                      )}
                      <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Star className="h-3 w-3" /> {poc.stars}
                        </span>
                        <span className="flex items-center gap-1">
                          <GitFork className="h-3 w-3" /> {poc.forks}
                        </span>
                        {poc.language && (
                          <Badge variant="outline" className="text-xs py-0">
                            {poc.language}
                          </Badge>
                        )}
                      </div>
                    </div>
                  </a>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No GitHub repositories found for this CVE</p>
            )}
          </div>

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
              <a
                key={i}
                href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
              >
                <Badge variant="outline" className="text-xs hover:bg-primary/20 cursor-pointer">
                  {cve}
                  <ExternalLink className="h-3 w-3 ml-1" />
                </Badge>
              </a>
            ))}
          </div>
          <div className="flex items-center gap-2">
            <a
              href={exploit.sourceUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3 py-1 rounded bg-primary/10 text-xs text-primary hover:bg-primary/20 transition-colors"
            >
              <Code className="h-3 w-3" />
              View Exploit
              <ExternalLink className="h-3 w-3" />
            </a>
            <a
              href={`https://github.com/search?q=${exploit.edbId}&type=repositories`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 p-1 rounded hover:bg-secondary text-muted-foreground hover:text-primary"
              title="Search on GitHub"
            >
              <Github className="h-4 w-4" />
            </a>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function GitHubPoCCard({ poc }: { poc: GitHubPoC }) {
  return (
    <Card className="bg-card border hover:border-primary/50 transition-all">
      <CardContent className="p-4">
        <div className="flex items-start gap-3">
          <div className="p-2 rounded-lg bg-secondary">
            <Github className="h-5 w-5 text-foreground" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <a
                href={poc.url}
                target="_blank"
                rel="noopener noreferrer"
                className="font-semibold text-foreground hover:text-primary transition-colors truncate"
              >
                {poc.fullName}
              </a>
              <ExternalLink className="h-3 w-3 text-muted-foreground flex-shrink-0" />
            </div>
            
            {poc.description && (
              <p className="text-sm text-muted-foreground line-clamp-2 mb-3">
                {poc.description}
              </p>
            )}

            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Star className="h-3 w-3 text-yellow-500" />
                  {poc.stars.toLocaleString()}
                </span>
                <span className="flex items-center gap-1">
                  <GitFork className="h-3 w-3" />
                  {poc.forks.toLocaleString()}
                </span>
                {poc.language && (
                  <Badge variant="outline" className="text-xs py-0">
                    {poc.language}
                  </Badge>
                )}
              </div>
              <div className="flex items-center gap-2">
                <a
                  href={poc.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 px-3 py-1 rounded bg-primary/10 text-xs text-primary hover:bg-primary/20 transition-colors"
                >
                  <Github className="h-3 w-3" />
                  View Repo
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>

            <div className="text-xs text-muted-foreground mt-2">
              Updated: {new Date(poc.updatedAt).toLocaleDateString()}
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
