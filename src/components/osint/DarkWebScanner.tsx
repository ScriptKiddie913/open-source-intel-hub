'use client';

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

import {
  Radar,
  Search,
  Loader2,
  AlertTriangle,
  Globe,
  Database,
  Eye,
  Clock,
  RefreshCcw,
  Layers,
  Shield,
  Activity,
  ExternalLink,
  Filter,
  Hash,
  Info,
  Brain,
  Zap,
  TrendingUp,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  CardDescription,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';
import { Progress } from '@/components/ui/progress';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';

import {
  discoverOnionSites,
  checkOnionUptime,
  searchDarkWebSignals,
  deepSearchDarkWeb,
  type OnionSite,
  type LeakSignal,
  type DeepSearchResult,
} from '@/services/torService';

import { type LeakAnalysis, type ExtractedEntity } from '@/services/llmAnalysisService';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

type ViewMode = 'cards' | 'compact';
type TabMode = 'onions' | 'signals' | 'analysis';

const RISK_COLORS: Record<
  'critical' | 'high' | 'medium' | 'low',
  string
> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

export function DarkWebScanner() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const [onionSites, setOnionSites] = useState<OnionSite[]>([]);
  const [signals, setSignals] = useState<LeakSignal[]>([]);
  const [analysis, setAnalysis] = useState<LeakAnalysis | null>(null);
  const [entities, setEntities] = useState<ExtractedEntity[]>([]);
  const [sourceStats, setSourceStats] = useState<Record<string, number>>({});
  const [searchTime, setSearchTime] = useState<number>(0);

  const [tab, setTab] = useState<TabMode>('signals');
  const [viewMode, setViewMode] = useState<ViewMode>('cards');
  const [deepSearchEnabled, setDeepSearchEnabled] = useState(true);
  const [llmAnalysisEnabled, setLlmAnalysisEnabled] = useState(true);

  const [uptimeLoading, setUptimeLoading] = useState<Record<string, boolean>>({});

  const refreshTimer = useRef<number | null>(null);

  const runSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a search keyword (domain, email, company, etc.)');
      return;
    }

    setLoading(true);
    setOnionSites([]);
    setSignals([]);
    setAnalysis(null);
    setEntities([]);
    setSourceStats({});

    try {
      // Run onion discovery in parallel with deep search
      const onionPromise = discoverOnionSites(query);
      
      let deepResult: DeepSearchResult | null = null;
      
      if (deepSearchEnabled) {
        // Use enhanced deep search with LLM analysis
        deepResult = await deepSearchDarkWeb({
          indicator: query,
          includeBreachDatabases: true,
          includeDarkWebSearch: true,
          includeCodeSearch: true,
          includePasteSites: true,
          includeLeakArchives: true,
          includeSocialMedia: true,
          maxResultsPerSource: 30,
          enableLLMAnalysis: llmAnalysisEnabled,
        });
        
        setSignals(deepResult.signals);
        setAnalysis(deepResult.analysis || null);
        setEntities(deepResult.entities);
        setSourceStats(deepResult.sourceStats);
        setSearchTime(deepResult.totalTime);
      } else {
        // Use regular search
        const sigs = await searchDarkWebSignals(query);
        setSignals(sigs);
      }

      const onions = await onionPromise;
      setOnionSites(onions);

      if (onions.length === 0 && signals.length === 0) {
        toast.info('No results found. Try a different search term.');
      } else {
        const totalResults = onions.length + (deepResult?.signals.length || signals.length);
        toast.success(
          `Found ${totalResults} results across ${Object.keys(deepResult?.sourceStats || {}).length || 6} sources`
        );
      }
    } catch (err) {
      console.error(err);
      toast.error('Dark web discovery failed. Check console for details.');
    } finally {
      setLoading(false);
    }
  }, [query, deepSearchEnabled, llmAnalysisEnabled]);

  useEffect(() => {
    if (refreshTimer.current !== null) {
      window.clearInterval(refreshTimer.current);
    }

    refreshTimer.current = window.setInterval(() => {
      if (query.trim()) {
        runSearch();
      }
    }, 300000); // 5 minutes

    return () => {
      if (refreshTimer.current !== null) {
        window.clearInterval(refreshTimer. current);
      }
    };
  }, [query, runSearch]);

  const checkUptime = async (site: OnionSite) => {
    setUptimeLoading(prev => ({
      ...prev,
      [site.url]: true,
    }));

    try {
      const result = await checkOnionUptime(site.url);

      setOnionSites(prev =>
        prev.map(o =>
          o.url === site. url
            ? {
                ...o,
                status: result. status,
                lastSeen: result.checkedAt,
              }
            : o
        )
      );

      toast.success(`${site.url} is ${result.status}`);
    } catch (error) {
      toast.error('Uptime check failed');
    } finally {
      setUptimeLoading(prev => ({
        ...prev,
        [site.url]: false,
      }));
    }
  };

  const stats = useMemo(() => {
    return {
      onions: onionSites.length,
      signals: signals.length,
      entities: entities.length,
      online: onionSites.filter(o => o.status === 'online').length,
      offline: onionSites.filter(o => o.status === 'offline').length,
      critical: signals.filter(s => s.severity === 'critical').length,
      high: signals.filter(s => s.severity === 'high').length,
      sources: Object.keys(sourceStats).length,
      threatScore: analysis?.threatAssessment?.score || 0,
    };
  }, [onionSites, signals, entities, sourceStats, analysis]);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Radar className="h-8 w-8 text-primary" />
            Dark Web Intelligence Monitor
            <Badge variant="outline" className="ml-2 text-xs">
              <Brain className="h-3 w-3 mr-1" />
              StealthMole-style
            </Badge>
          </h1>
          <p className="text-muted-foreground mt-2">
            Deep intelligence gathering across 15+ sources with LLM-powered analysis
          </p>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Switch 
              id="deep-search" 
              checked={deepSearchEnabled} 
              onCheckedChange={setDeepSearchEnabled}
            />
            <Label htmlFor="deep-search" className="text-sm">Deep Search</Label>
          </div>
          <div className="flex items-center gap-2">
            <Switch 
              id="llm-analysis" 
              checked={llmAnalysisEnabled} 
              onCheckedChange={setLlmAnalysisEnabled}
            />
            <Label htmlFor="llm-analysis" className="text-sm">AI Analysis</Label>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={runSearch}
            disabled={loading}
          >
            <RefreshCcw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
      </div>

      {/* LEGAL NOTICE */}
      <Card className="border-yellow-500/40 bg-yellow-500/10">
        <CardContent className="p-4 flex gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-500 shrink-0 mt-1" />
          <div>
            <h3 className="font-semibold text-yellow-600 dark:text-yellow-500">
              Metadata-Only Intelligence (Legal & Safe)
            </h3>
            <p className="text-sm text-muted-foreground mt-1">
              This tool queries public indexes, search engines, and metadata sources. 
              <strong> No Tor daemon required.  No illegal scraping.  No content downloading.</strong>
              {' '}All data comes from legitimate OSINT sources like Ahmia. fi, Pastebin archives, and public APIs.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* SEARCH BAR */}
      <Card className="border-primary/30">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runSearch()}
                placeholder="Search:  domain, email, company, breach, keyword..."
                className="pl-10"
              />
            </div>

            <Button onClick={runSearch} disabled={loading}>
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Eye className="h-4 w-4 mr-2" />
                  Discover
                </>
              )}
            </Button>
          </div>

          <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
            <Info className="h-3 w-3" />
            <span>
              Try: "facebook", "amazon", "ransomware", "database", or any company/email
            </span>
          </div>
        </CardContent>
      </Card>

      {/* STATS */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Globe className="h-5 w-5 mx-auto text-primary mb-2" />
              <div className="text-2xl font-bold">{stats.onions}</div>
              <div className="text-xs text-muted-foreground">Onion Sites</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Database className="h-5 w-5 mx-auto text-cyan-500 mb-2" />
              <div className="text-2xl font-bold">{stats.signals}</div>
              <div className="text-xs text-muted-foreground">Leak Signals</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Hash className="h-5 w-5 mx-auto text-purple-500 mb-2" />
              <div className="text-2xl font-bold">{stats.entities}</div>
              <div className="text-xs text-muted-foreground">Entities</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Layers className="h-5 w-5 mx-auto text-blue-500 mb-2" />
              <div className="text-2xl font-bold">{stats.sources}</div>
              <div className="text-xs text-muted-foreground">Sources</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <AlertTriangle className="h-5 w-5 mx-auto text-red-500 mb-2" />
              <div className="text-2xl font-bold text-red-500">{stats.critical}</div>
              <div className="text-xs text-muted-foreground">Critical</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <AlertTriangle className="h-5 w-5 mx-auto text-orange-500 mb-2" />
              <div className="text-2xl font-bold text-orange-500">{stats.high}</div>
              <div className="text-xs text-muted-foreground">High Risk</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Brain className="h-5 w-5 mx-auto text-violet-500 mb-2" />
              <div className="text-2xl font-bold">{stats.threatScore}</div>
              <div className="text-xs text-muted-foreground">Threat Score</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Zap className="h-5 w-5 mx-auto text-yellow-500 mb-2" />
              <div className="text-2xl font-bold">{searchTime ? `${(searchTime/1000).toFixed(1)}s` : '-'}</div>
              <div className="text-xs text-muted-foreground">Search Time</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* TABS */}
      <Tabs value={tab} onValueChange={v => setTab(v as TabMode)}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="signals">
            <Database className="h-4 w-4 mr-2" />
            Leak Signals ({signals.length})
          </TabsTrigger>
          <TabsTrigger value="analysis">
            <Brain className="h-4 w-4 mr-2" />
            AI Analysis
          </TabsTrigger>
          <TabsTrigger value="onions">
            <Globe className="h-4 w-4 mr-2" />
            Onion Sites ({onionSites.length})
          </TabsTrigger>
        </TabsList>

        {/* ONIONS */}
        <TabsContent value="onions" className="mt-6 space-y-4">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}

          {!loading && onionSites.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <Globe className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">
                  No onion sites discovered. Try searching for a different term.
                </p>
              </CardContent>
            </Card>
          )}

          {!loading && onionSites.map(site => (
            <OnionCard
              key={site.url}
              site={site}
              loading={uptimeLoading[site. url]}
              onCheck={() => checkUptime(site)}
            />
          ))}
        </TabsContent>

        {/* SIGNALS */}
        <TabsContent value="signals" className="mt-6 space-y-3">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}

          {/* Source Stats Bar */}
          {!loading && Object.keys(sourceStats).length > 0 && (
            <Card className="mb-4">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Sources Scanned</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(sourceStats).map(([source, count]) => (
                    <Badge 
                      key={source} 
                      variant={count > 0 ? 'default' : 'outline'}
                      className={cn(count > 0 ? 'bg-green-500/20 text-green-400 border-green-500/40' : '')}
                    >
                      {source}: {count}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {!loading && signals.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <Database className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">
                  No exposure signals found. Try searching for emails, domains, or companies.
                </p>
              </CardContent>
            </Card>
          )}

          {!loading && signals.map(sig => (
            <SignalCard key={sig.id} signal={sig} />
          ))}
        </TabsContent>

        {/* AI ANALYSIS */}
        <TabsContent value="analysis" className="mt-6 space-y-4">
          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
              <span className="ml-3 text-muted-foreground">Running LLM analysis...</span>
            </div>
          )}

          {!loading && !analysis && entities.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <Brain className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">
                  Run a search with AI Analysis enabled to see threat intelligence insights.
                </p>
              </CardContent>
            </Card>
          )}

          {/* Threat Assessment Card */}
          {!loading && analysis && (
            <Card className={cn(
              'border-2',
              analysis.threatAssessment.severity === 'critical' ? 'border-red-500/50 bg-red-500/5' :
              analysis.threatAssessment.severity === 'high' ? 'border-orange-500/50 bg-orange-500/5' :
              analysis.threatAssessment.severity === 'medium' ? 'border-yellow-500/50 bg-yellow-500/5' :
              'border-green-500/50 bg-green-500/5'
            )}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Threat Assessment
                  </CardTitle>
                  <Badge className={cn(
                    'text-lg px-4 py-1',
                    analysis.threatAssessment.severity === 'critical' ? 'bg-red-500' :
                    analysis.threatAssessment.severity === 'high' ? 'bg-orange-500' :
                    analysis.threatAssessment.severity === 'medium' ? 'bg-yellow-500' :
                    'bg-green-500'
                  )}>
                    {analysis.threatAssessment.score}/100
                  </Badge>
                </div>
                <CardDescription>{analysis.threatAssessment.category}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Score Progress */}
                <div>
                  <div className="flex justify-between text-sm mb-1">
                    <span>Threat Level</span>
                    <span className="uppercase font-bold">{analysis.threatAssessment.severity}</span>
                  </div>
                  <Progress 
                    value={analysis.threatAssessment.score} 
                    className={cn(
                      analysis.threatAssessment.severity === 'critical' ? '[&>div]:bg-red-500' :
                      analysis.threatAssessment.severity === 'high' ? '[&>div]:bg-orange-500' :
                      analysis.threatAssessment.severity === 'medium' ? '[&>div]:bg-yellow-500' :
                      '[&>div]:bg-green-500'
                    )}
                  />
                </div>

                {/* Summary */}
                <div>
                  <h4 className="font-semibold mb-2">Summary</h4>
                  <p className="text-sm text-muted-foreground">{analysis.summary}</p>
                </div>

                {/* Indicators */}
                {analysis.threatAssessment.indicators.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Indicators</h4>
                    <div className="flex flex-wrap gap-2">
                      {analysis.threatAssessment.indicators.map((ind, i) => (
                        <Badge key={i} variant="outline">{ind}</Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations */}
                {analysis.threatAssessment.recommendations.length > 0 && (
                  <div>
                    <h4 className="font-semibold mb-2">Recommended Actions</h4>
                    <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                      {analysis.threatAssessment.recommendations.map((rec, i) => (
                        <li key={i}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Extracted Entities */}
          {!loading && entities.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Hash className="h-5 w-5" />
                  Extracted Entities ({entities.length})
                </CardTitle>
                <CardDescription>Automatically detected sensitive data</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {entities.slice(0, 20).map((entity, i) => (
                    <div 
                      key={i}
                      className={cn(
                        'p-3 rounded-lg border',
                        entity.type === 'password' ? 'border-red-500/40 bg-red-500/5' :
                        entity.type === 'email' ? 'border-blue-500/40 bg-blue-500/5' :
                        entity.type === 'ip' ? 'border-green-500/40 bg-green-500/5' :
                        entity.type === 'domain' ? 'border-purple-500/40 bg-purple-500/5' :
                        'border-gray-500/40 bg-gray-500/5'
                      )}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <Badge variant="outline" className="text-xs uppercase">
                          {entity.type}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {Math.round(entity.confidence * 100)}% confidence
                        </span>
                      </div>
                      <p className="font-mono text-sm break-all">{entity.value}</p>
                      {entity.context && (
                        <p className="text-xs text-muted-foreground mt-1 truncate">
                          {entity.context}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Exposure Timeline */}
          {!loading && analysis?.exposureTimeline && analysis.exposureTimeline.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Clock className="h-5 w-5" />
                  Exposure Timeline
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {analysis.exposureTimeline.map((event, i) => (
                    <div key={i} className="flex gap-3 items-start">
                      <div className="w-2 h-2 rounded-full bg-primary mt-2" />
                      <div>
                        <p className="text-xs text-muted-foreground">
                          {new Date(event.date).toLocaleDateString()}
                        </p>
                        <p className="text-sm">{event.event}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* SOURCES */}
      <Card className="border-primary/40 bg-primary/5">
        <CardContent className="p-4 flex gap-3">
          <Database className="h-5 w-5 text-primary shrink-0" />
          <div>
            <h3 className="font-semibold">Real Data Sources (15+ APIs)</h3>
            <p className="text-sm text-muted-foreground mt-1">
              <strong>✅ Core:</strong> Archive.org, GitHub, Psbdmp, Reddit, Library of Leaks
              {' • '}
              <strong>🔍 Enhanced:</strong> HackerNews, SearchCode, Grep.app, WikiLeaks, DDoSecrets
              {' • '}
              <strong>💀 Breach DBs:</strong> IntelX, BreachDirectory, LeakCheck
              {' • '}
              <strong>📝 Pastes:</strong> Rentry, PasteArchives
              {' • '}
              <strong>🧅 Onion:</strong> Ahmia.fi
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* ============================================================================
   SUB COMPONENTS
============================================================================ */

function OnionCard({
  site,
  loading,
  onCheck,
}: {
  site: OnionSite;
  loading: boolean;
  onCheck: () => void;
}) {
  return (
    <Card className={cn('border-2', RISK_COLORS[site.riskLevel])}>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-mono text-sm break-all">{site.url}</h3>
              <Badge variant="outline" className={RISK_COLORS[site.riskLevel]}>
                {site.riskLevel. toUpperCase()}
              </Badge>
            </div>
            <h4 className="font-semibold">{site.title}</h4>
            <p className="text-sm text-muted-foreground mt-1">
              {site.description}
            </p>
          </div>

          <Badge variant="secondary">{site.category}</Badge>
        </div>

        {site.tags.length > 0 && (
          <div className="flex flex-wrap gap-2 mb-4">
            {site.tags. map(tag => (
              <Badge key={tag} variant="outline" className="text-xs">
                <Hash className="h-3 w-3 mr-1" />
                {tag}
              </Badge>
            ))}
          </div>
        )}

        <div className="flex justify-between items-center">
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {new Date(site.lastSeen).toLocaleString()}
            </span>
            <span className="flex items-center gap-1">
              <Activity className={cn(
                'h-3 w-3',
                site.status === 'online' && 'text-green-500',
                site.status === 'offline' && 'text-red-500'
              )} />
              {site.status. toUpperCase()}
            </span>
          </div>

          <Button
            size="sm"
            variant="outline"
            onClick={onCheck}
            disabled={loading}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <>
                <Activity className="h-4 w-4 mr-2" />
                Check Status
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function SignalCard({ signal }: { signal: LeakSignal }) {
  return (
    <Card className="hover:border-primary/50 transition-colors">
      <CardContent className="pt-6">
        <div className="flex items-start justify-between gap-4 mb-3">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold">{signal.title}</h3>
              <Badge variant="secondary">{signal.source. toUpperCase()}</Badge>
            </div>
            <p className="text-sm text-muted-foreground">
              <strong>Indicator:</strong>{' '}
              <span className="font-mono text-xs bg-secondary px-2 py-1 rounded">
                {signal.indicator}
              </span>
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {signal.context}
            </p>
          </div>
        </div>

        <div className="flex justify-between items-center">
          <span className="text-xs text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {new Date(signal.timestamp).toLocaleString()}
          </span>
          <Button size="sm" variant="outline" asChild>
            <a
              href={signal.url}
              target="_blank"
              rel="noreferrer"
            >
              <ExternalLink className="h-3 w-3 mr-2" />
              View Source
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
