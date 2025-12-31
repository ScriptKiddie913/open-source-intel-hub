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
  Download,
  FileArchive,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@/components/ui/tabs';

import {
  discoverOnionSites,
  checkOnionUptime,
  searchDarkWebSignals,
  type OnionSite,
  type LeakSignal,
} from '@/services/torService';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

type ViewMode = 'cards' | 'compact';
type TabMode = 'onions' | 'signals' | 'leaks';

const RISK_COLORS:  Record<
  'critical' | 'high' | 'medium' | 'low',
  string
> = {
  critical:  'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

export function DarkWebScanner() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const [onionSites, setOnionSites] = useState<OnionSite[]>([]);
  const [signals, setSignals] = useState<LeakSignal[]>([]);
  const [leakSources, setLeakSources] = useState<LeakSignal[]>([]);

  const [tab, setTab] = useState<TabMode>('onions');
  const [viewMode, setViewMode] = useState<ViewMode>('cards');
  const [sourceFilter, setSourceFilter] = useState<string>('all');

  const [uptimeLoading, setUptimeLoading] = useState<Record<string, boolean>>({});

  const refreshTimer = useRef<number | null>(null);

  const runSearch = useCallback(async () => {
    if (! query.trim()) {
      toast.error('Enter a search keyword (domain, email, company, etc.)');
      return;
    }

    setLoading(true);
    setOnionSites([]);
    setSignals([]);
    setLeakSources([]);

    try {
      const [onions, sigs] = await Promise.all([
        discoverOnionSites(query),
        searchDarkWebSignals(query),
      ]);

      setOnionSites(onions);
      
      // Separate leak sources with downloads from regular signals
      const leaks = sigs.filter(s => s.downloadUrl);
      const regularSignals = sigs.filter(s => !s.downloadUrl);
      
      setLeakSources(leaks);
      setSignals(regularSignals);

      if (onions.length === 0 && sigs.length === 0) {
        toast.info('No results found. Try a different search term.');
      } else {
        toast.success(
          `Found ${onions.length} onion sites, ${regularSignals.length} signals, and ${leaks.length} downloadable leaks`
        );
      }
    } catch (err) {
      console.error(err);
      toast.error('Dark web discovery failed. Check console for details.');
    } finally {
      setLoading(false);
    }
  }, [query]);

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
      leaks: leakSources.length,
      online: onionSites.filter(o => o.status === 'online').length,
      offline: onionSites.filter(o => o.status === 'offline').length,
      critical: onionSites.filter(o => o.riskLevel === 'critical').length,
      high: onionSites.filter(o => o.riskLevel === 'high').length,
    };
  }, [onionSites, signals, leakSources]);

  const filteredLeaks = useMemo(() => {
    if (sourceFilter === 'all') return leakSources;
    return leakSources.filter(leak => leak.source === sourceFilter);
  }, [leakSources, sourceFilter]);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Radar className="h-8 w-8 text-primary" />
            Dark Web Intelligence Monitor
          </h1>
          <p className="text-muted-foreground mt-2">
            Real-time monitoring of onion services, pastes, leaks, and dark web exposure
          </p>
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
      <div className="grid grid-cols-2 md:grid-cols-7 gap-4">
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
              <FileArchive className="h-5 w-5 mx-auto text-purple-500 mb-2" />
              <div className="text-2xl font-bold">{stats.leaks}</div>
              <div className="text-xs text-muted-foreground">Downloads</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Activity className="h-5 w-5 mx-auto text-green-500 mb-2" />
              <div className="text-2xl font-bold">{stats.online}</div>
              <div className="text-xs text-muted-foreground">Online</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <div className="text-center">
              <Shield className="h-5 w-5 mx-auto text-gray-500 mb-2" />
              <div className="text-2xl font-bold">{stats.offline}</div>
              <div className="text-xs text-muted-foreground">Offline</div>
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
              <div className="text-2xl font-bold text-orange-500">{stats. high}</div>
              <div className="text-xs text-muted-foreground">High Risk</div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* TABS */}
      <Tabs value={tab} onValueChange={v => setTab(v as TabMode)}>
        <TabsList className="grid w-full grid-cols-3">
          <TabsTrigger value="onions">
            <Globe className="h-4 w-4 mr-2" />
            Onion Discovery ({onionSites.length})
          </TabsTrigger>
          <TabsTrigger value="signals">
            <Database className="h-4 w-4 mr-2" />
            Exposure Signals ({signals.length})
          </TabsTrigger>
          <TabsTrigger value="leaks">
            <FileArchive className="h-4 w-4 mr-2" />
            Library of Leaks ({leakSources.length})
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

          {!loading && signals. map(sig => (
            <SignalCard key={sig.id} signal={sig} />
          ))}
        </TabsContent>

        {/* LIBRARY OF LEAKS */}
        <TabsContent value="leaks" className="mt-6 space-y-4">
          {/* Warning Notice */}
          <Card className="border-red-500/40 bg-red-500/10">
            <CardContent className="p-4 flex gap-3">
              <AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-1" />
              <div>
                <h3 className="font-semibold text-red-600 dark:text-red-500">
                  ⚠️ Responsible Use Warning
                </h3>
                <p className="text-sm text-muted-foreground mt-1">
                  These are real leaked databases from public sources. Download and use responsibly:
                  <strong> Only for authorized security research, vulnerability assessment, and OSINT.</strong>
                  {' '}Accessing, storing, or sharing personal data without authorization may violate laws (GDPR, CCPA, CFAA).
                  By downloading, you accept full responsibility for ethical and legal use.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Source Filter */}
          {leakSources.length > 0 && (
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Filter by source:</span>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant={sourceFilter === 'all' ? 'default' : 'outline'}
                  onClick={() => setSourceFilter('all')}
                >
                  All ({leakSources.length})
                </Button>
                <Button
                  size="sm"
                  variant={sourceFilter === 'libraryofleaks' ? 'default' : 'outline'}
                  onClick={() => setSourceFilter('libraryofleaks')}
                >
                  Library ({leakSources.filter(l => l.source === 'libraryofleaks').length})
                </Button>
                <Button
                  size="sm"
                  variant={sourceFilter === 'archive' ? 'default' : 'outline'}
                  onClick={() => setSourceFilter('archive')}
                >
                  Archive.org ({leakSources.filter(l => l.source === 'archive').length})
                </Button>
              </div>
            </div>
          )}

          {loading && (
            <div className="flex items-center justify-center py-12">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
          )}

          {!loading && leakSources.length === 0 && (
            <Card className="border-dashed">
              <CardContent className="pt-12 pb-12 text-center">
                <FileArchive className="h-16 w-16 mx-auto text-muted-foreground opacity-50 mb-4" />
                <p className="text-muted-foreground">
                  No downloadable leak datasets found. Try searching for specific companies, breaches, or data dumps.
                </p>
              </CardContent>
            </Card>
          )}

          {!loading && filteredLeaks.map(leak => (
            <LeakDownloadCard key={leak.id} leak={leak} />
          ))}
        </TabsContent>
      </Tabs>

      {/* SOURCES */}
      <Card className="border-primary/40 bg-primary/5">
        <CardContent className="p-4 flex gap-3">
          <Database className="h-5 w-5 text-primary shrink-0" />
          <div>
            <h3 className="font-semibold">Real Data Sources</h3>
            <p className="text-sm text-muted-foreground mt-1">
              <strong>Onion Discovery:</strong> Ahmia.fi, Dark.fail
              {' • '}
              <strong>Leak Monitoring:</strong> Pastebin, Psbdmp, GitHub Gists, Rentry, Ghostbin
              {' • '}
              <strong>Downloadable Leaks:</strong> Library of Leaks, Archive.org, GitHub Mirrors
              {' • '}
              <strong>Uptime: </strong> Tor2Web Gateways
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

function LeakDownloadCard({ leak }: { leak: LeakSignal }) {
  const [downloading, setDownloading] = useState(false);

  const handleDownload = () => {
    if (!leak.downloadUrl) return;
    
    setDownloading(true);
    
    // Log the download attempt
    console.log(`Download initiated: ${leak.title} from ${leak.source}`);
    
    // Open in new tab (safer than direct download)
    window.open(leak.downloadUrl, '_blank', 'noopener,noreferrer');
    
    setTimeout(() => setDownloading(false), 2000);
    
    toast.success(`Opening download: ${leak.title}`);
  };

  const riskColor = leak.riskLevel ? RISK_COLORS[leak.riskLevel] : '';

  return (
    <Card className={cn('border-2 hover:border-primary/50 transition-colors', riskColor)}>
      <CardContent className="pt-6">
        <div className="flex items-start justify-between gap-4 mb-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <h3 className="font-semibold text-lg">{leak.title}</h3>
              <Badge variant="secondary">{leak.source.toUpperCase()}</Badge>
              {leak.riskLevel && (
                <Badge variant="outline" className={RISK_COLORS[leak.riskLevel]}>
                  {leak.riskLevel.toUpperCase()}
                </Badge>
              )}
              {leak.category && (
                <Badge variant="outline">{leak.category}</Badge>
              )}
            </div>
            
            {leak.description && (
              <p className="text-sm text-muted-foreground mb-2">
                {leak.description}
              </p>
            )}
            
            <p className="text-sm text-muted-foreground">
              <strong>Indicator:</strong>{' '}
              <span className="font-mono text-xs bg-secondary px-2 py-1 rounded">
                {leak.indicator}
              </span>
            </p>
            
            <p className="text-xs text-muted-foreground mt-1">
              {leak.context}
            </p>
          </div>
        </div>

        {/* Metadata Row */}
        <div className="flex flex-wrap items-center gap-4 mb-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {new Date(leak.timestamp).toLocaleString()}
          </span>
          {leak.fileSize && (
            <span className="flex items-center gap-1">
              <FileArchive className="h-3 w-3" />
              {leak.fileSize}
            </span>
          )}
          <span className="flex items-center gap-1">
            <Database className="h-3 w-3" />
            {leak.source}
          </span>
        </div>

        {/* Action Buttons */}
        <div className="flex justify-between items-center gap-2">
          <Button size="sm" variant="outline" asChild>
            <a
              href={leak.url}
              target="_blank"
              rel="noreferrer"
            >
              <ExternalLink className="h-3 w-3 mr-2" />
              View Details
            </a>
          </Button>
          
          {leak.downloadUrl && (
            <Button
              size="sm"
              variant="default"
              onClick={handleDownload}
              disabled={downloading}
              className="bg-primary hover:bg-primary/90"
            >
              {downloading ? (
                <>
                  <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  Opening...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4 mr-2" />
                  Download Dataset
                </>
              )}
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
