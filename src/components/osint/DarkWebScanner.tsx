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
  Shield,
  Activity,
  ExternalLink,
  Hash,
  Info,
  Layers,
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

/* ============================================================================ */
/* TYPES                                                                        */
/* ============================================================================ */

type ViewMode = 'cards' | 'compact';
type TabMode = 'onions' | 'signals';

/* ============================================================================ */
/* CONSTANTS                                                                    */
/* ============================================================================ */

const RISK_COLORS: Record<
  'critical' | 'high' | 'medium' | 'low',
  string
> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

const SOURCE_COLORS: Record<string, string> = {
  pastebin: 'bg-red-500/10 text-red-400 border-red-500/30',
  psbdmp: 'bg-red-500/10 text-red-400 border-red-500/30',
  ghostbin: 'bg-purple-500/10 text-purple-400 border-purple-500/30',
  rentry: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30',
  github_gist: 'bg-gray-500/10 text-gray-300 border-gray-500/30',
  libraryofleaks: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  archive: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
  intelx: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
};

/* ============================================================================ */
/* MAIN COMPONENT                                                               */
/* ============================================================================ */

export function DarkWebScanner() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const [onionSites, setOnionSites] = useState<OnionSite[]>([]);
  const [signals, setSignals] = useState<LeakSignal[]>([]);

  const [tab, setTab] = useState<TabMode>('onions');
  const [viewMode] = useState<ViewMode>('cards');

  const [uptimeLoading, setUptimeLoading] = useState<Record<string, boolean>>(
    {}
  );

  const refreshTimer = useRef<number | null>(null);

  /* -------------------------------------------------------------------------- */
  /* SEARCH EXECUTION                                                           */
  /* -------------------------------------------------------------------------- */

  const runSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a search keyword (domain, email, company, etc.)');
      return;
    }

    setLoading(true);
    setOnionSites([]);
    setSignals([]);

    try {
      const [onions, sigs] = await Promise.all([
        discoverOnionSites(query),
        searchDarkWebSignals(query),
      ]);

      setOnionSites(onions);
      setSignals(sigs);

      if (onions.length === 0 && sigs.length === 0) {
        toast.info('No results found. Try a different search term.');
      } else {
        toast.success(
          `Found ${onions.length} onion services and ${sigs.length} exposure signals`
        );
      }
    } catch (err) {
      console.error(err);
      toast.error('Dark web discovery failed');
    } finally {
      setLoading(false);
    }
  }, [query]);

  /* -------------------------------------------------------------------------- */
  /* AUTO REFRESH                                                               */
  /* -------------------------------------------------------------------------- */

  useEffect(() => {
    if (refreshTimer.current !== null) {
      clearInterval(refreshTimer.current);
    }

    refreshTimer.current = window.setInterval(() => {
      if (query.trim()) {
        runSearch();
      }
    }, 300000);

    return () => {
      if (refreshTimer.current !== null) {
        clearInterval(refreshTimer.current);
      }
    };
  }, [query, runSearch]);

  /* -------------------------------------------------------------------------- */
  /* UPTIME CHECK                                                               */
  /* -------------------------------------------------------------------------- */

  const checkUptime = async (site: OnionSite) => {
    setUptimeLoading(prev => ({ ...prev, [site.url]: true }));

    try {
      const result = await checkOnionUptime(site.url);

      setOnionSites(prev =>
        prev.map(o =>
          o.url === site.url
            ? {
                ...o,
                status: result.status,
                lastSeen: result.checkedAt,
              }
            : o
        )
      );

      toast.success(`${site.url} is ${result.status}`);
    } catch {
      toast.error('Uptime check failed');
    } finally {
      setUptimeLoading(prev => ({ ...prev, [site.url]: false }));
    }
  };

  /* -------------------------------------------------------------------------- */
  /* STATS                                                                      */
  /* -------------------------------------------------------------------------- */

  const stats = useMemo(() => {
    return {
      onions: onionSites.length,
      signals: signals.length,
      online: onionSites.filter(o => o.status === 'online').length,
      offline: onionSites.filter(o => o.status === 'offline').length,
      critical: onionSites.filter(o => o.riskLevel === 'critical').length,
      high: onionSites.filter(o => o.riskLevel === 'high').length,
    };
  }, [onionSites, signals]);

  /* ========================================================================== */
  /* RENDER                                                                     */
  /* ========================================================================== */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <header className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex gap-3 items-center">
            <Radar className="h-8 w-8 text-primary" />
            Dark Web Intelligence Monitor
          </h1>
          <p className="text-muted-foreground mt-2">
            Metadata-only discovery of onion services, leaks, and exposure datasets
          </p>
        </div>

        <Button
          variant="outline"
          size="sm"
          onClick={runSearch}
          disabled={loading}
        >
          <RefreshCcw
            className={cn('h-4 w-4 mr-2', loading && 'animate-spin')}
          />
          Refresh
        </Button>
      </header>

      {/* SEARCH */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4" />
              <Input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runSearch()}
                placeholder="Search: email, domain, company, breach keyword…"
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

          <div className="mt-3 text-xs text-muted-foreground flex gap-2">
            <Info className="h-3 w-3" />
            Try keywords like <code>ransomware</code>, <code>facebook</code>,{' '}
            <code>database</code>
          </div>
        </CardContent>
      </Card>

      {/* TABS */}
      <Tabs value={tab} onValueChange={v => setTab(v as TabMode)}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="onions">
            <Globe className="h-4 w-4 mr-2" />
            Onion Services ({onionSites.length})
          </TabsTrigger>
          <TabsTrigger value="signals">
            <Database className="h-4 w-4 mr-2" />
            Exposure Signals ({signals.length})
          </TabsTrigger>
        </TabsList>

        {/* ONIONS */}
        <TabsContent value="onions" className="mt-6 space-y-4">
          {!loading &&
            onionSites.map(site => (
              <OnionCard
                key={site.url}
                site={site}
                loading={uptimeLoading[site.url]}
                onCheck={() => checkUptime(site)}
              />
            ))}
        </TabsContent>

        {/* SIGNALS */}
        <TabsContent value="signals" className="mt-6 space-y-3">
          {!loading &&
            signals.map(sig => (
              <SignalCard key={sig.id} signal={sig} />
            ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ============================================================================ */
/* SUB COMPONENTS                                                               */
/* ============================================================================ */

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
        <div className="flex justify-between gap-4 mb-4">
          <div className="flex-1">
            <h3 className="font-mono text-sm break-all">{site.url}</h3>
            <p className="font-semibold mt-1">{site.title}</p>
            <p className="text-sm text-muted-foreground">{site.description}</p>
          </div>

          <Badge className={RISK_COLORS[site.riskLevel]}>
            {site.riskLevel.toUpperCase()}
          </Badge>
        </div>

        <div className="flex justify-between items-center">
          <span className="text-xs text-muted-foreground flex gap-2">
            <Clock className="h-3 w-3" />
            {new Date(site.lastSeen).toLocaleString()}
          </span>

          <Button size="sm" variant="outline" onClick={onCheck} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Check'}
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
        <div className="flex justify-between gap-4 mb-3">
          <div className="flex-1">
            <h3 className="font-semibold">{signal.title}</h3>

            <div className="flex gap-2 mt-2">
              <Badge
                variant="outline"
                className={SOURCE_COLORS[signal.source] ?? ''}
              >
                {signal.source.toUpperCase()}
              </Badge>

              <Badge variant="secondary" className="font-mono text-xs">
                <Hash className="h-3 w-3 mr-1" />
                {signal.indicator}
              </Badge>
            </div>

            <p className="text-xs text-muted-foreground mt-2">
              {signal.context}
            </p>
          </div>
        </div>

        <div className="flex justify-between items-center">
          <span className="text-xs text-muted-foreground flex gap-2">
            <Clock className="h-3 w-3" />
            {new Date(signal.timestamp).toLocaleString()}
          </span>

          <Button size="sm" variant="outline" asChild>
            <a href={signal.url} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3 w-3 mr-2" />
              View Source
            </a>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}
