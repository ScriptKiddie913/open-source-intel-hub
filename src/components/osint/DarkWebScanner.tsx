'use client';

/* ============================================================================
   DarkWebScanner.tsx
   REAL Dark Web Exposure Monitor (Metadata-Based, Legal, OSINT-Grade)
   ============================================================================ */

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
  Filter,
  Clock,
  RefreshCcw,
  Layers,
  Shield,
  Bug,
  FileText,
  User,
  Hash,
  ExternalLink,
  Activity,
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
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';

import {
  discoverOnionSites,
  checkOnionUptime,
  searchDarkWebSignals,
  OnionSite,
  LeakSignal,
} from '@/services/torService';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

/* ============================================================================
   TYPES & CONSTANTS
============================================================================ */

type ViewMode = 'cards' | 'compact';
type Section = 'onions' | 'signals';

interface Stats {
  onions: number;
  signals: number;
  online: number;
  offline: number;
}

const RISK_COLORS: Record<
  'critical' | 'high' | 'medium' | 'low',
  string
> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function DarkWebScanner() {
  /* ------------------------------------------------------------------------
     STATE
  ------------------------------------------------------------------------ */

  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const [onions, setOnions] = useState<OnionSite[]>([]);
  const [signals, setSignals] = useState<LeakSignal[]>([]);

  const [section, setSection] = useState<Section>('onions');
  const [viewMode, setViewMode] = useState<ViewMode>('cards');

  const [checkingUptime, setCheckingUptime] = useState<
    Record<string, boolean>
  >({});

  const autoRefreshRef = useRef<NodeJS.Timeout | null>(
    null
  );

  /* ------------------------------------------------------------------------
     SEARCH HANDLER
  ------------------------------------------------------------------------ */

  const handleSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a search keyword');
      return;
    }

    setLoading(true);
    setOnions([]);
    setSignals([]);

    try {
      const [onionResults, signalResults] =
        await Promise.all([
          discoverOnionSites(query),
          searchDarkWebSignals(query),
        ]);

      setOnions(onionResults);
      setSignals(signalResults);

      toast.success(
        `Discovered ${onionResults.length} onion sites and ${signalResults.length} exposure signals`
      );
    } catch (err) {
      console.error(err);
      toast.error('Dark web discovery failed');
    } finally {
      setLoading(false);
    }
  }, [query]);

  /* ------------------------------------------------------------------------
     AUTO REFRESH (METADATA ONLY)
  ------------------------------------------------------------------------ */

  useEffect(() => {
    if (autoRefreshRef.current) {
      clearInterval(autoRefreshRef.current);
    }

    autoRefreshRef.current = setInterval(() => {
      if (query.trim()) {
        handleSearch();
      }
    }, 120000);

    return () => {
      if (autoRefreshRef.current) {
        clearInterval(autoRefreshRef.current);
      }
    };
  }, [query, handleSearch]);

  /* ------------------------------------------------------------------------
     STATS
  ------------------------------------------------------------------------ */

  const stats: Stats = useMemo(() => {
    let online = 0;
    let offline = 0;

    onions.forEach(o => {
      if (o.status === 'online') online++;
      if (o.status === 'offline') offline++;
    });

    return {
      onions: onions.length,
      signals: signals.length,
      online,
      offline,
    };
  }, [onions, signals]);

  /* ------------------------------------------------------------------------
     UPTIME CHECK
  ------------------------------------------------------------------------ */

  const runUptimeCheck = async (onion: OnionSite) => {
    setCheckingUptime(prev => ({
      ...prev,
      [onion.url]: true,
    }));

    try {
      const result = await checkOnionUptime(
        onion.url
      );

      setOnions(prev =>
        prev.map(o =>
          o.url === onion.url
            ? {
                ...o,
                status: result.status,
                lastSeen: result.checkedAt,
              }
            : o
        )
      );
    } catch {
      toast.error('Uptime check failed');
    } finally {
      setCheckingUptime(prev => ({
        ...prev,
        [onion.url]: false,
      }));
    }
  };

  /* ------------------------------------------------------------------------
     RENDER
  ------------------------------------------------------------------------ */

  return (
    <TooltipProvider>
      <div className="p-6 space-y-6 animate-fade-in">
        {/* HEADER */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Radar className="h-7 w-7 text-primary" />
              Dark Web Exposure Monitor
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Real metadata-based monitoring of onion
              services and public leak indicators
            </p>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={handleSearch}
            disabled={loading}
          >
            <RefreshCcw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* LEGAL NOTICE */}
        <Card className="border-yellow-500/40 bg-yellow-500/10">
          <CardContent className="p-4 flex gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-500 mt-1" />
            <div>
              <h3 className="font-semibold">
                Metadata-Only Intelligence
              </h3>
              <p className="text-sm text-muted-foreground">
                This system performs passive OSINT
                collection using public indexes and
                metadata sources only. No authentication
                bypass, dump downloads, or illegal
                scraping is performed.
              </p>
            </div>
          </CardContent>
        </Card>

        {/* SEARCH BAR */}
        <Card>
          <CardContent className="p-4 flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={e =>
                  setQuery(e.target.value)
                }
                onKeyDown={e =>
                  e.key === 'Enter' &&
                  handleSearch()
                }
                placeholder="Domain, email, company, keyword..."
                className="pl-10"
              />
            </div>

            <Button
              onClick={handleSearch}
              disabled={loading}
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Eye className="h-4 w-4 mr-2" />
                  Discover
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* STATS */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <Stat
            label="Onion Sites"
            value={stats.onions}
            icon={Globe}
          />
          <Stat
            label="Exposure Signals"
            value={stats.signals}
            icon={Database}
          />
          <Stat
            label="Online"
            value={stats.online}
            icon={Activity}
          />
          <Stat
            label="Offline"
            value={stats.offline}
            icon={Shield}
          />
        </div>

        {/* TABS */}
        <Tabs
          defaultValue="onions"
          onValueChange={v =>
            setSection(v as Section)
          }
        >
          <TabsList>
            <TabsTrigger value="onions">
              Onion Discovery
            </TabsTrigger>
            <TabsTrigger value="signals">
              Exposure Signals
            </TabsTrigger>
          </TabsList>

          {/* ONION SITES */}
          <TabsContent
            value="onions"
            className="mt-4 space-y-4"
          >
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  setViewMode(v =>
                    v === 'cards'
                      ? 'compact'
                      : 'cards'
                  )
                }
              >
                <Layers className="h-4 w-4 mr-2" />
                {viewMode === 'cards'
                  ? 'Compact'
                  : 'Cards'}
              </Button>
            </div>

            {onions.map(site => (
              <OnionCard
                key={site.url}
                site={site}
                view={viewMode}
                loading={
                  checkingUptime[site.url]
                }
                onCheck={() =>
                  runUptimeCheck(site)
                }
              />
            ))}

            {!loading && onions.length === 0 && (
              <EmptyState
                icon={Globe}
                text="No onion sites discovered"
              />
            )}
          </TabsContent>

          {/* SIGNALS */}
          <TabsContent
            value="signals"
            className="mt-4 space-y-3"
          >
            {signals.map(sig => (
              <SignalCard
                key={sig.id}
                signal={sig}
              />
            ))}

            {!loading &&
              signals.length === 0 && (
                <EmptyState
                  icon={Database}
                  text="No exposure signals found"
                />
              )}
          </TabsContent>
        </Tabs>

        {/* SOURCES */}
        <Card className="border-primary/40 bg-primary/5">
          <CardContent className="p-4 flex gap-3">
            <Database className="h-5 w-5 text-primary" />
            <div>
              <h3 className="font-semibold">
                Real Data Sources
              </h3>
              <p className="text-sm text-muted-foreground">
                Ahmia (onion index) • Pastebin
                archive • Ghostbin • Rentry •
                GitHub Gists • Tor2Web gateways
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </TooltipProvider>
  );
}

/* ============================================================================
   SUB COMPONENTS
============================================================================ */

function Stat({
  label,
  value,
  icon: Icon,
}: {
  label: string;
  value: number;
  icon: any;
}) {
  return (
    <Card>
      <CardContent className="p-4 flex items-center gap-3">
        <Icon className="h-5 w-5 text-primary" />
        <div>
          <p className="text-xs text-muted-foreground">
            {label}
          </p>
          <p className="font-mono font-bold">
            {value}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function OnionCard({
  site,
  view,
  loading,
  onCheck,
}: {
  site: OnionSite;
  view: ViewMode;
  loading: boolean;
  onCheck: () => void;
}) {
  return (
    <Card
      className={cn(
        'border',
        RISK_COLORS[site.riskLevel]
      )}
    >
      <CardContent className="p-4 space-y-3">
        <div className="flex justify-between gap-4">
          <div>
            <h3 className="font-mono break-all">
              {site.url}
            </h3>
            <p className="text-sm text-muted-foreground">
              {site.description}
            </p>
          </div>

          <Badge>{site.riskLevel}</Badge>
        </div>

        <div className="flex flex-wrap gap-2">
          {site.tags.map(tag => (
            <Badge
              key={tag}
              variant="outline"
            >
              {tag}
            </Badge>
          ))}
        </div>

        <div className="flex items-center justify-between text-sm">
          <span className="flex items-center gap-1 text-muted-foreground">
            <Clock className="h-3 w-3" />
            {new Date(
              site.lastSeen
            ).toLocaleString()}
          </span>

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
                <Activity className="h-4 w-4 mr-1" />
                Check
              </>
            )}
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function SignalCard({
  signal,
}: {
  signal: LeakSignal;
}) {
  return (
    <Card>
      <CardContent className="p-4 space-y-2">
        <div className="flex justify-between">
          <h3 className="font-semibold">
            {signal.title}
          </h3>
          <Badge variant="secondary">
            {signal.source}
          </Badge>
        </div>

        <p className="text-sm text-muted-foreground">
          Indicator: {signal.indicator}
        </p>

        <div className="flex justify-between text-xs text-muted-foreground">
          <span>
            {new Date(
              signal.timestamp
            ).toLocaleString()}
          </span>
          <a
            href={signal.url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 hover:underline"
          >
            View
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </CardContent>
    </Card>
  );
}

function EmptyState({
  icon: Icon,
  text,
}: {
  icon: any;
  text: string;
}) {
  return (
    <Card>
      <CardContent className="p-12 text-center">
        <Icon className="h-12 w-12 mx-auto text-muted-foreground/40 mb-4" />
        <p className="text-muted-foreground">
          {text}
        </p>
      </CardContent>
    </Card>
  );
}
