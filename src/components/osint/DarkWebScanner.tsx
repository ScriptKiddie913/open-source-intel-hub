'use client';

/* ============================================================================
   DarkWebScanner.tsx
   Full-scale Dark Web Intelligence UI
   CLIENT ONLY — Server logic via API routes
============================================================================ */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

/* ============================================================================
   Icons
============================================================================ */

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
  Filter,
  Layers,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

/* ============================================================================
   UI Components
============================================================================ */

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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

/* ============================================================================
   TYPES (CLIENT MIRROR OF SERVER TYPES)
============================================================================ */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';

export interface OnionSite {
  url: string;
  title: string;
  description: string;
  category: string;
  riskLevel: RiskLevel;
  lastSeen: string;
  status: 'online' | 'offline' | 'unknown';
  tags: string[];
  language?: string;
}

export interface LeakSignal {
  id: string;
  title: string;
  indicator: string;
  source: string;
  timestamp: string;
  url: string;
  context: string;
  metadata?: {
    channelName?: string;
    subscribers?: number;
    views?: number;
    emails?: string[];
    bitcoins?: string[];
  };
}

/* ============================================================================
   UI CONSTANTS
============================================================================ */

const RISK_COLORS: Record<RiskLevel, string> = {
  critical: 'border-red-500/40 bg-red-500/10 text-red-400',
  high: 'border-orange-500/40 bg-orange-500/10 text-orange-400',
  medium: 'border-yellow-500/40 bg-yellow-500/10 text-yellow-400',
  low: 'border-blue-500/40 bg-blue-500/10 text-blue-400',
};

const SOURCE_BADGES: Record<string, string> = {
  telegram: 'bg-blue-500/20 text-blue-400',
  pastebin: 'bg-orange-500/20 text-orange-400',
  psbdmp: 'bg-purple-500/20 text-purple-400',
  rentry: 'bg-green-500/20 text-green-400',
  ghostbin: 'bg-gray-500/20 text-gray-400',
  github_gist: 'bg-black/30 text-gray-300',
};

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export default function DarkWebScanner() {
  /* ------------------------------------------------------------------------
     STATE
  ------------------------------------------------------------------------ */

  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [onionSites, setOnionSites] = useState<OnionSite[]>([]);
  const [signals, setSignals] = useState<LeakSignal[]>([]);

  const [tab, setTab] = useState<'onions' | 'signals'>('onions');
  const [riskFilter, setRiskFilter] = useState<RiskLevel | 'all'>('all');
  const [sourceFilter, setSourceFilter] = useState<string | 'all'>('all');

  const [uptimeLoading, setUptimeLoading] = useState<Record<string, boolean>>(
    {}
  );

  const refreshTimer = useRef<number | null>(null);

  /* ------------------------------------------------------------------------
     SEARCH HANDLER (SERVER PROXY)
  ------------------------------------------------------------------------ */

  const runSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a keyword to search');
      return;
    }

    setLoading(true);
    setError(null);
    setOnionSites([]);
    setSignals([]);

    try {
      const res = await fetch('/api/darkweb', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query }),
      });

      if (!res.ok) {
        throw new Error(`API error: ${res.status}`);
      }

      const data = await res.json();

      setOnionSites(data.onions || []);
      setSignals(data.signals || []);

      if ((data.onions?.length || 0) === 0 && (data.signals?.length || 0) === 0) {
        toast.info('No results found. Try another keyword.');
      } else {
        toast.success(
          `Found ${data.onions.length} onion sites and ${data.signals.length} signals`
        );
      }
    } catch (err: any) {
      console.error(err);
      setError('Dark web scan failed');
      toast.error('Dark web scan failed');
    } finally {
      setLoading(false);
    }
  }, [query]);

  /* ------------------------------------------------------------------------
     AUTO REFRESH (5 MIN)
  ------------------------------------------------------------------------ */

  useEffect(() => {
    if (refreshTimer.current) {
      clearInterval(refreshTimer.current);
    }

    refreshTimer.current = window.setInterval(() => {
      if (query.trim()) {
        runSearch();
      }
    }, 300000);

    return () => {
      if (refreshTimer.current) {
        clearInterval(refreshTimer.current);
      }
    };
  }, [query, runSearch]);

  /* ------------------------------------------------------------------------
     ONION UPTIME CHECK (SERVER PROXY)
  ------------------------------------------------------------------------ */

  const checkUptime = async (site: OnionSite) => {
    setUptimeLoading(prev => ({ ...prev, [site.url]: true }));

    try {
      const res = await fetch('/api/onion-uptime', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ onion: site.url }),
      });

      const result = await res.json();

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

  /* ------------------------------------------------------------------------
     FILTERED DATA
  ------------------------------------------------------------------------ */

  const filteredOnions = useMemo(() => {
    return onionSites.filter(o =>
      riskFilter === 'all' ? true : o.riskLevel === riskFilter
    );
  }, [onionSites, riskFilter]);

  const filteredSignals = useMemo(() => {
    return signals.filter(s =>
      sourceFilter === 'all' ? true : s.source === sourceFilter
    );
  }, [signals, sourceFilter]);

  /* ------------------------------------------------------------------------
     STATS
  ------------------------------------------------------------------------ */

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

  /* ------------------------------------------------------------------------
     RENDER
  ------------------------------------------------------------------------ */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* HEADER */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Radar className="h-8 w-8 text-primary" />
            Dark Web Intelligence Monitor
          </h1>
          <p className="text-muted-foreground mt-2">
            Metadata-only OSINT from onion indexes, paste sites, and public channels
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
      </div>

      {/* LEGAL NOTICE */}
      <Card className="border-yellow-500/40 bg-yellow-500/10">
        <CardContent className="p-4 flex gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-500 mt-1" />
          <div>
            <h3 className="font-semibold text-yellow-600 dark:text-yellow-500">
              Legal & Safe Intelligence
            </h3>
            <p className="text-sm text-muted-foreground mt-1">
              No Tor daemon. No illegal scraping. No content downloads.
              This tool queries public indexes and metadata sources only.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* SEARCH */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runSearch()}
                placeholder="Search: leak, ransomware, database, gmail, company..."
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
        </CardContent>
      </Card>

      {/* STATS */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <StatCard icon={Globe} label="Onions" value={stats.onions} />
        <StatCard icon={Database} label="Signals" value={stats.signals} />
        <StatCard icon={Activity} label="Online" value={stats.online} />
        <StatCard icon={Shield} label="Offline" value={stats.offline} />
        <StatCard
          icon={AlertTriangle}
          label="Critical"
          value={stats.critical}
          color="text-red-500"
        />
        <StatCard
          icon={AlertTriangle}
          label="High"
          value={stats.high}
          color="text-orange-500"
        />
      </div>

      {/* FILTERS */}
      <div className="flex gap-3 flex-wrap">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm">
              <Filter className="h-4 w-4 mr-2" />
              Risk: {riskFilter}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            {['all', 'critical', 'high', 'medium', 'low'].map(r => (
              <DropdownMenuItem
                key={r}
                onClick={() => setRiskFilter(r as any)}
              >
                {r}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm">
              <Layers className="h-4 w-4 mr-2" />
              Source: {sourceFilter}
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuItem onClick={() => setSourceFilter('all')}>
              all
            </DropdownMenuItem>
            {Object.keys(SOURCE_BADGES).map(src => (
              <DropdownMenuItem
                key={src}
                onClick={() => setSourceFilter(src)}
              >
                {src}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* TABS */}
      <Tabs value={tab} onValueChange={v => setTab(v as any)}>
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="onions">
            <Globe className="h-4 w-4 mr-2" />
            Onion Discovery
          </TabsTrigger>
          <TabsTrigger value="signals">
            <Database className="h-4 w-4 mr-2" />
            Exposure Signals
          </TabsTrigger>
        </TabsList>

        {/* ONIONS */}
        <TabsContent value="onions" className="mt-6 space-y-4">
          {loading && <CenteredLoader />}
          {!loading && filteredOnions.length === 0 && <EmptyState text="No onion sites found" />}
          {!loading &&
            filteredOnions.map(site => (
              <OnionCard
                key={site.url}
                site={site}
                loading={uptimeLoading[site.url]}
                onCheck={() => checkUptime(site)}
              />
            ))}
        </TabsContent>

        {/* SIGNALS */}
        <TabsContent value="signals" className="mt-6 space-y-4">
          {loading && <CenteredLoader />}
          {!loading && filteredSignals.length === 0 && <EmptyState text="No signals found" />}
          {!loading &&
            filteredSignals.map(sig => (
              <SignalCard key={sig.id} signal={sig} />
            ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ============================================================================
   SUB COMPONENTS
============================================================================ */

function StatCard({
  icon: Icon,
  label,
  value,
  color,
}: {
  icon: any;
  label: string;
  value: number;
  color?: string;
}) {
  return (
    <Card>
      <CardContent className="pt-6 text-center">
        <Icon className={cn('h-5 w-5 mx-auto mb-2', color)} />
        <div className={cn('text-2xl font-bold', color)}>{value}</div>
        <div className="text-xs text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}

function CenteredLoader() {
  return (
    <div className="flex justify-center py-12">
      <Loader2 className="h-8 w-8 animate-spin text-primary" />
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return (
    <Card className="border-dashed">
      <CardContent className="py-12 text-center text-muted-foreground">
        {text}
      </CardContent>
    </Card>
  );
}

function OnionCard({
  site,
  loading,
  onCheck,
}: {
  site: OnionSite;
  loading?: boolean;
  onCheck: () => void;
}) {
  return (
    <Card className={cn('border-2', RISK_COLORS[site.riskLevel])}>
      <CardContent className="pt-6 space-y-4">
        <div className="flex justify-between gap-4">
          <div className="min-w-0">
            <p className="font-mono text-xs break-all">{site.url}</p>
            <h3 className="font-semibold">{site.title}</h3>
            <p className="text-sm text-muted-foreground">{site.description}</p>
          </div>

          <Button size="sm" variant="outline" onClick={onCheck} disabled={loading}>
            {loading ? <Loader2 className="animate-spin h-4 w-4" /> : 'Check'}
          </Button>
        </div>

        <div className="flex flex-wrap gap-2">
          {site.tags.map(tag => (
            <Badge key={tag} variant="outline">
              <Hash className="h-3 w-3 mr-1" />
              {tag}
            </Badge>
          ))}
        </div>

        <div className="flex justify-between text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {new Date(site.lastSeen).toLocaleString()}
          </span>
          <span className="flex items-center gap-1">
            <Activity className="h-3 w-3" />
            {site.status}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function SignalCard({ signal }: { signal: LeakSignal }) {
  return (
    <Card>
      <CardContent className="pt-6 space-y-3">
        <div className="flex justify-between gap-3">
          <div>
            <h3 className="font-semibold">{signal.title}</h3>
            <p className="text-xs text-muted-foreground">{signal.context}</p>
          </div>
          <Badge className={SOURCE_BADGES[signal.source] || ''}>
            {signal.source}
          </Badge>
        </div>

        <div className="flex justify-between items-center text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <Clock className="h-3 w-3" />
            {new Date(signal.timestamp).toLocaleString()}
          </span>
          <a
            href={signal.url}
            target="_blank"
            rel="noreferrer"
            className="flex items-center gap-1 text-primary"
          >
            <ExternalLink className="h-3 w-3" />
            Source
          </a>
        </div>
      </CardContent>
    </Card>
  );
}

