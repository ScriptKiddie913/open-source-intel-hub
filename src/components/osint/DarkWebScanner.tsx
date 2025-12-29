'use client';

/* ============================================================================
   DarkWebScanner.tsx
   FULL DARK WEB INTELLIGENCE DASHBOARD
   - Named exports ONLY (no default export)
   - Includes GraphVisualization & NewsIntelligence stubs
   - No other files need changes
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
   TYPES (CLIENT MIRROR)
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
   CONSTANTS
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
  github_gist: 'bg-neutral-500/20 text-neutral-300',
};

/* ============================================================================
   MAIN EXPORT — DarkWebScanner
============================================================================ */

export function DarkWebScanner() {
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
     SEARCH (SERVER PROXY)
  ------------------------------------------------------------------------ */

  const runSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a keyword');
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

      if (!res.ok) throw new Error(`API error ${res.status}`);

      const data = await res.json();

      setOnionSites(data.onions || []);
      setSignals(data.signals || []);

      if (
        (data.onions?.length || 0) === 0 &&
        (data.signals?.length || 0) === 0
      ) {
        toast.info('No results found');
      } else {
        toast.success(
          `Found ${data.onions.length} onion sites and ${data.signals.length} signals`
        );
      }
    } catch (e) {
      console.error(e);
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
    if (refreshTimer.current) clearInterval(refreshTimer.current);

    refreshTimer.current = window.setInterval(() => {
      if (query.trim()) runSearch();
    }, 300000);

    return () => {
      if (refreshTimer.current) clearInterval(refreshTimer.current);
    };
  }, [query, runSearch]);

  /* ------------------------------------------------------------------------
     UPTIME CHECK
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
     FILTERING
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
    <div className="p-6 space-y-6">
      {/* HEADER */}
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Radar className="h-8 w-8 text-primary" />
            Dark Web Intelligence Monitor
          </h1>
          <p className="text-muted-foreground mt-1">
            Metadata-only OSINT from public dark web indexes
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

      {/* LEGAL */}
      <Card className="border-yellow-500/40 bg-yellow-500/10">
        <CardContent className="p-4 flex gap-3">
          <AlertTriangle className="h-5 w-5 text-yellow-500 mt-1" />
          <div>
            <h3 className="font-semibold text-yellow-600">
              Legal & Safe Intelligence
            </h3>
            <p className="text-sm text-muted-foreground">
              No Tor daemon. No illegal access. Metadata only.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* SEARCH */}
      <Card>
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Input
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runSearch()}
              placeholder="Search: leak, database, ransomware, gmail..."
            />
            <Button onClick={runSearch} disabled={loading}>
              {loading ? <Loader2 className="animate-spin" /> : 'Discover'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* STATS */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
        <Stat label="Onions" value={stats.onions} icon={Globe} />
        <Stat label="Signals" value={stats.signals} icon={Database} />
        <Stat label="Online" value={stats.online} icon={Activity} />
        <Stat label="Offline" value={stats.offline} icon={Shield} />
        <Stat label="Critical" value={stats.critical} icon={AlertTriangle} />
        <Stat label="High" value={stats.high} icon={AlertTriangle} />
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
        <TabsList className="grid grid-cols-2">
          <TabsTrigger value="onions">Onion Sites</TabsTrigger>
          <TabsTrigger value="signals">Exposure Signals</TabsTrigger>
        </TabsList>

        <TabsContent value="onions" className="space-y-4 mt-4">
          {filteredOnions.map(site => (
            <OnionCard
              key={site.url}
              site={site}
              loading={uptimeLoading[site.url]}
              onCheck={() => checkUptime(site)}
            />
          ))}
        </TabsContent>

        <TabsContent value="signals" className="space-y-4 mt-4">
          {filteredSignals.map(sig => (
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
      <CardContent className="pt-6 text-center">
        <Icon className="h-5 w-5 mx-auto mb-2 text-primary" />
        <div className="text-2xl font-bold">{value}</div>
        <div className="text-xs text-muted-foreground">{label}</div>
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
      <CardContent className="pt-6 space-y-3">
        <div className="flex justify-between">
          <div>
            <p className="font-mono text-xs break-all">{site.url}</p>
            <h3 className="font-semibold">{site.title}</h3>
            <p className="text-sm text-muted-foreground">
              {site.description}
            </p>
          </div>
          <Button size="sm" onClick={onCheck} disabled={loading}>
            {loading ? <Loader2 className="animate-spin h-4 w-4" /> : 'Check'}
          </Button>
        </div>

        <div className="flex flex-wrap gap-2">
          {site.tags.map(t => (
            <Badge key={t} variant="outline">
              <Hash className="h-3 w-3 mr-1" />
              {t}
            </Badge>
          ))}
        </div>

        <div className="flex justify-between text-xs text-muted-foreground">
          <span>{new Date(site.lastSeen).toLocaleString()}</span>
          <span>{site.status}</span>
        </div>
      </CardContent>
    </Card>
  );
}

function SignalCard({ signal }: { signal: LeakSignal }) {
  return (
    <Card>
      <CardContent className="pt-6 space-y-2">
        <div className="flex justify-between">
          <h3 className="font-semibold">{signal.title}</h3>
          <Badge>{signal.source}</Badge>
        </div>
        <p className="text-xs text-muted-foreground">{signal.context}</p>
        <a
          href={signal.url}
          target="_blank"
          rel="noreferrer"
          className="text-primary text-xs flex items-center gap-1"
        >
          <ExternalLink className="h-3 w-3" />
          View source
        </a>
      </CardContent>
    </Card>
  );
}

/* ============================================================================
   ADDITIONAL EXPORTS (FIX ROLLUP ERRORS)
============================================================================ */

/**
 * Stub graph component to satisfy existing imports.
 * Fully replace later without breaking build.
 */
export function GraphVisualization() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Graph Visualization</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        Entity graph module placeholder.
      </CardContent>
    </Card>
  );
}

/**
 * Stub news intelligence component.
 */
export function NewsIntelligence() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>News Intelligence</CardTitle>
      </CardHeader>
      <CardContent className="text-sm text-muted-foreground">
        Dark web news correlation placeholder.
      </CardContent>
    </Card>
  );
}
