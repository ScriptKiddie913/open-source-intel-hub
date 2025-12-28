'use client';

/* ============================================================================
   DarkWebScanner.tsx
   Enterprise Dark Web & Data Leak Intelligence Dashboard
   ============================================================================ */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Shield,
  Search,
  Loader2,
  AlertTriangle,
  Globe,
  Database,
  Lock,
  Eye,
  Filter,
  Clock,
  RefreshCcw,
  ExternalLink,
  Layers,
  Radar,
  Bug,
  FileText,
  User,
  Hash,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
  scanDarkWebLeaks,
  DarkWebLeak,
} from '@/services/enhancedThreatService';

import { toast } from 'sonner';
import { cn } from '@/lib/utils';

/* ============================================================================
   TYPES & CONSTANTS
   ============================================================================ */

type Severity = 'critical' | 'high' | 'medium' | 'low';
type SeverityFilter = Severity | 'all';

type ViewMode = 'cards' | 'compact';

interface Stats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const SEVERITY_ORDER: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'text-red-500 border-red-500/40 bg-red-500/10',
  high: 'text-orange-500 border-orange-500/40 bg-orange-500/10',
  medium: 'text-yellow-500 border-yellow-500/40 bg-yellow-500/10',
  low: 'text-blue-500 border-blue-500/40 bg-blue-500/10',
};

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-blue-500/20 text-blue-400',
};

/* ============================================================================
   TYPE GUARDS & HELPERS
   ============================================================================ */

function isSeverity(value: string): value is Severity {
  return (
    value === 'critical' ||
    value === 'high' ||
    value === 'medium' ||
    value === 'low'
  );
}

function normalizeSeverity(value: string): Severity {
  return isSeverity(value) ? value : 'low';
}

function formatDate(date: string): string {
  try {
    return new Date(date).toLocaleString();
  } catch {
    return 'Unknown';
  }
}

/* ============================================================================
   MAIN COMPONENT
   ============================================================================ */

export function DarkWebScanner() {
  /* ------------------------------------------------------------------------
     STATE
     ------------------------------------------------------------------------ */

  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  const [leaks, setLeaks] = useState<DarkWebLeak[]>([]);
  const [recentLeaks, setRecentLeaks] = useState<DarkWebLeak[]>([]);

  const [severityFilter, setSeverityFilter] =
    useState<SeverityFilter>('all');

  const [viewMode, setViewMode] = useState<ViewMode>('cards');
  const [autoRefresh, setAutoRefresh] = useState(false);

  const refreshTimer = useRef<NodeJS.Timeout | null>(null);

  /* ------------------------------------------------------------------------
     LOAD RECENT LEAKS
     ------------------------------------------------------------------------ */

  const loadRecentLeaks = useCallback(async () => {
    try {
      const data = await scanDarkWebLeaks();
      setRecentLeaks(data);
    } catch (err) {
      console.error(err);
      toast.error('Failed to load recent leaks');
    }
  }, []);

  useEffect(() => {
    loadRecentLeaks();
  }, [loadRecentLeaks]);

  /* ------------------------------------------------------------------------
     AUTO REFRESH
     ------------------------------------------------------------------------ */

  useEffect(() => {
    if (!autoRefresh) {
      if (refreshTimer.current) {
        clearInterval(refreshTimer.current);
      }
      return;
    }

    refreshTimer.current = setInterval(() => {
      if (query.trim()) {
        handleSearch();
      }
    }, 60000);

    return () => {
      if (refreshTimer.current) {
        clearInterval(refreshTimer.current);
      }
    };
  }, [autoRefresh, query]);

  /* ------------------------------------------------------------------------
     SEARCH
     ------------------------------------------------------------------------ */

  const handleSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Enter a valid search query');
      return;
    }

    setLoading(true);
    setLeaks([]);

    try {
      const results = await scanDarkWebLeaks(query);
      setLeaks(results);

      if (results.length === 0) {
        toast.info('No leaks found');
      } else {
        toast.success(`Detected ${results.length} leak signals`);
      }
    } catch (err) {
      console.error(err);
      toast.error('Dark web scan failed');
    } finally {
      setLoading(false);
    }
  }, [query]);

  /* ------------------------------------------------------------------------
     FILTERING
     ------------------------------------------------------------------------ */

  const filteredLeaks = useMemo(() => {
    if (severityFilter === 'all') return leaks;
    return leaks.filter(
      l => normalizeSeverity(l.severity) === severityFilter
    );
  }, [leaks, severityFilter]);

  const stats: Stats = useMemo(() => {
    const base: Stats = {
      total: filteredLeaks.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    filteredLeaks.forEach(l => {
      const sev = normalizeSeverity(l.severity);
      base[sev]++;
    });

    return base;
  }, [filteredLeaks]);

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
              Dark Web Intelligence Scanner
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Continuous monitoring of dark web leaks, dumps, and
              underground data exposure
            </p>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={loadRecentLeaks}
          >
            <RefreshCcw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* ETHICS */}
        <Card className="border-destructive/40 bg-destructive/10">
          <CardContent className="p-4 flex gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive mt-1" />
            <div>
              <h3 className="font-semibold text-destructive">
                Authorized Use Only
              </h3>
              <p className="text-sm text-muted-foreground">
                This system is for defensive threat intelligence,
                breach monitoring, and research purposes only.
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
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
                placeholder="Email, domain, username, keyword..."
                className="pl-10"
              />
            </div>

            <Button onClick={handleSearch} disabled={loading}>
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Eye className="h-4 w-4 mr-2" />
                  Scan
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* STATS */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Stat label="Total" value={stats.total} icon={Database} />
          <Stat label="Critical" value={stats.critical} icon={Bug} />
          <Stat label="High" value={stats.high} icon={Shield} />
          <Stat label="Medium" value={stats.medium} icon={AlertTriangle} />
          <Stat label="Low" value={stats.low} icon={FileText} />
        </div>

        {/* TABS */}
        <Tabs defaultValue="search">
          <TabsList>
            <TabsTrigger value="search">Search Results</TabsTrigger>
            <TabsTrigger value="recent">Recent Leaks</TabsTrigger>
          </TabsList>

          {/* SEARCH RESULTS */}
          <TabsContent value="search" className="space-y-4 mt-4">
            <div className="flex flex-wrap gap-2 items-center">
              <Filter className="h-4 w-4 text-muted-foreground" />
              {(['all', ...SEVERITY_ORDER] as SeverityFilter[]).map(s => (
                <Button
                  key={s}
                  size="sm"
                  variant={severityFilter === s ? 'default' : 'outline'}
                  onClick={() => setSeverityFilter(s)}
                >
                  {s.toUpperCase()}
                </Button>
              ))}

              <div className="flex-1" />

              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  setViewMode(v =>
                    v === 'cards' ? 'compact' : 'cards'
                  )
                }
              >
                <Layers className="h-4 w-4 mr-2" />
                {viewMode === 'cards' ? 'Compact' : 'Cards'}
              </Button>
            </div>

            {filteredLeaks.map(leak => (
              <LeakCard
                key={leak.id}
                leak={leak}
                view={viewMode}
              />
            ))}

            {!loading && filteredLeaks.length === 0 && (
              <Card>
                <CardContent className="p-12 text-center">
                  <Globe className="h-12 w-12 mx-auto text-muted-foreground/40 mb-4" />
                  <p className="text-muted-foreground">
                    No results found
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* RECENT */}
          <TabsContent value="recent" className="mt-4 space-y-3">
            {recentLeaks.map(leak => (
              <LeakCard
                key={leak.id}
                leak={leak}
                view="compact"
              />
            ))}
          </TabsContent>
        </Tabs>

        {/* SOURCES */}
        <Card className="border-primary/40 bg-primary/5">
          <CardContent className="p-4 flex gap-3">
            <Database className="h-5 w-5 text-primary" />
            <div>
              <h3 className="font-semibold">Intelligence Sources</h3>
              <p className="text-sm text-muted-foreground">
                Darknet forums • Paste sites • Breach repositories •
                Underground markets • OSINT feeds
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
          <p className="text-xs text-muted-foreground">{label}</p>
          <p className="font-mono font-bold">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function LeakCard({
  leak,
  view,
}: {
  leak: DarkWebLeak;
  view: 'cards' | 'compact';
}) {
  const sev = normalizeSeverity(leak.severity);

  return (
    <Card className={cn('border', SEVERITY_COLORS[sev])}>
      <CardContent className="p-4 space-y-3">
        <div className="flex justify-between gap-4">
          <div>
            <h3 className="font-semibold">{leak.title}</h3>
            <p className="text-sm text-muted-foreground">
              {leak.description}
            </p>
          </div>

          <Badge className={SEVERITY_BADGE[sev]}>
            {sev.toUpperCase()}
          </Badge>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <Meta icon={Database} label="Records">
            {leak.recordCount.toLocaleString()}
          </Meta>
          <Meta icon={Globe} label="Source">
            {leak.source}
          </Meta>
          <Meta icon={Clock} label="Date">
            {formatDate(leak.leakDate)}
          </Meta>
          <Meta icon={User} label="Entities">
            {leak.affectedEntities.length}
          </Meta>
        </div>

        {leak.indicators && leak.indicators.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {leak.indicators.slice(0, 6).map(ind => (
              <Badge
                key={ind}
                variant="outline"
                className="font-mono"
              >
                <Hash className="h-3 w-3 mr-1" />
                {ind}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Meta({
  icon: Icon,
  label,
  children,
}: {
  icon: any;
  label: string;
  children: any;
}) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="h-4 w-4 text-muted-foreground" />
      <div>
        <p className="text-xs text-muted-foreground">{label}</p>
        <p className="font-mono">{children}</p>
      </div>
    </div>
  );
}
