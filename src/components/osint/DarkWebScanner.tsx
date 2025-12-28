'use client';

// src/components/osint/DarkWebScanner.tsx

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Shield,
  Search,
  Loader2,
  AlertTriangle,
  Globe,
  Database,
  Lock,
  Eye,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

import { scanDarkWebLeaks, DarkWebLeak } from '@/services/enhancedThreatService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

type Severity = 'critical' | 'high' | 'medium' | 'low';
type SeverityFilter = Severity | 'all';

/* -------------------------------------------------------------------------- */
/* Type Guards                                                                */
/* -------------------------------------------------------------------------- */

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

/* -------------------------------------------------------------------------- */
/* Severity Styling Helpers                                                   */
/* -------------------------------------------------------------------------- */

function severityText(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'text-red-500';
    case 'high':
      return 'text-orange-500';
    case 'medium':
      return 'text-yellow-500';
    case 'low':
      return 'text-blue-500';
  }
}

function severityCard(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return 'border-red-500/40 bg-red-500/10';
    case 'high':
      return 'border-orange-500/40 bg-orange-500/10';
    case 'medium':
      return 'border-yellow-500/40 bg-yellow-500/10';
    case 'low':
      return 'border-blue-500/40 bg-blue-500/10';
  }
}

/* -------------------------------------------------------------------------- */
/* Component                                                                  */
/* -------------------------------------------------------------------------- */

export function DarkWebScanner() {
  const [query, setQuery] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);

  const [leaks, setLeaks] = useState<DarkWebLeak[]>([]);
  const [recentLeaks, setRecentLeaks] = useState<DarkWebLeak[]>([]);

  const [filterSeverity, setFilterSeverity] =
    useState<SeverityFilter>('all');

  /* ---------------------------------------------------------------------- */
  /* Load Recent Leaks                                                       */
  /* ---------------------------------------------------------------------- */

  const loadRecentLeaks = useCallback(async () => {
    try {
      const data = await scanDarkWebLeaks();
      setRecentLeaks(data);
    } catch (error) {
      console.error('Failed to load recent leaks:', error);
      toast.error('Failed to load recent leaks');
    }
  }, []);

  useEffect(() => {
    loadRecentLeaks();
  }, [loadRecentLeaks]);

  /* ---------------------------------------------------------------------- */
  /* Search Handler                                                         */
  /* ---------------------------------------------------------------------- */

  const handleSearch = useCallback(async () => {
    if (!query.trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setLoading(true);
    setLeaks([]);

    try {
      const results = await scanDarkWebLeaks(query);
      setLeaks(results);

      if (results.length === 0) {
        toast.info('No dark web leaks found');
      } else {
        toast.success(`Found ${results.length} potential leaks`);
      }
    } catch (error) {
      console.error('Dark web scan failed:', error);
      toast.error('Dark web scan failed');
    } finally {
      setLoading(false);
    }
  }, [query]);

  /* ---------------------------------------------------------------------- */
  /* Filtering Logic                                                        */
  /* ---------------------------------------------------------------------- */

  const filteredLeaks = useMemo(() => {
    if (filterSeverity === 'all') {
      return leaks;
    }

    return leaks.filter(
      leak => normalizeSeverity(leak.severity) === filterSeverity
    );
  }, [leaks, filterSeverity]);

  /* ---------------------------------------------------------------------- */
  /* Render                                                                 */
  /* ---------------------------------------------------------------------- */

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Lock className="h-7 w-7 text-primary" />
          Dark Web & Data Leak Monitor
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Monitor dark web forums, marketplaces, and paste sites for data leaks
        </p>
      </div>

      {/* Ethical Warning */}
      <Card className="border-destructive/40 bg-destructive/10">
        <CardContent className="p-4 flex gap-3">
          <AlertTriangle className="h-5 w-5 text-destructive mt-1" />
          <div>
            <h3 className="font-semibold text-destructive">
              Ethical Use Only
            </h3>
            <p className="text-sm text-muted-foreground mt-1">
              This tool is intended strictly for legitimate threat intelligence
              and security research. Unauthorized access or misuse may be illegal.
            </p>
          </div>
        </CardContent>
      </Card>

      {/* Search */}
      <Card>
        <CardContent className="p-4 flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  handleSearch();
                }
              }}
              placeholder="Search by email, domain, or keyword..."
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

      {/* Tabs */}
      <Tabs defaultValue="search">
        <TabsList>
          <TabsTrigger value="search">Search Results</TabsTrigger>
          <TabsTrigger value="recent">Recent Leaks</TabsTrigger>
        </TabsList>

        {/* Search Results */}
        <TabsContent value="search" className="mt-4 space-y-4">
          {leaks.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {(['all', 'critical', 'high', 'medium', 'low'] as SeverityFilter[]).map(
                severity => (
                  <Button
                    key={severity}
                    size="sm"
                    variant={filterSeverity === severity ? 'default' : 'outline'}
                    onClick={() => setFilterSeverity(severity)}
                  >
                    {severity.toUpperCase()}
                  </Button>
                )
              )}
            </div>
          )}

          {filteredLeaks.map(leak => {
            const sev = normalizeSeverity(leak.severity);

            return (
              <Card
                key={leak.id}
                className={cn('border', severityCard(sev))}
              >
                <CardContent className="p-4 space-y-3">
                  <div className="flex justify-between">
                    <div className="flex gap-3">
                      <Shield
                        className={cn('h-5 w-5', severityText(sev))}
                      />
                      <div>
                        <h3 className="font-semibold">{leak.title}</h3>
                        <p className="text-sm text-muted-foreground">
                          {leak.description}
                        </p>
                      </div>
                    </div>
                    <Badge>{sev}</Badge>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground">RECORDS</p>
                      <p className="font-mono font-bold">
                        {leak.recordCount.toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">SOURCE</p>
                      <p className="font-mono">{leak.source}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">DATE</p>
                      <p className="font-mono">
                        {new Date(leak.leakDate).toLocaleDateString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground">ENTITIES</p>
                      <p className="font-mono">
                        {leak.affectedEntities.length}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}

          {!loading && leaks.length === 0 && (
            <Card>
              <CardContent className="p-12 text-center">
                <Globe className="h-12 w-12 mx-auto text-muted-foreground/40 mb-4" />
                <p className="text-muted-foreground">
                  No search results
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Recent Leaks */}
        <TabsContent value="recent" className="mt-4 space-y-3">
          {recentLeaks.map(leak => (
            <Card key={leak.id}>
              <CardContent className="p-4">
                <h3 className="font-semibold">{leak.title}</h3>
                <p className="text-sm text-muted-foreground">
                  {leak.description}
                </p>
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>

      {/* Data Sources */}
      <Card className="border-primary/40 bg-primary/5">
        <CardContent className="p-4 flex gap-3">
          <Database className="h-5 w-5 text-primary" />
          <div>
            <h3 className="font-semibold">Data Sources</h3>
            <p className="text-sm text-muted-foreground">
              Dark Web Forums • Paste Sites • Breach Databases •
              Have I Been Pwned • Leak-Lookup • Intelligence X
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
