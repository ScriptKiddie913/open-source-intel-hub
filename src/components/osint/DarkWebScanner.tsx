// src/components/osint/DarkWebScanner.tsx
import { useState, useEffect } from 'react';
import { Shield, Search, Loader2, AlertTriangle, Globe, Database, Lock, Eye } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { scanDarkWebLeaks, DarkWebLeak } from '@/services/enhancedThreatService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function DarkWebScanner() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [leaks, setLeaks] = useState<DarkWebLeak[]>([]);
  const [recentLeaks, setRecentLeaks] = useState<DarkWebLeak[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  useEffect(() => {
    loadRecentLeaks();
  }, []);

  const loadRecentLeaks = async () => {
    try {
      const recent = await scanDarkWebLeaks();
      setRecentLeaks(recent);
    } catch (error) {
      console.error('Failed to load recent leaks:', error);
    }
  };

  const handleSearch = async () => {
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
        toast.info('No dark web leaks found for this query');
      } else {
        toast.success(`Found ${results.length} potential leaks`);
      }
    } catch (error) {
      toast.error('Dark web scan failed');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500';
      case 'high': return 'text-orange-500';
      case 'medium': return 'text-yellow-500';
      case 'low': return 'text-blue-500';
      default: return 'text-muted-foreground';
    }
  };

  const getSeverityBg = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/20 border-red-500';
      case 'high': return 'bg-orange-500/20 border-orange-500';
      case 'medium': return 'bg-yellow-500/20 border-yellow-500';
      case 'low': return 'bg-blue-500/20 border-blue-500';
      default: return 'bg-muted border-border';
    }
  };

  const filteredLeaks = filterSeverity === 'all' 
    ? leaks 
    : leaks.filter(l => l.severity === filterSeverity);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Lock className="h-7 w-7 text-primary" />
          Dark Web & Data Leak Monitor
        </h1>
        <p className="text-muted-foreground text-sm mt-1">
          Monitor dark web forums, marketplaces, and paste sites for data leaks
        </p>
      </div>

      {/* Warning Banner */}
      <Card className="bg-destructive/10 border-destructive/30">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive mt-0.5" />
            <div>
              <h3 className="font-semibold text-destructive">Ethical Use Only</h3>
              <p className="text-sm text-muted-foreground mt-1">
                This tool is for legitimate threat intelligence and security research. 
                Unauthorized access to dark web content or leaked data may be illegal.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Search */}
      <Card className="bg-card border-border">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Search by email, domain, or keyword..."
                className="pl-10 bg-background"
              />
            </div>
            <Button onClick={handleSearch} disabled={loading} className="min-w-[120px]">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Eye className="h-4 w-4 mr-2" />
                  Scan
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="search" className="w-full">
        <TabsList className="bg-secondary/50 border border-border">
          <TabsTrigger value="search" className="flex items-center gap-2">
            <Search className="h-4 w-4" />
            Search Results
          </TabsTrigger>
          <TabsTrigger value="recent" className="flex items-center gap-2">
            <Database className="h-4 w-4" />
            Recent Leaks
          </TabsTrigger>
        </TabsList>

        {/* Search Results */}
        <TabsContent value="search" className="mt-4">
          {leaks.length > 0 && (
            <>
              {/* Filter */}
              <div className="flex flex-wrap gap-2 mb-4">
                {['all', 'critical', 'high', 'medium', 'low'].map((severity) => (
                  <Button
                    key={severity}
                    variant={filterSeverity === severity ? 'default' : 'outline'}
                    size="sm"
                    onClick={() => setFilterSeverity(severity)}
                  >
                    {severity.charAt(0).toUpperCase() + severity.slice(1)}
                  </Button>
                ))}
              </div>

              {/* Leak Cards */}
              <div className="space-y-3">
                {filteredLeaks.map((leak) => (
                  <Card key={leak.id} className={cn('border', getSeverityBg(leak.severity))}>
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-start gap-3">
                          <div className={cn('p-2 rounded-lg', getSeverityBg(leak.severity))}>
                            <Shield className={cn('h-5 w-5', getSeverityColor(leak.severity))} />
                          </div>
                          <div>
                            <h3 className="font-semibold text-foreground">{leak.title}</h3>
                            <p className="text-sm text-muted-foreground mt-1">{leak.description}</p>
                          </div>
                        </div>
                        <Badge className={getSeverityColor(leak.severity)}>
                          {leak.severity}
                        </Badge>
                      </div>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-3">
                        <div>
                          <p className="text-xs text-muted-foreground uppercase">Records</p>
                          <p className="font-mono font-bold text-foreground">
                            {leak.recordCount.toLocaleString()}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground uppercase">Source</p>
                          <p className="font-mono text-sm text-foreground">{leak.source}</p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground uppercase">Leak Date</p>
                          <p className="font-mono text-sm text-foreground">
                            {new Date(leak.leakDate).toLocaleDateString()}
                          </p>
                        </div>
                        <div>
                          <p className="text-xs text-muted-foreground uppercase">Entities</p>
                          <p className="font-mono text-sm text-foreground">
                            {leak.affectedEntities.length}
                          </p>
                        </div>
                      </div>

                      <div className="space-y-2">
                        <div>
                          <p className="text-xs text-muted-foreground uppercase mb-1">Data Types</p>
                          <div className="flex flex-wrap gap-2">
                            {leak.dataTypes.map((type, i) => (
                              <Badge key={i} variant="outline" className="text-xs">
                                {type}
                              </Badge>
                            ))}
                          </div>
                        </div>
                        {leak.affectedEntities.length > 0 && (
                          <div>
                            <p className="text-xs text-muted-foreground uppercase mb-1">
                              Affected Entities
                            </p>
                            <div className="flex flex-wrap gap-2">
                              {leak.affectedEntities.map((entity, i) => (
                                <Badge key={i} variant="secondary" className="text-xs">
                                  {entity}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </>
          )}

          {!loading && leaks.length === 0 && (
            <Card className="bg-card border-border">
              <CardContent className="p-12 text-center">
                <Globe className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                <p className="text-muted-foreground mb-2">No search results</p>
                <p className="text-xs text-muted-foreground/60">
                  Enter an email, domain, or keyword to scan for leaks
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Recent Leaks */}
        <TabsContent value="recent" className="mt-4">
          <div className="space-y-3">
            {recentLeaks.map((leak) => (
              <Card key={leak.id} className={cn('border', getSeverityBg(leak.severity))}>
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-start gap-3">
                      <div className={cn('p-2 rounded-lg', getSeverityBg(leak.severity))}>
                        <Shield className={cn('h-5 w-5', getSeverityColor(leak.severity))} />
                      </div>
                      <div>
                        <h3 className="font-semibold text-foreground">{leak.title}</h3>
                        <p className="text-sm text-muted-foreground mt-1">{leak.description}</p>
                      </div>
                    </div>
                    <Badge className={getSeverityColor(leak.severity)}>
                      {leak.severity}
                    </Badge>
                  </div>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Records</p>
                      <p className="font-mono font-bold text-foreground">
                        {leak.recordCount.toLocaleString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Source</p>
                      <p className="font-mono text-sm text-foreground">{leak.source}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Leak Date</p>
                      <p className="font-mono text-sm text-foreground">
                        {new Date(leak.leakDate).toLocaleDateString()}
                      </p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground uppercase">Data Types</p>
                      <p className="font-mono text-sm text-foreground">
                        {leak.dataTypes.length}
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Info Card */}
      <Card className="bg-primary/5 border-primary/30">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Database className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <h3 className="font-semibold text-foreground">Data Sources</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Monitoring: Dark Web Forums • Paste Sites • Data Brokers • Breach Databases • 
                Have I Been Pwned • Leak-Lookup • Intelligence X
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
