import { useState, useEffect } from 'react';
import { Activity, AlertTriangle, Globe, Hash, Link as LinkIcon, Mail, RefreshCw, Shield, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { getIPGeolocation } from '@/services/ipService';

export interface ThreatFeed {
  id: string;
  indicator: string;
  indicatorType: 'ip';
  type: 'malware' | 'phishing' | 'botnet' | 'c2';
  threat: string;
  confidence: number;
  source: string;
  tags: string[];
  firstSeen: string;
}

interface ThreatMapData {
  lat: number;
  lon: number;
  threat: string;
  count: number;
}

export function LiveThreatFeed() {
  const [loading, setLoading] = useState(false);
  const [feeds, setFeeds] = useState<ThreatFeed[]>([]);
  const [malware, setMalware] = useState<ThreatFeed[]>([]);
  const [mapData, setMapData] = useState<ThreatMapData[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [selectedType, setSelectedType] =
    useState<'all' | 'malware' | 'phishing' | 'botnet' | 'c2'>('all');

  useEffect(() => {
    loadThreats();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const interval = setInterval(loadThreats, 60000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  async function loadThreats() {
    setLoading(true);
    try {
      const feeds: ThreatFeed[] = [];

      /* ===============================
         Emerging Threats – Botnets
      =============================== */
      const emerging = await fetch(
        'https://rules.emergingthreats.net/blockrules/compromised-ips.txt'
      ).then(r => r.text());

      emerging.split('\n').forEach((line, i) => {
        const ip = line.trim();
        if (!ip || ip.startsWith('#')) return;

        feeds.push({
          id: `et-${i}`,
          indicator: ip,
          indicatorType: 'ip',
          type: 'botnet',
          threat: 'Compromised Host',
          confidence: 90,
          source: 'EmergingThreats',
          tags: ['botnet', 'public'],
          firstSeen: new Date().toISOString()
        });
      });

      /* ===============================
         Feodo Tracker – C2 Servers
      =============================== */
      const feodo = await fetch(
        'https://feodotracker.abuse.ch/downloads/ipblocklist.json'
      ).then(r => r.json());

      feodo.forEach((entry: any, i: number) => {
        feeds.push({
          id: `feodo-${i}`,
          indicator: entry.ip_address,
          indicatorType: 'ip',
          type: 'c2',
          threat: entry.malware || 'C2 Server',
          confidence: 95,
          source: 'FeodoTracker',
          tags: ['c2', 'malware'],
          firstSeen: entry.first_seen || new Date().toISOString()
        });
      });

      setFeeds(feeds);
      setMalware(feeds.filter(f => f.type === 'malware'));
      setLastUpdate(new Date());

      await buildMapData(feeds);

      toast.success('Threat data refreshed');
    } catch (e) {
      toast.error('Failed to load threat feeds');
    } finally {
      setLoading(false);
    }
  }

  async function buildMapData(feedData: ThreatFeed[]) {
    const ipFeeds = feedData.filter(f => f.indicatorType === 'ip').slice(0, 50);

    const geoResults = await Promise.all(
      ipFeeds.map(async feed => {
        const geo = await getIPGeolocation(feed.indicator);
        if (!geo) return null;
        return { lat: geo.lat, lon: geo.lon, threat: feed.threat };
      })
    );

    const aggregated: ThreatMapData[] = [];

    geoResults.filter(Boolean).forEach((p: any) => {
      const existing = aggregated.find(
        e => Math.abs(e.lat - p.lat) < 0.5 && Math.abs(e.lon - p.lon) < 0.5
      );
      if (existing) {
        existing.count++;
      } else {
        aggregated.push({ ...p, count: 1 });
      }
    });

    setMapData(aggregated);
  }

  const filteredFeeds =
    feeds.filter(f => selectedType === 'all' || f.type === selectedType);

  const stats = {
    total: feeds.length,
    critical: feeds.filter(f => f.confidence >= 90).length,
    malware: feeds.filter(f => f.type === 'malware').length,
    phishing: feeds.filter(f => f.type === 'phishing').length,
    botnet: feeds.filter(f => f.type === 'botnet').length
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Live Threat Intelligence</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Real-time threat feeds and malware tracking
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={autoRefresh ? 'border-primary' : ''}
          >
            <Activity className={cn('h-4 w-4 mr-2', autoRefresh && 'animate-pulse')} />
            Auto Refresh
          </Button>
          <Button onClick={loadThreats} disabled={loading} size="sm">
            <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
      </div>

      {lastUpdate && (
        <div className="text-xs text-muted-foreground text-center">
          Last updated: {lastUpdate.toLocaleTimeString()}
        </div>
      )}

      {/* Map */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary" />
            Global Threat Map
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ThreatMap data={mapData} />
        </CardContent>
      </Card>

      {/* Feeds */}
      <Tabs defaultValue="feeds">
        <TabsList className="bg-secondary/50 border border-border">
          <TabsTrigger value="feeds">
            <Shield className="h-4 w-4 mr-2" />
            Threat Feeds
          </TabsTrigger>
        </TabsList>

        <TabsContent value="feeds" className="mt-4">
          <div className="space-y-3">
            {filteredFeeds.map(feed => (
              <ThreatFeedCard key={feed.id} feed={feed} />
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ===============================
   Cards + Map (UNCHANGED)
=============================== */

function ThreatFeedCard({ feed }: { feed: ThreatFeed }) {
  const getTypeColor = (type: string) => {
    switch (type) {
      case 'botnet': return 'bg-purple-500/20 text-purple-500 border-purple-500/50';
      case 'c2': return 'bg-orange-500/20 text-orange-500 border-orange-500/50';
      default: return 'bg-gray-500/20 text-gray-500 border-gray-500/50';
    }
  };

  return (
    <Card className="bg-card border">
      <CardContent className="p-4">
        <div className="flex justify-between mb-2">
          <h3 className="font-semibold">{feed.threat}</h3>
          <Badge className={getTypeColor(feed.type)}>{feed.type}</Badge>
        </div>
        <code className="text-xs font-mono">{feed.indicator}</code>
      </CardContent>
    </Card>
  );
}

function ThreatMap({ data }: { data: ThreatMapData[] }) {
  const mapWidth = 800;
  const mapHeight = 400;

  const latToY = (lat: number) => ((90 - lat) / 180) * mapHeight;
  const lonToX = (lon: number) => ((lon + 180) / 360) * mapWidth;

  return (
    <svg viewBox={`0 0 ${mapWidth} ${mapHeight}`} className="w-full h-[400px]">
      {data.map((p, i) => (
        <circle
          key={i}
          cx={lonToX(p.lon)}
          cy={latToY(p.lat)}
          r={Math.min(4 + p.count * 2, 15)}
          fill="red"
        />
      ))}
    </svg>
  );
}
