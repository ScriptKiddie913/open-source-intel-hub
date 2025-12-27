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
  indicatorType: 'ip' | 'domain' | 'url' | 'hash' | 'email';
  type: 'malware' | 'phishing' | 'botnet' | 'c2' | 'exploit';
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
    if (autoRefresh) {
      const interval = setInterval(() => {
        loadThreats();
      }, 60000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const feeds: ThreatFeed[] = [];
      const malwareSamples: ThreatFeed[] = [];

      /* ===============================
         Emerging Threats – Botnet IPs
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

      /* ===============================
         MalwareBazaar – Malware Hashes
      =============================== */
      const bazaar = await fetch(
        'https://mb-api.abuse.ch/api/v1/',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: 'query=get_recent&selector=30'
        }
      ).then(r => r.json());

      if (bazaar?.data) {
        bazaar.data.forEach((entry: any, i: number) => {
          malwareSamples.push({
            id: `mb-${i}`,
            indicator: entry.sha256_hash,
            indicatorType: 'hash',
            type: 'malware',
            threat: entry.malware || 'Malware Sample',
            confidence: 95,
            source: 'MalwareBazaar',
            tags: entry.tags || [],
            firstSeen: entry.first_seen
          });
        });
      }

      setFeeds(feeds);
      setMalware(malwareSamples);
      setLastUpdate(new Date());

      await buildMapData(feeds);

      toast.success('Threat data refreshed');
    } catch (error) {
      toast.error('Failed to load threat feeds');
    } finally {
      setLoading(false);
    }
  };

  const buildMapData = async (feedData: ThreatFeed[]) => {
    const ipFeeds = feedData.filter(f => f.indicatorType === 'ip').slice(0, 50);

    const geoResults = await Promise.all(
      ipFeeds.map(async feed => {
        try {
          const geo = await getIPGeolocation(feed.indicator);
          if (!geo) return null;
          return { lat: geo.lat, lon: geo.lon, threat: feed.threat };
        } catch {
          return null;
        }
      })
    );

    const mapPoints: ThreatMapData[] = [];

    geoResults.filter(Boolean).forEach((point: any) => {
      const existing = mapPoints.find(
        p => Math.abs(p.lat - point.lat) < 0.5 &&
             Math.abs(p.lon - point.lon) < 0.5
      );

      if (existing) {
        existing.count++;
      } else {
        mapPoints.push({
          lat: point.lat,
          lon: point.lon,
          threat: point.threat,
          count: 1
        });
      }
    });

    setMapData(mapPoints);
  };

  const filteredFeeds =
    feeds.filter(f => selectedType === 'all' || f.type === selectedType);

  const stats = {
    total: feeds.length + malware.length,
    critical: feeds.filter(f => f.confidence >= 90).length,
    malware: malware.length,
    phishing: feeds.filter(f => f.type === 'phishing').length,
    botnet: feeds.filter(f => f.type === 'botnet').length
  };

  /* ===============================
     UI BELOW IS 100% UNCHANGED
  =============================== */

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

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card><CardContent className="p-4 text-center">
          <div className="text-2xl font-bold text-primary font-mono">{stats.total}</div>
          <div className="text-xs text-muted-foreground">Total Threats</div>
        </CardContent></Card>
        <Card><CardContent className="p-4 text-center">
          <div className="text-2xl font-bold text-red-500 font-mono">{stats.critical}</div>
          <div className="text-xs text-muted-foreground">High Confidence</div>
        </CardContent></Card>
        <Card><CardContent className="p-4 text-center">
          <div className="text-2xl font-bold text-orange-500 font-mono">{stats.malware}</div>
          <div className="text-xs text-muted-foreground">Malware Samples</div>
        </CardContent></Card>
        <Card><CardContent className="p-4 text-center">
          <div className="text-2xl font-bold text-yellow-500 font-mono">{stats.phishing}</div>
          <div className="text-xs text-muted-foreground">Phishing URLs</div>
        </CardContent></Card>
        <Card><CardContent className="p-4 text-center">
          <div className="text-2xl font-bold text-purple-500 font-mono">{stats.botnet}</div>
          <div className="text-xs text-muted-foreground">Botnet C2s</div>
        </CardContent></Card>
      </div>

      {/* Map */}
      <Card>
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

      {/* Tabs */}
      <Tabs defaultValue="feeds">
        <TabsList>
          <TabsTrigger value="feeds"><Shield className="h-4 w-4 mr-2" />Threat Feeds</TabsTrigger>
          <TabsTrigger value="malware"><AlertTriangle className="h-4 w-4 mr-2" />Malware</TabsTrigger>
        </TabsList>

        <TabsContent value="feeds">
          <div className="space-y-3">
            {filteredFeeds.map(feed => (
              <ThreatFeedCard key={feed.id} feed={feed} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="malware">
          <div className="space-y-3">
            {malware.map(sample => (
              <MalwareCard key={sample.id} sample={sample} />
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

/* ===============================
   REMAINDER UNCHANGED
=============================== */

function ThreatFeedCard({ feed }: { feed: ThreatFeed }) {
  const getIcon = (indicatorType: string) => {
    switch (indicatorType) {
      case 'ip': return <Zap className="h-4 w-4" />;
      case 'domain': return <Globe className="h-4 w-4" />;
      case 'url': return <LinkIcon className="h-4 w-4" />;
      case 'hash': return <Hash className="h-4 w-4" />;
      case 'email': return <Mail className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  return (
    <Card className="bg-card border">
      <CardContent className="p-4">
        <div className="flex items-center gap-3 mb-2">
          {getIcon(feed.indicatorType)}
          <div className="font-semibold">{feed.threat}</div>
        </div>
        <code className="text-xs font-mono">{feed.indicator}</code>
      </CardContent>
    </Card>
  );
}

function MalwareCard({ sample }: { sample: ThreatFeed }) {
  return (
    <Card className="bg-card border">
      <CardContent className="p-4">
        <div className="font-semibold mb-1">{sample.threat}</div>
        <code className="text-xs font-mono">{sample.indicator}</code>
      </CardContent>
    </Card>
  );
}

function ThreatMap({ data }: { data: ThreatMapData[] }) {
  const width = 800;
  const height = 400;
  const latToY = (lat: number) => ((90 - lat) / 180) * height;
  const lonToX = (lon: number) => ((lon + 180) / 360) * width;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-[400px]">
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

