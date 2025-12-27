import { useState, useEffect } from 'react';
import {
  Activity,
  AlertTriangle,
  Globe,
  Hash,
  Link as LinkIcon,
  Mail,
  RefreshCw,
  Shield,
  Zap
} from 'lucide-react';
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
    if (!autoRefresh) return;
    const interval = setInterval(loadThreats, 60000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const feeds: ThreatFeed[] = [];
      const malwareSamples: ThreatFeed[] = [];

      /* ===============================
         IPsum – malicious IP activity
      =============================== */
      const ipsumText = await fetch(
        'https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt'
      ).then(r => r.text());

      ipsumText.split('\n').forEach((line, i) => {
        if (!line || line.startsWith('#')) return;
        const [ip] = line.split(/\s+/);
        if (!ip) return;

        feeds.push({
          id: `ipsum-${i}`,
          indicator: ip,
          indicatorType: 'ip',
          type: 'botnet',
          threat: 'Malicious IP Activity',
          confidence: 85,
          source: 'IPsum',
          tags: ['botnet', 'network'],
          firstSeen: new Date().toISOString()
        });
      });

      /* ===============================
         Spamhaus DROP mirror
      =============================== */
      const spamhausText = await fetch(
        'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/spamhaus_drop.netset'
      ).then(r => r.text());

      spamhausText.split('\n').forEach((line, i) => {
        if (!line || line.startsWith('#')) return;

        feeds.push({
          id: `spamhaus-${i}`,
          indicator: line.trim(),
          indicatorType: 'ip',
          type: 'c2',
          threat: 'High Risk Infrastructure',
          confidence: 95,
          source: 'Spamhaus',
          tags: ['c2', 'malware'],
          firstSeen: new Date().toISOString()
        });
      });

      /* ===============================
         MalwareBazaar – recent hashes
      =============================== */
      const bazaar = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'query=get_recent&selector=30'
      }).then(r => r.json());

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
    } catch (e) {
      toast.error('Failed to load threat feeds');
    } finally {
      setLoading(false);
    }
  };

  const buildMapData = async (feedData: ThreatFeed[]) => {
    const ipFeeds = feedData
      .filter(f => f.indicatorType === 'ip')
      .slice(0, 50);

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

    const points: ThreatMapData[] = [];

    geoResults.filter(Boolean).forEach((p: any) => {
      const existing = points.find(
        e =>
          Math.abs(e.lat - p.lat) < 0.5 &&
          Math.abs(e.lon - p.lon) < 0.5
      );

      if (existing) {
        existing.count++;
      } else {
        points.push({
          lat: p.lat,
          lon: p.lon,
          threat: p.threat,
          count: 1
        });
      }
    });

    setMapData(points);
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

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">
            Live Threat Intelligence
          </h1>
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
            <Activity
              className={cn(
                'h-4 w-4 mr-2',
                autoRefresh && 'animate-pulse'
              )}
            />
            Auto Refresh
          </Button>
          <Button onClick={loadThreats} disabled={loading} size="sm">
            <RefreshCw
              className={cn(
                'h-4 w-4 mr-2',
                loading && 'animate-spin'
              )}
            />
            Refresh
          </Button>
        </div>
      </div>

      {lastUpdate && (
        <div className="text-xs text-muted-foreground text-center">
          Last updated: {lastUpdate.toLocaleTimeString()}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <StatCard label="Total Threats" value={stats.total} color="text-primary" />
        <StatCard label="High Confidence" value={stats.critical} color="text-red-500" />
        <StatCard label="Malware Samples" value={stats.malware} color="text-orange-500" />
        <StatCard label="Phishing URLs" value={stats.phishing} color="text-yellow-500" />
        <StatCard label="Botnet C2s" value={stats.botnet} color="text-purple-500" />
      </div>

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

      <Tabs defaultValue="feeds">
        <TabsList>
          <TabsTrigger value="feeds">
            <Shield className="h-4 w-4 mr-2" />
            Threat Feeds
          </TabsTrigger>
          <TabsTrigger value="malware">
            <AlertTriangle className="h-4 w-4 mr-2" />
            Malware
          </TabsTrigger>
        </TabsList>

        <TabsContent value="feeds" className="mt-4">
          <div className="flex gap-2 mb-4 flex-wrap">
            {(['all', 'malware', 'phishing', 'botnet', 'c2'] as const).map(type => (
              <Button
                key={type}
                size="sm"
                variant={selectedType === type ? 'default' : 'outline'}
                onClick={() => setSelectedType(type)}
              >
                {type === 'all'
                  ? 'All'
                  : type.charAt(0).toUpperCase() + type.slice(1)}
              </Button>
            ))}
          </div>

          <div className="space-y-3">
            {filteredFeeds.map(feed => (
              <ThreatFeedCard key={feed.id} feed={feed} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="malware" className="mt-4">
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

function StatCard({ label, value, color }: any) {
  return (
    <Card>
      <CardContent className="p-4 text-center">
        <div className={`text-2xl font-bold font-mono ${color}`}>
          {value}
        </div>
        <div className="text-xs text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}

function ThreatFeedCard({ feed }: { feed: ThreatFeed }) {
  const getIcon = (type: string) => {
    switch (type) {
      case 'ip': return <Zap className="h-4 w-4" />;
      case 'domain': return <Globe className="h-4 w-4" />;
      case 'url': return <LinkIcon className="h-4 w-4" />;
      case 'hash': return <Hash className="h-4 w-4" />;
      case 'email': return <Mail className="h-4 w-4" />;
      default: return <AlertTriangle className="h-4 w-4" />;
    }
  };

  return (
    <Card>
      <CardContent className="p-4">
        <div className="flex gap-3 mb-2 items-center">
          {getIcon(feed.indicatorType)}
          <div className="font-semibold">{feed.threat}</div>
        </div>
        <code className="text-xs font-mono break-all">{feed.indicator}</code>
      </CardContent>
    </Card>
  );
}

function MalwareCard({ sample }: { sample: ThreatFeed }) {
  return (
    <Card>
      <CardContent className="p-4">
        <div className="font-semibold mb-1">{sample.threat}</div>
        <code className="text-xs font-mono break-all">{sample.indicator}</code>
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
    <svg
      viewBox={`0 0 ${mapWidth} ${mapHeight}`}
      className="w-full h-[400px]"
      style={{
        background: 'linear-gradient(180deg,#0a0e27 0%,#1a1f3a 100%)'
      }}
    >
      {data.map((p, i) => (
        <circle
          key={i}
          cx={lonToX(p.lon)}
          cy={latToY(p.lat)}
          r={Math.min(4 + p.count * 2, 15)}
          fill="rgb(239,68,68)"
        />
      ))}
    </svg>
  );
}
