import { useState, useEffect } from 'react';
import { Activity, AlertTriangle, Globe, Hash, Link as LinkIcon, Mail, RefreshCw, Shield, Zap } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { getLiveThreatFeeds, getMalwareHashes, ThreatFeed } from '@/services/cveService';
import { getIPGeolocation } from '@/services/ipService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

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
  const [selectedType, setSelectedType] = useState<'all' | 'malware' | 'phishing' | 'botnet' | 'c2'>('all');

  useEffect(() => {
    loadThreats();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(() => {
        loadThreats();
      }, 60000); // Refresh every minute

      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const [feedData, malwareData] = await Promise.all([
        getLiveThreatFeeds(),
        getMalwareHashes(30),
      ]);

      setFeeds(feedData);
      setMalware(malwareData);
      setLastUpdate(new Date());
      
      // Build map data from IP indicators
      await buildMapData(feedData);
      
      toast.success('Threat data refreshed');
    } catch (error) {
      toast.error('Failed to load threat feeds');
    } finally {
      setLoading(false);
    }
  };

  const buildMapData = async (feedData: ThreatFeed[]) => {
    const ipFeeds = feedData.filter(f => f.indicatorType === 'ip');
    const mapPoints: ThreatMapData[] = [];
    const locationCache = new Map<string, { lat: number; lon: number }>();

    for (const feed of ipFeeds.slice(0, 50)) {
      try {
        let location = locationCache.get(feed.indicator);
        
        if (!location) {
          const geo = await getIPGeolocation(feed.indicator);
          if (geo) {
            location = { lat: geo.lat, lon: geo.lon };
            locationCache.set(feed.indicator, location);
          }
        }

        if (location) {
          const existing = mapPoints.find(
            p => Math.abs(p.lat - location!.lat) < 0.5 && Math.abs(p.lon - location!.lon) < 0.5
          );

          if (existing) {
            existing.count++;
          } else {
            mapPoints.push({
              lat: location.lat,
              lon: location.lon,
              threat: feed.threat,
              count: 1,
            });
          }
        }
      } catch (error) {
        // Skip if geolocation fails
      }
    }

    setMapData(mapPoints);
  };

  const filteredFeeds = feeds.filter(f => selectedType === 'all' || f.type === selectedType);

  const stats = {
    total: feeds.length + malware.length,
    critical: feeds.filter(f => f.confidence >= 90).length,
    malware: malware.length,
    phishing: feeds.filter(f => f.type === 'phishing').length,
    botnet: feeds.filter(f => f.type === 'botnet').length,
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

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-primary font-mono">{stats.total}</div>
            <div className="text-xs text-muted-foreground">Total Threats</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-red-500 font-mono">{stats.critical}</div>
            <div className="text-xs text-muted-foreground">High Confidence</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-orange-500 font-mono">{stats.malware}</div>
            <div className="text-xs text-muted-foreground">Malware Samples</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-yellow-500 font-mono">{stats.phishing}</div>
            <div className="text-xs text-muted-foreground">Phishing URLs</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-bold text-purple-500 font-mono">{stats.botnet}</div>
            <div className="text-xs text-muted-foreground">Botnet C2s</div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Map */}
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

      {/* Threat Feed Tabs */}
      <Tabs defaultValue="feeds">
        <TabsList className="bg-secondary/50 border border-border">
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
          {/* Filter Buttons */}
          <div className="flex flex-wrap gap-2 mb-4">
            {(['all', 'malware', 'phishing', 'botnet', 'c2'] as const).map((type) => (
              <Button
                key={type}
                variant={selectedType === type ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedType(type)}
              >
                {type === 'all' ? 'All' : type.charAt(0).toUpperCase() + type.slice(1)}
              </Button>
            ))}
          </div>

          <div className="space-y-3">
            {filteredFeeds.map((feed) => (
              <ThreatFeedCard key={feed.id} feed={feed} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="malware" className="mt-4">
          <div className="space-y-3">
            {malware.map((sample) => (
              <MalwareCard key={sample.id} sample={sample} />
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function ThreatFeedCard({ feed }: { feed: ThreatFeed }) {
  const getTypeColor = (type: string) => {
    switch (type) {
      case 'malware': return 'bg-red-500/20 text-red-500 border-red-500/50';
      case 'phishing': return 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50';
      case 'botnet': return 'bg-purple-500/20 text-purple-500 border-purple-500/50';
      case 'c2': return 'bg-orange-500/20 text-orange-500 border-orange-500/50';
      case 'exploit': return 'bg-pink-500/20 text-pink-500 border-pink-500/50';
      default: return 'bg-gray-500/20 text-gray-500 border-gray-500/50';
    }
  };

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
    <Card className="bg-card border hover:border-primary/50 transition-all">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className={cn('p-2 rounded-lg', getTypeColor(feed.type))}>
              {getIcon(feed.indicatorType)}
            </div>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <h3 className="font-semibold text-foreground">{feed.threat}</h3>
                <Badge variant="outline" className="text-xs">
                  {feed.confidence}% confidence
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground">
                Source: {feed.source}
              </p>
            </div>
          </div>
          <Badge className={getTypeColor(feed.type)}>{feed.type}</Badge>
        </div>

        <div className="p-3 rounded-lg bg-secondary/50 mb-3">
          <code className="text-xs font-mono break-all">{feed.indicator}</code>
        </div>

        <div className="flex items-center justify-between text-xs text-muted-foreground">
          <div className="flex gap-2">
            {feed.tags.map((tag, i) => (
              <Badge key={i} variant="secondary" className="text-xs">
                {tag}
              </Badge>
            ))}
          </div>
          <div>
            First seen: {new Date(feed.firstSeen).toLocaleDateString()}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function MalwareCard({ sample }: { sample: ThreatFeed }) {
  return (
    <Card className="bg-card border hover:border-primary/50 transition-all">
      <CardContent className="p-4">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/20">
              <AlertTriangle className="h-5 w-5 text-red-500" />
            </div>
            <div>
              <h3 className="font-semibold text-foreground">{sample.threat}</h3>
              <p className="text-xs text-muted-foreground">
                Source: {sample.source}
              </p>
            </div>
          </div>
          <Badge variant="destructive">Malware</Badge>
        </div>

        <div className="p-3 rounded-lg bg-secondary/50 mb-3">
          <div className="text-xs text-muted-foreground mb-1">SHA256</div>
          <code className="text-xs font-mono break-all">{sample.indicator}</code>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex flex-wrap gap-2">
            {sample.tags.slice(0, 5).map((tag, i) => (
              <Badge key={i} variant="outline" className="text-xs">
                {tag}
              </Badge>
            ))}
          </div>
          <div className="text-xs text-muted-foreground">
            {new Date(sample.firstSeen).toLocaleDateString()}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function ThreatMap({ data }: { data: ThreatMapData[] }) {
  const [hoveredPoint, setHoveredPoint] = useState<ThreatMapData | null>(null);

  // Simple SVG world map visualization
  const mapWidth = 800;
  const mapHeight = 400;

  const latToY = (lat: number) => {
    return ((90 - lat) / 180) * mapHeight;
  };

  const lonToX = (lon: number) => {
    return ((lon + 180) / 360) * mapWidth;
  };

  return (
    <div className="relative bg-secondary/20 rounded-lg overflow-hidden">
      <svg 
        viewBox={`0 0 ${mapWidth} ${mapHeight}`} 
        className="w-full h-[400px]"
        style={{ background: 'linear-gradient(180deg, #0a0e27 0%, #1a1f3a 100%)' }}
      >
        {/* Grid lines */}
        <g opacity="0.1" stroke="currentColor" strokeWidth="0.5">
          {Array.from({ length: 18 }).map((_, i) => (
            <line
              key={`h-${i}`}
              x1="0"
              y1={i * (mapHeight / 18)}
              x2={mapWidth}
              y2={i * (mapHeight / 18)}
            />
          ))}
          {Array.from({ length: 36 }).map((_, i) => (
            <line
              key={`v-${i}`}
              x1={i * (mapWidth / 36)}
              y1="0"
              x2={i * (mapWidth / 36)}
              y2={mapHeight}
            />
          ))}
        </g>

        {/* Threat points */}
        {data.map((point, i) => {
          const x = lonToX(point.lon);
          const y = latToY(point.lat);
          const radius = Math.min(3 + point.count * 2, 15);
          
          return (
            <g key={i}>
              {/* Glow effect */}
              <circle
                cx={x}
                cy={y}
                r={radius + 5}
                fill="rgba(239, 68, 68, 0.2)"
                className="animate-pulse"
              />
              {/* Main point */}
              <circle
                cx={x}
                cy={y}
                r={radius}
                fill="rgb(239, 68, 68)"
                className="cursor-pointer hover:fill-red-400 transition-colors"
                onMouseEnter={() => setHoveredPoint(point)}
                onMouseLeave={() => setHoveredPoint(null)}
              />
              {/* Count label */}
              {point.count > 1 && (
                <text
                  x={x}
                  y={y}
                  textAnchor="middle"
                  dominantBaseline="central"
                  className="text-xs font-bold fill-white pointer-events-none"
                >
                  {point.count}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Tooltip */}
      {hoveredPoint && (
        <div className="absolute top-4 right-4 bg-card border border-border rounded-lg p-3 shadow-lg">
          <div className="text-sm font-semibold text-foreground">{hoveredPoint.threat}</div>
          <div className="text-xs text-muted-foreground">
            Threats: {hoveredPoint.count}
          </div>
          <div className="text-xs text-muted-foreground">
            {hoveredPoint.lat.toFixed(2)}°, {hoveredPoint.lon.toFixed(2)}°
          </div>
        </div>
      )}

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-card/90 border border-border rounded-lg p-3">
        <div className="text-xs font-semibold text-foreground mb-2">Threat Density</div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <div className="w-3 h-3 rounded-full bg-red-500" />
          <span>Active Threats</span>
        </div>
      </div>
    </div>
  );
}
