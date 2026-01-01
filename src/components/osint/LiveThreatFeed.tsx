// src/components/osint/LiveThreatFeed.tsx
// REAL-TIME THREAT INTELLIGENCE VISUALIZATION
// Integrates APTmap, MISP feeds, and LLM processing

import { useState, useEffect, useRef } from 'react';
import { Activity, RefreshCw, Globe, Zap, AlertTriangle, MapPin, Target, Shield, Users } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { fetchLiveThreatMap, ThreatPoint } from '@/services/realTimeThreatService';
import { getAPTThreatMapData, fetchAPTMapData, getAPTStats, type APTThreatPoint } from '@/services/aptMapService';
import { fetchAllThreatFeeds, getMalwareThreatMapData, type ThreatFeedSummary, type MalwareThreatPoint } from '@/services/mispFeedService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

type CombinedThreatPoint = ThreatPoint | APTThreatPoint | MalwareThreatPoint;

export function LiveThreatFeed() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [aptThreats, setAptThreats] = useState<APTThreatPoint[]>([]);
  const [malwareThreats, setMalwareThreats] = useState<MalwareThreatPoint[]>([]);
  const [feedSummary, setFeedSummary] = useState<ThreatFeedSummary | null>(null);
  const [aptStats, setAptStats] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [hoveredThreat, setHoveredThreat] = useState<CombinedThreatPoint | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const [activeView, setActiveView] = useState<'all' | 'apt' | 'malware' | 'c2'>('all');

  useEffect(() => {
    loadAllThreats();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(loadAllThreats, 300000); // 5 minutes
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  useEffect(() => {
    drawMap();
  }, [threats, aptThreats, malwareThreats, hoveredThreat, activeView]);

  const loadAllThreats = async () => {
    setLoading(true);
    try {
      // Fetch all data sources in parallel
      const [c2Data, aptData, mispData, aptStatsData] = await Promise.all([
        fetchLiveThreatMap(),
        getAPTThreatMapData(),
        fetchAllThreatFeeds(),
        getAPTStats(),
      ]);
      
      const malwareMapData = await getMalwareThreatMapData();
      
      setThreats(c2Data);
      setAptThreats(aptData);
      setMalwareThreats(malwareMapData);
      setFeedSummary(mispData);
      setAptStats(aptStatsData);
      setLastUpdate(new Date());
      
      const totalIndicators = c2Data.length + aptData.length + malwareMapData.length;
      toast.success(`Loaded ${totalIndicators} live threat indicators from APTmap, MISP feeds`);
    } catch (error) {
      console.error('Failed to load threats:', error);
      toast.error('Failed to load live threat data');
    } finally {
      setLoading(false);
    }
  };

  const loadThreats = loadAllThreats;

  const drawMap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    // Dark background with grid
    ctx.fillStyle = '#0a0e27';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw world map outline (simplified)
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.1)';
    ctx.lineWidth = 1;
    
    // Grid lines
    for (let i = 0; i < 18; i++) {
      ctx.beginPath();
      ctx.moveTo(0, i * (canvas.height / 18));
      ctx.lineTo(canvas.width, i * (canvas.height / 18));
      ctx.stroke();
    }
    for (let i = 0; i < 36; i++) {
      ctx.beginPath();
      ctx.moveTo(i * (canvas.width / 36), 0);
      ctx.lineTo(i * (canvas.width / 36), canvas.height);
      ctx.stroke();
    }

    // Convert lat/lon to canvas coordinates
    const latToY = (lat: number) => ((90 - lat) / 180) * canvas.height;
    const lonToX = (lon: number) => ((lon + 180) / 360) * canvas.width;

    const severityColors = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#3b82f6',
    };

    // Determine which points to draw based on active view
    const drawThreatPoint = (threat: CombinedThreatPoint, type: 'apt' | 'c2' | 'malware') => {
      const x = lonToX(threat.lon);
      const y = latToY(threat.lat);
      const radius = Math.min(5 + (threat.count || 1) * 2, 25);
      const color = severityColors[threat.severity];

      // Glow effect
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius + 10);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, radius + 10, 0, Math.PI * 2);
      ctx.fill();

      // Different shapes for different types
      ctx.fillStyle = color;
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;

      if (type === 'apt') {
        // Triangle for APT groups
        ctx.beginPath();
        ctx.moveTo(x, y - radius);
        ctx.lineTo(x + radius, y + radius);
        ctx.lineTo(x - radius, y + radius);
        ctx.closePath();
        ctx.fill();
        ctx.stroke();
      } else if (type === 'malware') {
        // Square for malware
        ctx.fillRect(x - radius/2, y - radius/2, radius, radius);
        ctx.strokeRect(x - radius/2, y - radius/2, radius, radius);
      } else {
        // Circle for C2
        ctx.beginPath();
        ctx.arc(x, y, radius, 0, Math.PI * 2);
        ctx.fill();
        ctx.stroke();
      }

      // Pulse for critical
      if (threat.severity === 'critical') {
        const time = Date.now() / 1000;
        const pulseRadius = radius + Math.sin(time * 3) * 5;
        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.globalAlpha = 0.5 + Math.sin(time * 3) * 0.5;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Count label
      if ((threat.count || 0) > 1) {
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 11px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(threat.count?.toString() || '', x, y);
      }

      // Highlight on hover
      if (hoveredThreat?.id === threat.id) {
        ctx.strokeStyle = '#00FF9F';
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.arc(x, y, radius + 15, 0, Math.PI * 2);
        ctx.stroke();
      }
    };

    // Draw based on active view
    if (activeView === 'all' || activeView === 'apt') {
      aptThreats.forEach((threat) => drawThreatPoint(threat, 'apt'));
    }
    if (activeView === 'all' || activeView === 'c2') {
      threats.forEach((threat) => drawThreatPoint(threat, 'c2'));
    }
    if (activeView === 'all' || activeView === 'malware') {
      malwareThreats.forEach((threat) => drawThreatPoint(threat, 'malware'));
    }
  };

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const lonToX = (lon: number) => ((lon + 180) / 360) * canvas.width;
    const latToY = (lat: number) => ((90 - lat) / 180) * canvas.height;

    // Check all threat types
    const allPoints: CombinedThreatPoint[] = [...threats, ...aptThreats, ...malwareThreats];
    
    const clicked = allPoints.find((threat) => {
      const tx = lonToX(threat.lon);
      const ty = latToY(threat.lat);
      const distance = Math.sqrt((x - tx) ** 2 + (y - ty) ** 2);
      const radius = Math.min(5 + (threat.count || 1) * 2, 25);
      return distance <= radius + 15;
    });

    setHoveredThreat(clicked || null);
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (rect) {
      setMousePos({
        x: e.clientX - rect.left,
        y: e.clientY - rect.top,
      });
    }
  };

  const stats = {
    total: threats.length + aptThreats.length + malwareThreats.length,
    critical: [...threats, ...aptThreats, ...malwareThreats].filter(t => t.severity === 'critical').length,
    high: [...threats, ...aptThreats, ...malwareThreats].filter(t => t.severity === 'high').length,
    aptGroups: aptStats?.totalGroups || aptThreats.length,
    countries: new Set([...threats, ...aptThreats, ...malwareThreats].map(t => t.country)).size,
    indicators: feedSummary?.stats.totalIndicators || 0,
    malwareFamilies: feedSummary?.stats.malwareFamilies.length || 0,
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
          <Globe className="h-7 w-7 text-primary" />
          Live Threat Intelligence Map
        </h1>
        <p className="text-muted-foreground text-sm mt-1">
          Real-time global threat visualization from APTmap, MISP, Feodo, URLhaus, ThreatFox
        </p>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={autoRefresh ? 'border-primary' : ''}
          >
            <Activity className={cn('h-4 w-4 mr-2', autoRefresh && 'animate-pulse text-primary')} />
            Auto Refresh
          </Button>
          <Button onClick={loadThreats} disabled={loading} size="sm">
            <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
        
        {/* View Filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">Filter:</span>
          {(['all', 'apt', 'c2', 'malware'] as const).map((view) => (
            <Button
              key={view}
              variant={activeView === view ? 'default' : 'outline'}
              size="sm"
              onClick={() => setActiveView(view)}
              className="capitalize"
            >
              {view === 'apt' ? 'APT Groups' : view === 'c2' ? 'C2 Servers' : view}
            </Button>
          ))}
        </div>
        
        {lastUpdate && (
          <div className="text-xs text-muted-foreground font-mono">
            Updated: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        {[
          { label: 'Total Threats', value: stats.total, color: 'text-primary', icon: Target },
          { label: 'Critical', value: stats.critical, color: 'text-red-500', icon: AlertTriangle },
          { label: 'High', value: stats.high, color: 'text-orange-500', icon: Shield },
          { label: 'APT Groups', value: stats.aptGroups, color: 'text-purple-500', icon: Users },
          { label: 'Indicators', value: stats.indicators, color: 'text-cyan-500', icon: Activity },
          { label: 'Malware Families', value: stats.malwareFamilies, color: 'text-yellow-500', icon: Zap },
          { label: 'Countries', value: stats.countries, color: 'text-green-500', icon: MapPin },
        ].map((stat) => (
          <Card key={stat.label} className="bg-card border-border">
            <CardContent className="p-3 text-center">
              <stat.icon className={cn('h-4 w-4 mx-auto mb-1', stat.color)} />
              <div className={cn('text-xl font-bold font-mono', stat.color)}>{stat.value}</div>
              <div className="text-xs text-muted-foreground">{stat.label}</div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Map */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-foreground">
            <MapPin className="h-5 w-5 text-primary" />
            Global Threat Distribution
          </CardTitle>
        </CardHeader>
        <CardContent className="relative">
          <canvas
            ref={canvasRef}
            className="w-full h-[600px] rounded-lg cursor-pointer"
            onClick={handleCanvasClick}
            onMouseMove={handleMouseMove}
          />

          {/* Tooltip */}
          {hoveredThreat && (
            <div
              className="absolute bg-card/95 border border-border rounded-lg p-3 shadow-xl max-w-xs pointer-events-none z-10"
              style={{
                left: Math.min(mousePos.x + 10, (canvasRef.current?.width || 0) - 250),
                top: mousePos.y + 10,
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <Badge className={cn(
                  hoveredThreat.severity === 'critical' ? 'bg-red-500' :
                  hoveredThreat.severity === 'high' ? 'bg-orange-500' :
                  hoveredThreat.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                )}>
                  {hoveredThreat.severity.toUpperCase()}
                </Badge>
                <span className="text-sm font-semibold">
                  {'threatType' in hoveredThreat ? hoveredThreat.threatType : 
                   'aptName' in hoveredThreat ? hoveredThreat.aptName :
                   'malwareFamily' in hoveredThreat ? hoveredThreat.malwareFamily : 'Unknown'}
                </span>
              </div>
              <div className="space-y-1 text-xs">
                <div><strong>Location:</strong> {'city' in hoveredThreat ? `${hoveredThreat.city}, ` : ''}{hoveredThreat.country}</div>
                {'indicator' in hoveredThreat && (
                  <div><strong>Indicator:</strong> <code className="font-mono bg-secondary px-1 rounded">{hoveredThreat.indicator}</code></div>
                )}
                {'aptName' in hoveredThreat && (
                  <>
                    <div><strong>APT Group:</strong> {hoveredThreat.aptName}</div>
                    <div><strong>Aliases:</strong> {hoveredThreat.aliases?.slice(0, 3).join(', ')}</div>
                  </>
                )}
                {'malwareFamily' in hoveredThreat && (
                  <>
                    <div><strong>Malware:</strong> {hoveredThreat.malwareFamily}</div>
                    <div><strong>Type:</strong> {hoveredThreat.type}</div>
                  </>
                )}
                {'source' in hoveredThreat && <div><strong>Source:</strong> {hoveredThreat.source}</div>}
                <div><strong>Count:</strong> {hoveredThreat.count || 1}</div>
                {'timestamp' in hoveredThreat && (
                  <div className="text-muted-foreground">
                    {new Date(hoveredThreat.timestamp).toLocaleString()}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Legend */}
          <div className="absolute bottom-4 left-4 bg-card/90 border border-border rounded-lg p-3">
            <div className="text-xs font-semibold mb-2">Threat Severity</div>
            <div className="space-y-1 text-xs">
              {['critical', 'high', 'medium', 'low'].map((severity) => (
                <div key={severity} className="flex items-center gap-2">
                  <div className={cn(
                    'w-3 h-3 rounded-full',
                    severity === 'critical' ? 'bg-red-500' :
                    severity === 'high' ? 'bg-orange-500' :
                    severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                  )} />
                  <span className="capitalize">{severity}</span>
                </div>
              ))}
            </div>
            <div className="border-t border-border mt-2 pt-2">
              <div className="text-xs font-semibold mb-1">Threat Types</div>
              <div className="space-y-1 text-xs">
                <div className="flex items-center gap-2">
                  <div className="w-0 h-0 border-l-[5px] border-r-[5px] border-b-[8px] border-l-transparent border-r-transparent border-b-purple-500" />
                  <span>APT Groups</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full bg-cyan-500" />
                  <span>C2 Servers</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-3 h-3 bg-orange-500" />
                  <span>Malware</span>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Data Sources */}
      <Card className="bg-primary/5 border-primary/30">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Zap className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <h3 className="font-semibold text-foreground">Live Data Sources</h3>
              <p className="text-sm text-muted-foreground mt-1">
                <strong>APTmap:</strong> 100+ threat actor groups from MISP, MITRE ATT&CK, VX-Underground • 
                <strong>Feodo Tracker:</strong> Botnet C2 servers • 
                <strong>URLhaus:</strong> Malware distribution URLs • 
                <strong>ThreatFox:</strong> Recent IOCs • 
                <strong>MalwareBazaar:</strong> Malware samples
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Top Malware Families */}
      {feedSummary && feedSummary.stats.malwareFamilies.length > 0 && (
        <Card className="bg-card border-border">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-foreground text-lg">
              <Activity className="h-5 w-5 text-primary" />
              Top Active Malware Families
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-2">
              {feedSummary.stats.malwareFamilies.slice(0, 10).map((family, idx) => (
                <div key={family.name} className="flex items-center justify-between bg-secondary/50 rounded-lg p-2">
                  <span className="text-sm font-medium truncate">{family.name}</span>
                  <Badge variant="outline" className="ml-2">{family.count}</Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
