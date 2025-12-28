// src/components/osint/EnhancedThreatMap.tsx
import { useState, useEffect, useRef } from 'react';
import { Activity, RefreshCw, Globe, Zap, AlertTriangle } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { getEnhancedLiveThreatMap, LiveThreatPoint } from '@/services/enhancedThreatService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function EnhancedThreatMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [threats, setThreats] = useState<LiveThreatPoint[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [hoveredThreat, setHoveredThreat] = useState<LiveThreatPoint | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);

  useEffect(() => {
    loadThreats();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(loadThreats, 60000); // 1 minute
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  useEffect(() => {
    drawMap();
  }, [threats, hoveredThreat]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const data = await getEnhancedLiveThreatMap();
      setThreats(data);
      setLastUpdate(new Date());
      
      if (data.length > 0) {
        toast.success(`Loaded ${data.length} threat indicators`);
      }
    } catch (error) {
      console.error('Failed to load threats:', error);
      toast.error('Failed to load threat data');
    } finally {
      setLoading(false);
    }
  };

  const drawMap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    // Dark background
    ctx.fillStyle = '#0a0e27';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw grid lines
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.05)';
    ctx.lineWidth = 1;
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
    const latToY = (lat: number) => {
      return ((90 - lat) / 180) * canvas.height;
    };

    const lonToX = (lon: number) => {
      return ((lon + 180) / 360) * canvas.width;
    };

    // Draw threat points
    threats.forEach((threat) => {
      const x = lonToX(threat.lon);
      const y = latToY(threat.lat);
      const radius = Math.min(5 + threat.count * 2, 20);

      // Severity colors
      const colors = {
        critical: 'rgb(239, 68, 68)',
        high: 'rgb(251, 146, 60)',
        medium: 'rgb(234, 179, 8)',
        low: 'rgb(59, 130, 246)',
      };

      const color = colors[threat.severity];

      // Glow effect
      ctx.beginPath();
      ctx.arc(x, y, radius + 5, 0, Math.PI * 2);
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius + 5);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.fill();

      // Main point
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      // Pulse animation for critical threats
      if (threat.severity === 'critical') {
        const time = Date.now() / 1000;
        const pulseRadius = radius + Math.sin(time * 3) * 3;
        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.globalAlpha = 0.5 + Math.sin(time * 3) * 0.5;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Count label
      if (threat.count > 1) {
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 10px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(threat.count.toString(), x, y);
      }

      // Highlight on hover
      if (hoveredThreat?.id === threat.id) {
        ctx.strokeStyle = '#00FF9F';
        ctx.lineWidth = 3;
        ctx.beginPath();
        ctx.arc(x, y, radius + 10, 0, Math.PI * 2);
        ctx.stroke();
      }
    });
  };

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const lonToX = (lon: number) => ((lon + 180) / 360) * canvas.width;
    const latToY = (lat: number) => ((90 - lat) / 180) * canvas.height;

    // Find clicked threat
    const clicked = threats.find((threat) => {
      const tx = lonToX(threat.lon);
      const ty = latToY(threat.lat);
      const distance = Math.sqrt((x - tx) ** 2 + (y - ty) ** 2);
      const radius = Math.min(5 + threat.count * 2, 20);
      return distance <= radius + 10;
    });

    if (clicked) {
      setHoveredThreat(clicked);
    } else {
      setHoveredThreat(null);
    }
  };

  const stats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    countries: new Set(threats.map(t => t.country)).size,
  };

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between">
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
        {lastUpdate && (
          <div className="text-xs text-muted-foreground font-mono">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-primary font-mono">{stats.total}</div>
            <div className="text-xs text-muted-foreground">Total Threats</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-red-500 font-mono">{stats.critical}</div>
            <div className="text-xs text-muted-foreground">Critical</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-orange-500 font-mono">{stats.high}</div>
            <div className="text-xs text-muted-foreground">High</div>
          </CardContent>
        </Card>
        <Card className="bg-card border-border">
          <CardContent className="p-3 text-center">
            <div className="text-2xl font-bold text-cyan-500 font-mono">{stats.countries}</div>
            <div className="text-xs text-muted-foreground">Countries</div>
          </CardContent>
        </Card>
      </div>

      {/* Map */}
      <Card className="bg-card border-border">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Globe className="h-5 w-5 text-primary" />
            Live Threat Map
          </CardTitle>
        </CardHeader>
        <CardContent className="relative">
          <canvas
            ref={canvasRef}
            className="w-full h-[500px] rounded-lg cursor-pointer"
            onClick={handleCanvasClick}
          />

          {/* Tooltip */}
          {hoveredThreat && (
            <div className="absolute top-4 right-4 bg-card border border-border rounded-lg p-3 shadow-lg max-w-xs">
              <div className="flex items-center gap-2 mb-2">
                <Badge className={cn(
                  hoveredThreat.severity === 'critical' ? 'bg-red-500' :
                  hoveredThreat.severity === 'high' ? 'bg-orange-500' :
                  hoveredThreat.severity === 'medium' ? 'bg-yellow-500' :
                  'bg-blue-500'
                )}>
                  {hoveredThreat.severity}
                </Badge>
                <span className="text-sm font-semibold">{hoveredThreat.threatType}</span>
              </div>
              <div className="space-y-1 text-xs">
                <div><strong>Location:</strong> {hoveredThreat.city}, {hoveredThreat.country}</div>
                <div><strong>Indicator:</strong> <code className="font-mono bg-secondary px-1 rounded">{hoveredThreat.indicator}</code></div>
                <div><strong>Source:</strong> {hoveredThreat.source}</div>
                <div><strong>Count:</strong> {hoveredThreat.count}</div>
                <div className="text-muted-foreground">
                  {new Date(hoveredThreat.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          )}

          {/* Legend */}
          <div className="absolute bottom-4 left-4 bg-card/90 border border-border rounded-lg p-3">
            <div className="text-xs font-semibold mb-2">Threat Severity</div>
            <div className="space-y-1 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-red-500" />
                <span>Critical</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-orange-500" />
                <span>High</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-yellow-500" />
                <span>Medium</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-blue-500" />
                <span>Low</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Info */}
      <Card className="bg-primary/5 border-primary/30">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Zap className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <h3 className="font-semibold text-foreground">Real-Time Data</h3>
              <p className="text-sm text-muted-foreground mt-1">
                Threat data from Feodo Tracker, ThreatFox, URLhaus, OpenPhish, and MalwareBazaar. 
                Geolocation powered by IP-API.com. Data refreshes every 5 minutes.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
