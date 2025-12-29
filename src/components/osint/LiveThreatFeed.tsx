import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  RefreshCw,
  Globe,
  Zap,
  MapPin
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { fetchLiveThreatMap } from '@/services/realTimeThreatService'; // <-- ADD THIS IMPORT

// Remove the fake API_KEY - you don't need it! 

export type ThreatSeverity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low';

export interface ThreatPoint {
  id: string;
  lat: number;
  lon: number;
  city: string;
  country: string;
  indicator: string;
  threatType: string;
  severity:  ThreatSeverity;
  source: string;
  count: number;
  timestamp: string;
}

export function LiveThreatFeed() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [hoveredThreat, setHoveredThreat] = useState<ThreatPoint | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    loadThreats();
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadThreats();
    }, 300000); // 5 minutes

    return () => clearInterval(interval);
  }, [autoRefresh]);

  useEffect(() => {
    drawMap();
  }, [threats, hoveredThreat]);

  // ✅ UPDATED: Use the REAL threat intelligence service
  const loadThreats = async () => {
    setLoading(true);

    try {
      // Call the REAL service that fetches from Feodo, URLhaus, ThreatFox
      const data = await fetchLiveThreatMap();

      setThreats(data);
      setLastUpdate(new Date());

      if (data.length > 0) {
        toast.success(`Loaded ${data.length} live threat indicators`);
      } else {
        toast.info('No active threat indicators available');
      }
    } catch (error) {
      console.error('Live threat load error:', error);
      toast.error('Failed to load live threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  const drawMap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas. height = canvas.offsetHeight;

    // Background
    ctx.fillStyle = '#0a0e27';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Grid
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.08)';
    ctx.lineWidth = 1;

    for (let i = 0; i <= 18; i++) {
      ctx.beginPath();
      ctx.moveTo(0, i * (canvas.height / 18));
      ctx.lineTo(canvas.width, i * (canvas.height / 18));
      ctx.stroke();
    }

    for (let i = 0; i <= 36; i++) {
      ctx.beginPath();
      ctx.moveTo(i * (canvas.width / 36), 0);
      ctx.lineTo(i * (canvas.width / 36), canvas.height);
      ctx.stroke();
    }

    const latToY = (lat: number) =>
      ((90 - lat) / 180) * canvas.height;

    const lonToX = (lon:  number) =>
      ((lon + 180) / 360) * canvas.width;

    const severityColors:  Record<ThreatSeverity, string> = {
      critical:  '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#3b82f6'
    };

    threats.forEach((threat) => {
      const x = lonToX(threat.lon);
      const y = latToY(threat.lat);
      const radius = Math.min(5 + threat.count * 2, 25);
      const color = severityColors[threat.severity];

      // Glow effect
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius * 2);
      gradient.addColorStop(0, color + '40');
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx. fillRect(x - radius * 2, y - radius * 2, radius * 4, radius * 4);

      // Threat point
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fill();

      // Pulse animation for critical threats
      if (threat.severity === 'critical') {
        ctx.strokeStyle = color + '80';
        ctx.lineWidth = 2;
        ctx.beginPath();
        ctx.arc(x, y, radius + 5, 0, Math. PI * 2);
        ctx.stroke();
      }
    });
  };

  const handleCanvasHover = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect. left;
    const y = e.clientY - rect.top;

    const latToY = (lat: number) =>
      ((90 - lat) / 180) * canvas.height;

    const lonToX = (lon: number) =>
      ((lon + 180) / 360) * canvas.width;

    let found:  ThreatPoint | null = null;

    for (const threat of threats) {
      const tx = lonToX(threat.lon);
      const ty = latToY(threat.lat);
      const radius = Math.min(5 + threat.count * 2, 25);

      const distance = Math.sqrt((x - tx) ** 2 + (y - ty) ** 2);

      if (distance <= radius) {
        found = threat;
        break;
      }
    }

    setHoveredThreat(found);
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect. top
    });
  };

  const stats = {
    total: threats. length,
    critical: threats. filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    countries: new Set(threats.map(t => t.country)).size
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Globe className="h-7 w-7 text-primary" />
          Live Threat Intelligence Map
        </h1>
        <p className="text-sm text-muted-foreground mt-1">
          Real-time global threat intelligence from Feodo, URLhaus and ThreatFox
        </p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: 'Total Threats', value: stats.total, color: 'text-primary' },
          { label: 'Critical', value: stats.critical, color: 'text-red-500' },
          { label: 'High', value: stats.high, color: 'text-orange-500' },
          { label: 'Countries', value: stats.countries, color: 'text-cyan-500' }
        ]. map(stat => (
          <Card key={stat.label}>
            <CardContent className="p-3 text-center">
              <div className={cn('text-2xl font-bold font-mono', stat.color)}>
                {stat.value}
              </div>
              <div className="text-xs text-muted-foreground">
                {stat.label}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <MapPin className="h-5 w-5 text-primary" />
              Global Threat Distribution
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setAutoRefresh(!autoRefresh)}
              >
                <Activity className={cn("h-4 w-4 mr-2", autoRefresh && "animate-pulse")} />
                Auto-refresh {autoRefresh ? 'On' : 'Off'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={loadThreats}
                disabled={loading}
              >
                <RefreshCw className={cn("h-4 w-4 mr-2", loading && "animate-spin")} />
                Refresh
              </Button>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <canvas
              ref={canvasRef}
              className="w-full h-[600px] rounded-lg border border-border bg-background"
              onMouseMove={handleCanvasHover}
              onMouseLeave={() => setHoveredThreat(null)}
            />

            {hoveredThreat && (
              <div
                className="absolute bg-popover border border-border rounded-lg p-3 shadow-lg pointer-events-none z-10"
                style={{
                  left: mousePos.x + 10,
                  top:  mousePos.y + 10,
                }}
              >
                <div className="space-y-1 text-xs">
                  <div className="font-bold text-foreground">{hoveredThreat.threatType}</div>
                  <div className="text-muted-foreground">
                    {hoveredThreat.city}, {hoveredThreat. country}
                  </div>
                  <div className="font-mono text-xs text-muted-foreground">
                    {hoveredThreat.indicator}
                  </div>
                  <Badge variant="outline" className={cn(
                    hoveredThreat.severity === 'critical' && 'bg-red-500/20 text-red-500',
                    hoveredThreat.severity === 'high' && 'bg-orange-500/20 text-orange-500',
                    hoveredThreat.severity === 'medium' && 'bg-yellow-500/20 text-yellow-500',
                    hoveredThreat.severity === 'low' && 'bg-blue-500/20 text-blue-500'
                  )}>
                    {hoveredThreat.severity. toUpperCase()}
                  </Badge>
                  <div className="text-muted-foreground">
                    Source: {hoveredThreat. source}
                  </div>
                </div>
              </div>
            )}
          </div>

          {lastUpdate && (
            <div className="mt-4 text-xs text-muted-foreground text-center">
              Last updated: {lastUpdate.toLocaleString()}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-primary" />
            Recent Threats
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {threats.slice(0, 50).map(threat => (
              <div
                key={threat.id}
                className="flex items-center justify-between p-3 rounded-lg bg-secondary/50 hover:bg-secondary transition-colors"
              >
                <div className="flex-1 space-y-1">
                  <div className="font-medium text-sm">{threat.threatType}</div>
                  <div className="text-xs text-muted-foreground font-mono">
                    {threat.indicator}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {threat.city}, {threat.country} • {threat.source}
                  </div>
                </div>
                <Badge variant="outline" className={cn(
                  threat.severity === 'critical' && 'bg-red-500/20 text-red-500',
                  threat.severity === 'high' && 'bg-orange-500/20 text-orange-500',
                  threat.severity === 'medium' && 'bg-yellow-500/20 text-yellow-500',
                  threat.severity === 'low' && 'bg-blue-500/20 text-blue-500'
                )}>
                  {threat.severity.toUpperCase()}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
