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

/*
|--------------------------------------------------------------------------
| TEMPORARY API KEY (WILL BE FIXED LATER)
|--------------------------------------------------------------------------
| WARNING:
| This key is exposed to the client.
| You explicitly requested this approach.
*/

const API_KEY = "sk_live_123456";

/*
|--------------------------------------------------------------------------
| Types
|--------------------------------------------------------------------------
*/

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
  severity: ThreatSeverity;
  source: string;
  count: number;
  timestamp: string;
}

/*
|--------------------------------------------------------------------------
| Component
|--------------------------------------------------------------------------
*/

export function LiveThreatFeed() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [autoRefresh, setAutoRefresh] = useState<boolean>(true);
  const [hoveredThreat, setHoveredThreat] = useState<ThreatPoint | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  /*
  |--------------------------------------------------------------------------
  | Effects
  |--------------------------------------------------------------------------
  */

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

  /*
  |--------------------------------------------------------------------------
  | Load Threat Intelligence (REAL DATA)
  |--------------------------------------------------------------------------
  */

  const loadThreats = async () => {
    setLoading(true);

    try {
      const response = await fetch('/api/live-threats', {
        method: 'GET',
        headers: {
          'Accept': 'application/json',
          'Authorization': `Bearer ${API_KEY}`
        }
      });

      if (!response.ok) {
        throw new Error('Failed to fetch live threat data');
      }

      const data: ThreatPoint[] = await response.json();

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

  /*
  |--------------------------------------------------------------------------
  | Canvas Rendering
  |--------------------------------------------------------------------------
  */

  const drawMap = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

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

    const lonToX = (lon: number) =>
      ((lon + 180) / 360) * canvas.width;

    const severityColors: Record<ThreatSeverity, string> = {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#3b82f6'
    };

    threats.forEach((threat) => {
      const x = lonToX(threat.lon);
      const y = latToY(threat.lat);
      const radius = Math.min(5 + threat.count * 2, 25);
      const color = severityColors[threat.severity];

      // Glow
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius + 12);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, 'transparent');

      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, radius + 12, 0, Math.PI * 2);
      ctx.fill();

      // Core
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.stroke();

      // Critical pulse
      if (threat.severity === 'critical') {
        const t = Date.now() / 1000;
        const pulseRadius = radius + Math.sin(t * 3) * 6;

        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.strokeStyle = color;
        ctx.lineWidth = 2;
        ctx.globalAlpha = 0.4;
        ctx.stroke();
        ctx.globalAlpha = 1;
      }

      // Count label
      if (threat.count > 1) {
        ctx.fillStyle = '#ffffff';
        ctx.font = 'bold 11px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(threat.count.toString(), x, y);
      }

      // Hover highlight
      if (hoveredThreat?.id === threat.id) {
        ctx.strokeStyle = '#00FF9F';
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.arc(x, y, radius + 16, 0, Math.PI * 2);
        ctx.stroke();
      }
    });
  };

  /*
  |--------------------------------------------------------------------------
  | Interaction Handlers
  |--------------------------------------------------------------------------
  */

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    const lonToX = (lon: number) =>
      ((lon + 180) / 360) * canvas.width;

    const latToY = (lat: number) =>
      ((90 - lat) / 180) * canvas.height;

    const clickedThreat = threats.find((threat) => {
      const tx = lonToX(threat.lon);
      const ty = latToY(threat.lat);
      const distance = Math.hypot(x - tx, y - ty);
      const radius = Math.min(5 + threat.count * 2, 25);
      return distance <= radius + 16;
    });

    setHoveredThreat(clickedThreat || null);
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return;

    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    });
  };

  /*
  |--------------------------------------------------------------------------
  | Stats
  |--------------------------------------------------------------------------
  */

  const stats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    countries: new Set(threats.map(t => t.country)).size
  };

  /*
  |--------------------------------------------------------------------------
  | Render
  |--------------------------------------------------------------------------
  */

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

      <div className="flex items-center justify-between">
        <div className="flex gap-3">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={autoRefresh ? 'border-primary' : ''}
          >
            <Activity className={cn(
              'h-4 w-4 mr-2',
              autoRefresh && 'animate-pulse text-primary'
            )} />
            Auto Refresh
          </Button>

          <Button size="sm" onClick={loadThreats} disabled={loading}>
            <RefreshCw className={cn(
              'h-4 w-4 mr-2',
              loading && 'animate-spin'
            )} />
            Refresh
          </Button>
        </div>

        {lastUpdate && (
          <div className="text-xs font-mono text-muted-foreground">
            Updated: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Threats', value: stats.total, color: 'text-primary' },
          { label: 'Critical', value: stats.critical, color: 'text-red-500' },
          { label: 'High', value: stats.high, color: 'text-orange-500' },
          { label: 'Countries', value: stats.countries, color: 'text-cyan-500' }
        ].map(stat => (
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
          <CardTitle className="flex items-center gap-2">
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

          {hoveredThreat && (
            <div
              className="absolute bg-card/95 border rounded-lg p-3 shadow-xl max-w-xs pointer-events-none z-10"
              style={{
                left: Math.min(
                  mousePos.x + 10,
                  (canvasRef.current?.width || 0) - 260
                ),
                top: mousePos.y + 10
              }}
            >
              <div className="flex items-center gap-2 mb-2">
                <Badge className={cn(
                  hoveredThreat.severity === 'critical' ? 'bg-red-500' :
                  hoveredThreat.severity === 'high' ? 'bg-orange-500' :
                  hoveredThreat.severity === 'medium' ? 'bg-yellow-500' :
                  'bg-blue-500'
                )}>
                  {hoveredThreat.severity.toUpperCase()}
                </Badge>
                <span className="text-sm font-semibold">
                  {hoveredThreat.threatType}
                </span>
              </div>

              <div className="space-y-1 text-xs">
                <div><strong>Location:</strong> {hoveredThreat.city}, {hoveredThreat.country}</div>
                <div><strong>Indicator:</strong> <code>{hoveredThreat.indicator}</code></div>
                <div><strong>Source:</strong> {hoveredThreat.source}</div>
                <div><strong>Count:</strong> {hoveredThreat.count}</div>
                <div className="text-muted-foreground">
                  {new Date(hoveredThreat.timestamp).toLocaleString()}
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-primary/5 border-primary/30">
        <CardContent className="p-4 flex gap-3">
          <Zap className="h-5 w-5 text-primary mt-1" />
          <div>
            <h3 className="font-semibold">Live Data Sources</h3>
            <p className="text-sm text-muted-foreground mt-1">
              Feodo Tracker (botnet C2) • URLhaus (malware distribution) • ThreatFox (recent IOCs)
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
