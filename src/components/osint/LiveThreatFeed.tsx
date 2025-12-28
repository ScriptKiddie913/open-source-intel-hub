// src/components/osint/LiveThreatFeed.tsx
// REPLACE ENTIRE FILE WITH THIS

import { useState, useEffect, useRef } from 'react';
import { Activity, RefreshCw, Globe, Zap, AlertTriangle, MapPin } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { fetchLiveThreatMap, ThreatPoint } from '@/services/realTimeThreatService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

export function LiveThreatFeed() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [hoveredThreat, setHoveredThreat] = useState<ThreatPoint | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  useEffect(() => {
    loadThreats();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(loadThreats, 300000); // 5 minutes
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  useEffect(() => {
    drawMap();
  }, [threats, hoveredThreat]);

  const loadThreats = async () => {
    setLoading(true);
    try {
      const data = await fetchLiveThreatMap();
      setThreats(data);
      setLastUpdate(new Date());
      
      if (data.length > 0) {
        toast.success(`Loaded ${data.length} live threat indicators`);
      } else {
        toast.info('No active threats detected at this time');
      }
    } catch (error) {
      console.error('Failed to load threats:', error);
      toast.error('Failed to load live threat data');
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

    // Draw threat points
    threats.forEach((threat) => {
      const x = lonToX(threat.lon);
      const y = latToY(threat.lat);
      const radius = Math.min(5 + threat.count * 2, 25);

      const severityColors = {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#3b82f6',
      };

      const color = severityColors[threat.severity];

      // Glow effect
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, radius + 10);
      gradient.addColorStop(0, color);
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, radius + 10, 0, Math.PI * 2);
      ctx.fill();

      // Main point
      ctx.beginPath();
      ctx.arc(x, y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.stroke();

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
      if (threat.count > 1) {
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 11px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(threat.count.toString(), x, y);
      }

      // Highlight on hover
      if (hoveredThreat?.id === threat.id) {
        ctx.strokeStyle = '#00FF9F';
        ctx.lineWidth = 4;
        ctx.beginPath();
        ctx.arc(x, y, radius + 15, 0, Math.PI * 2);
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

    const clicked = threats.find((threat) => {
      const tx = lonToX(threat.lon);
      const ty = latToY(threat.lat);
      const distance = Math.sqrt((x - tx) ** 2 + (y - ty) ** 2);
      const radius = Math.min(5 + threat.count * 2, 25);
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
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    countries: new Set(threats.map(t => t.country)).size,
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
          Real-time global threat visualization from Feodo, URLhaus, ThreatFox
        </p>
      </div>

      {/* Controls */}
      <div className="flex items-center justify-between">
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
        {lastUpdate && (
          <div className="text-xs text-muted-foreground font-mono">
            Updated: {lastUpdate.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: 'Total Threats', value: stats.total, color: 'text-primary' },
          { label: 'Critical', value: stats.critical, color: 'text-red-500' },
          { label: 'High', value: stats.high, color: 'text-orange-500' },
          { label: 'Countries', value: stats.countries, color: 'text-cyan-500' },
        ].map((stat) => (
          <Card key={stat.label} className="bg-card border-border">
            <CardContent className="p-3 text-center">
              <div className={cn('text-2xl font-bold font-mono', stat.color)}>{stat.value}</div>
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
                <strong>Feodo Tracker:</strong> Botnet C2 servers • 
                <strong>URLhaus:</strong> Malware distribution URLs • 
                <strong>ThreatFox:</strong> Recent IOCs • 
                Geolocation via ip-api.com
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
