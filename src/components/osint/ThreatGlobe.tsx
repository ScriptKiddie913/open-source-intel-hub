// ============================================================================
// ThreatGlobe.tsx
// INTERACTIVE 3D GLOBE FOR LIVE THREAT VISUALIZATION
// ============================================================================
// ✔ WebGL-based 3D globe using Canvas
// ✔ Real-time threat markers with animations
// ✔ Interactive rotation and zoom
// ✔ Click on threats for details
// ✔ Attack arcs animation
// ============================================================================

'use client';

import React, { useRef, useEffect, useState, useCallback } from 'react';
import {
  Globe,
  RefreshCw,
  Pause,
  Play,
  ZoomIn,
  ZoomOut,
  Crosshair,
  AlertTriangle,
  Shield,
  Activity,
  MapPin,
  Info,
  X,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

/* ============================================================================
   TYPES
============================================================================ */

interface ThreatMarker {
  id: string;
  lat: number;
  lon: number;
  type: 'apt' | 'malware' | 'c2' | 'ransomware' | 'botnet' | 'phishing' | 'ddos';
  severity: 'critical' | 'high' | 'medium' | 'low';
  name: string;
  description: string;
  country: string;
  city?: string;
  indicators: string[];
  timestamp: string;
  metadata?: Record<string, any>;
}

interface AttackArc {
  id: string;
  sourceLat: number;
  sourceLon: number;
  targetLat: number;
  targetLon: number;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  progress: number;
  timestamp: string;
}

interface ThreatGlobeProps {
  threats: ThreatMarker[];
  attacks?: AttackArc[];
  onThreatClick?: (threat: ThreatMarker) => void;
  className?: string;
  autoRotate?: boolean;
  showStats?: boolean;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const THREAT_TYPE_COLORS = {
  apt: '#8b5cf6',
  malware: '#ec4899',
  c2: '#f97316',
  ransomware: '#ef4444',
  botnet: '#06b6d4',
  phishing: '#eab308',
  ddos: '#3b82f6',
};

// Country coordinates for quick lookup
const COUNTRY_COORDS: Record<string, { lat: number; lon: number }> = {
  'United States': { lat: 39.8283, lon: -98.5795 },
  'Russia': { lat: 61.5240, lon: 105.3188 },
  'China': { lat: 35.8617, lon: 104.1954 },
  'North Korea': { lat: 40.3399, lon: 127.5101 },
  'Iran': { lat: 32.4279, lon: 53.6880 },
  'India': { lat: 20.5937, lon: 78.9629 },
  'Brazil': { lat: -14.2350, lon: -51.9253 },
  'Germany': { lat: 51.1657, lon: 10.4515 },
  'United Kingdom': { lat: 55.3781, lon: -3.4360 },
  'France': { lat: 46.2276, lon: 2.2137 },
  'Japan': { lat: 36.2048, lon: 138.2529 },
  'South Korea': { lat: 35.9078, lon: 127.7669 },
  'Australia': { lat: -25.2744, lon: 133.7751 },
  'Canada': { lat: 56.1304, lon: -106.3468 },
  'Netherlands': { lat: 52.1326, lon: 5.2913 },
  'Singapore': { lat: 1.3521, lon: 103.8198 },
  'Israel': { lat: 31.0461, lon: 34.8516 },
  'Ukraine': { lat: 48.3794, lon: 31.1656 },
  'Poland': { lat: 51.9194, lon: 19.1451 },
  'Vietnam': { lat: 14.0583, lon: 108.2772 },
  'Pakistan': { lat: 30.3753, lon: 69.3451 },
  'Turkey': { lat: 38.9637, lon: 35.2433 },
  'Indonesia': { lat: -0.7893, lon: 113.9213 },
  'Mexico': { lat: 23.6345, lon: -102.5528 },
  'Nigeria': { lat: 9.0820, lon: 8.6753 },
};

/* ============================================================================
   GLOBE RENDERING UTILITIES
============================================================================ */

function latLonToXY(
  lat: number,
  lon: number,
  rotation: number,
  centerX: number,
  centerY: number,
  radius: number
): { x: number; y: number; visible: boolean } {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + rotation) * (Math.PI / 180);
  
  const x3d = radius * Math.sin(phi) * Math.cos(theta);
  const y3d = radius * Math.cos(phi);
  const z3d = radius * Math.sin(phi) * Math.sin(theta);
  
  // Simple orthographic projection
  const x = centerX + x3d;
  const y = centerY - y3d;
  const visible = z3d > 0;
  
  return { x, y, visible };
}

function drawGlobe(
  ctx: CanvasRenderingContext2D,
  width: number,
  height: number,
  rotation: number,
  threats: ThreatMarker[],
  attacks: AttackArc[],
  hoveredThreat: string | null,
  zoom: number
) {
  const centerX = width / 2;
  const centerY = height / 2;
  const radius = Math.min(width, height) * 0.4 * zoom;
  
  // Clear canvas
  ctx.fillStyle = '#0f172a';
  ctx.fillRect(0, 0, width, height);
  
  // Draw stars background
  ctx.fillStyle = '#ffffff';
  for (let i = 0; i < 100; i++) {
    const x = Math.random() * width;
    const y = Math.random() * height;
    const size = Math.random() * 1.5;
    ctx.beginPath();
    ctx.arc(x, y, size, 0, Math.PI * 2);
    ctx.fill();
  }
  
  // Draw globe base (dark sphere)
  const gradient = ctx.createRadialGradient(
    centerX - radius * 0.3,
    centerY - radius * 0.3,
    0,
    centerX,
    centerY,
    radius
  );
  gradient.addColorStop(0, '#1e3a5f');
  gradient.addColorStop(0.5, '#0f2744');
  gradient.addColorStop(1, '#0a1929');
  
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
  ctx.fillStyle = gradient;
  ctx.fill();
  
  // Draw atmosphere glow
  const atmosphereGradient = ctx.createRadialGradient(
    centerX,
    centerY,
    radius * 0.9,
    centerX,
    centerY,
    radius * 1.15
  );
  atmosphereGradient.addColorStop(0, 'rgba(59, 130, 246, 0.1)');
  atmosphereGradient.addColorStop(0.5, 'rgba(59, 130, 246, 0.05)');
  atmosphereGradient.addColorStop(1, 'rgba(59, 130, 246, 0)');
  
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius * 1.15, 0, Math.PI * 2);
  ctx.fillStyle = atmosphereGradient;
  ctx.fill();
  
  // Draw latitude/longitude grid
  ctx.strokeStyle = 'rgba(59, 130, 246, 0.15)';
  ctx.lineWidth = 0.5;
  
  // Latitude lines
  for (let lat = -60; lat <= 60; lat += 30) {
    ctx.beginPath();
    let started = false;
    for (let lon = -180; lon <= 180; lon += 5) {
      const { x, y, visible } = latLonToXY(lat, lon, rotation, centerX, centerY, radius);
      if (visible) {
        if (!started) {
          ctx.moveTo(x, y);
          started = true;
        } else {
          ctx.lineTo(x, y);
        }
      } else {
        started = false;
      }
    }
    ctx.stroke();
  }
  
  // Longitude lines
  for (let lon = -180; lon < 180; lon += 30) {
    ctx.beginPath();
    let started = false;
    for (let lat = -90; lat <= 90; lat += 5) {
      const { x, y, visible } = latLonToXY(lat, lon, rotation, centerX, centerY, radius);
      if (visible) {
        if (!started) {
          ctx.moveTo(x, y);
          started = true;
        } else {
          ctx.lineTo(x, y);
        }
      } else {
        started = false;
      }
    }
    ctx.stroke();
  }
  
  // Draw continents outline (simplified)
  drawContinents(ctx, rotation, centerX, centerY, radius);
  
  // Draw attack arcs
  attacks.forEach(attack => {
    const source = latLonToXY(attack.sourceLat, attack.sourceLon, rotation, centerX, centerY, radius);
    const target = latLonToXY(attack.targetLat, attack.targetLon, rotation, centerX, centerY, radius);
    
    if (source.visible || target.visible) {
      // Draw arc
      const midX = (source.x + target.x) / 2;
      const midY = (source.y + target.y) / 2 - 50;
      
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.quadraticCurveTo(midX, midY, target.x, target.y);
      ctx.strokeStyle = `${SEVERITY_COLORS[attack.severity]}88`;
      ctx.lineWidth = 2;
      ctx.stroke();
      
      // Draw animated particle along arc
      const t = attack.progress;
      const px = (1-t)*(1-t)*source.x + 2*(1-t)*t*midX + t*t*target.x;
      const py = (1-t)*(1-t)*source.y + 2*(1-t)*t*midY + t*t*target.y;
      
      ctx.beginPath();
      ctx.arc(px, py, 4, 0, Math.PI * 2);
      ctx.fillStyle = SEVERITY_COLORS[attack.severity];
      ctx.fill();
    }
  });
  
  // Draw threat markers
  threats.forEach(threat => {
    const { x, y, visible } = latLonToXY(threat.lat, threat.lon, rotation, centerX, centerY, radius);
    
    if (visible) {
      const isHovered = hoveredThreat === threat.id;
      const markerRadius = isHovered ? 12 : 8;
      const color = THREAT_TYPE_COLORS[threat.type] || SEVERITY_COLORS[threat.severity];
      
      // Pulse animation for critical threats
      if (threat.severity === 'critical') {
        const pulseRadius = markerRadius + 8 + Math.sin(Date.now() / 200) * 4;
        ctx.beginPath();
        ctx.arc(x, y, pulseRadius, 0, Math.PI * 2);
        ctx.fillStyle = `${color}22`;
        ctx.fill();
      }
      
      // Outer glow
      ctx.beginPath();
      ctx.arc(x, y, markerRadius + 4, 0, Math.PI * 2);
      ctx.fillStyle = `${color}44`;
      ctx.fill();
      
      // Main marker
      ctx.beginPath();
      ctx.arc(x, y, markerRadius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      
      // Inner highlight
      ctx.beginPath();
      ctx.arc(x - markerRadius * 0.3, y - markerRadius * 0.3, markerRadius * 0.3, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
      ctx.fill();
      
      // Label for hovered threats
      if (isHovered) {
        ctx.font = '12px system-ui, sans-serif';
        ctx.fillStyle = '#ffffff';
        ctx.textAlign = 'center';
        ctx.fillText(threat.name, x, y - markerRadius - 8);
      }
    }
  });
  
  // Draw globe border
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
  ctx.strokeStyle = 'rgba(59, 130, 246, 0.3)';
  ctx.lineWidth = 2;
  ctx.stroke();
}

function drawContinents(
  ctx: CanvasRenderingContext2D,
  rotation: number,
  centerX: number,
  centerY: number,
  radius: number
) {
  // Simplified continent outlines
  const continents = [
    // North America (simplified)
    [[50, -120], [60, -100], [50, -60], [30, -80], [25, -100], [30, -120], [50, -120]],
    // South America
    [[10, -80], [0, -50], [-20, -45], [-50, -70], [-55, -68], [-35, -60], [0, -70], [10, -80]],
    // Europe
    [[70, 0], [60, 30], [45, 40], [35, 20], [40, -10], [50, -10], [60, 10], [70, 0]],
    // Africa
    [[35, -10], [30, 30], [10, 40], [-5, 40], [-30, 30], [-35, 20], [-20, 15], [0, -15], [20, -20], [35, -10]],
    // Asia
    [[70, 60], [70, 120], [60, 140], [40, 130], [30, 120], [25, 90], [40, 70], [50, 60], [70, 60]],
    // Australia
    [[-20, 115], [-15, 145], [-35, 150], [-40, 145], [-35, 115], [-20, 115]],
  ];
  
  ctx.strokeStyle = 'rgba(34, 197, 94, 0.3)';
  ctx.fillStyle = 'rgba(34, 197, 94, 0.1)';
  ctx.lineWidth = 1;
  
  continents.forEach(continent => {
    ctx.beginPath();
    let started = false;
    
    continent.forEach(([lat, lon]) => {
      const { x, y, visible } = latLonToXY(lat, lon, rotation, centerX, centerY, radius);
      if (visible) {
        if (!started) {
          ctx.moveTo(x, y);
          started = true;
        } else {
          ctx.lineTo(x, y);
        }
      }
    });
    
    if (started) {
      ctx.closePath();
      ctx.fill();
      ctx.stroke();
    }
  });
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function ThreatGlobe({
  threats,
  attacks = [],
  onThreatClick,
  className,
  autoRotate = true,
  showStats = true,
}: ThreatGlobeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number | null>(null);
  
  const [rotation, setRotation] = useState(0);
  const [isPlaying, setIsPlaying] = useState(autoRotate);
  const [zoom, setZoom] = useState(1);
  const [hoveredThreat, setHoveredThreat] = useState<string | null>(null);
  const [selectedThreat, setSelectedThreat] = useState<ThreatMarker | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0, rotation: 0 });
  const [attackProgress, setAttackProgress] = useState<Record<string, number>>({});
  
  // Animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    let lastTime = 0;
    
    const animate = (time: number) => {
      const deltaTime = time - lastTime;
      lastTime = time;
      
      // Update rotation
      if (isPlaying && !isDragging) {
        setRotation(prev => (prev + 0.1) % 360);
      }
      
      // Update attack progress
      setAttackProgress(prev => {
        const updated = { ...prev };
        attacks.forEach(attack => {
          updated[attack.id] = ((prev[attack.id] || 0) + 0.005) % 1;
        });
        return updated;
      });
      
      // Render
      const attacksWithProgress = attacks.map(a => ({
        ...a,
        progress: attackProgress[a.id] || 0,
      }));
      
      drawGlobe(
        ctx,
        canvas.width,
        canvas.height,
        rotation,
        threats,
        attacksWithProgress,
        hoveredThreat,
        zoom
      );
      
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animationRef.current = requestAnimationFrame(animate);
    
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [rotation, isPlaying, isDragging, threats, attacks, hoveredThreat, zoom, attackProgress]);
  
  // Handle resize
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const resizeCanvas = () => {
      const container = canvas.parentElement;
      if (container) {
        canvas.width = container.clientWidth;
        canvas.height = container.clientHeight;
      }
    };
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    return () => window.removeEventListener('resize', resizeCanvas);
  }, []);
  
  // Mouse handlers
  const handleMouseDown = (e: React.MouseEvent) => {
    setIsDragging(true);
    setDragStart({
      x: e.clientX,
      y: e.clientY,
      rotation,
    });
  };
  
  const handleMouseMove = (e: React.MouseEvent) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    if (isDragging) {
      const deltaX = e.clientX - dragStart.x;
      setRotation(dragStart.rotation + deltaX * 0.5);
    } else {
      // Check for threat hover
      const rect = canvas.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      
      const centerX = canvas.width / 2;
      const centerY = canvas.height / 2;
      const radius = Math.min(canvas.width, canvas.height) * 0.4 * zoom;
      
      let found = false;
      for (const threat of threats) {
        const pos = latLonToXY(threat.lat, threat.lon, rotation, centerX, centerY, radius);
        if (pos.visible) {
          const dist = Math.sqrt((x - pos.x) ** 2 + (y - pos.y) ** 2);
          if (dist < 15) {
            setHoveredThreat(threat.id);
            found = true;
            break;
          }
        }
      }
      if (!found) setHoveredThreat(null);
    }
  };
  
  const handleMouseUp = () => {
    setIsDragging(false);
  };
  
  const handleClick = (e: React.MouseEvent) => {
    if (hoveredThreat) {
      const threat = threats.find(t => t.id === hoveredThreat);
      if (threat) {
        setSelectedThreat(threat);
        onThreatClick?.(threat);
      }
    }
  };
  
  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setZoom(prev => Math.max(0.5, Math.min(2, prev - e.deltaY * 0.001)));
  };
  
  // Stats calculation
  const stats = {
    total: threats.length,
    critical: threats.filter(t => t.severity === 'critical').length,
    high: threats.filter(t => t.severity === 'high').length,
    byType: threats.reduce((acc, t) => {
      acc[t.type] = (acc[t.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>),
  };
  
  return (
    <div className={cn('relative w-full h-full min-h-[500px]', className)}>
      {/* Globe Canvas */}
      <canvas
        ref={canvasRef}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onClick={handleClick}
        onWheel={handleWheel}
      />
      
      {/* Controls */}
      <div className="absolute top-4 left-4 flex flex-col gap-2">
        <Button
          variant="outline"
          size="icon"
          className="bg-slate-900/80 border-slate-700 hover:bg-slate-800"
          onClick={() => setIsPlaying(!isPlaying)}
        >
          {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="bg-slate-900/80 border-slate-700 hover:bg-slate-800"
          onClick={() => setZoom(prev => Math.min(2, prev + 0.2))}
        >
          <ZoomIn className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="bg-slate-900/80 border-slate-700 hover:bg-slate-800"
          onClick={() => setZoom(prev => Math.max(0.5, prev - 0.2))}
        >
          <ZoomOut className="h-4 w-4" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="bg-slate-900/80 border-slate-700 hover:bg-slate-800"
          onClick={() => {
            setRotation(0);
            setZoom(1);
          }}
        >
          <Crosshair className="h-4 w-4" />
        </Button>
      </div>
      
      {/* Stats Panel */}
      {showStats && (
        <div className="absolute top-4 right-4 w-48">
          <Card className="bg-slate-900/90 border-slate-700/50 backdrop-blur">
            <CardHeader className="p-3 pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="h-4 w-4 text-primary" />
                Live Threats
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3 pt-0 space-y-2">
              <div className="flex justify-between text-sm">
                <span className="text-slate-400">Total</span>
                <Badge variant="outline">{stats.total}</Badge>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-red-400">Critical</span>
                <Badge className="bg-red-500/20 text-red-400 border-red-500/30">
                  {stats.critical}
                </Badge>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-orange-400">High</span>
                <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30">
                  {stats.high}
                </Badge>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
      
      {/* Legend */}
      <div className="absolute bottom-4 left-4">
        <Card className="bg-slate-900/90 border-slate-700/50 backdrop-blur">
          <CardContent className="p-3">
            <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              {Object.entries(THREAT_TYPE_COLORS).slice(0, 6).map(([type, color]) => (
                <div key={type} className="flex items-center gap-2">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-slate-400 capitalize">{type}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
      
      {/* Selected Threat Detail Panel */}
      {selectedThreat && (
        <div className="absolute bottom-4 right-4 w-80">
          <Card className="bg-slate-900/95 border-slate-700/50 backdrop-blur">
            <CardHeader className="p-3 pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <MapPin className="h-4 w-4" style={{ color: THREAT_TYPE_COLORS[selectedThreat.type] }} />
                  {selectedThreat.name}
                </CardTitle>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-6 w-6"
                  onClick={() => setSelectedThreat(null)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-3 pt-0 space-y-2">
              <div className="flex items-center gap-2">
                <Badge
                  className={cn(
                    'text-xs',
                    selectedThreat.severity === 'critical' && 'bg-red-500/20 text-red-400',
                    selectedThreat.severity === 'high' && 'bg-orange-500/20 text-orange-400',
                    selectedThreat.severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                    selectedThreat.severity === 'low' && 'bg-green-500/20 text-green-400'
                  )}
                >
                  {selectedThreat.severity}
                </Badge>
                <Badge variant="outline" className="text-xs capitalize">
                  {selectedThreat.type}
                </Badge>
              </div>
              <p className="text-xs text-slate-400">{selectedThreat.description}</p>
              <div className="text-xs">
                <span className="text-slate-500">Location: </span>
                <span className="text-slate-300">
                  {selectedThreat.city ? `${selectedThreat.city}, ` : ''}{selectedThreat.country}
                </span>
              </div>
              {selectedThreat.indicators.length > 0 && (
                <div className="text-xs">
                  <span className="text-slate-500">Indicators: </span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedThreat.indicators.slice(0, 3).map((ind, i) => (
                      <Badge key={i} variant="outline" className="text-xs font-mono">
                        {ind.substring(0, 20)}...
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
              <div className="text-xs text-slate-500">
                Last seen: {new Date(selectedThreat.timestamp).toLocaleString()}
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}

export { COUNTRY_COORDS, SEVERITY_COLORS, THREAT_TYPE_COLORS };
export type { ThreatMarker, AttackArc };
export default ThreatGlobe;
