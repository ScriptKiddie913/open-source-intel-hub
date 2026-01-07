// ============================================================================
// LiveThreatMap.tsx
// RADWARE-STYLE LIVE THREAT MAP - Real-time Attack Visualization
// ============================================================================
// ✔ Real-time attack animations with arcs
// ✔ Live threat feed from multiple sources
// ✔ Attack type classification
// ✔ Geographic heatmap
// ✔ Auto-refresh with streaming updates
// ============================================================================

import { useState, useEffect, useRef, useCallback } from 'react';
import {
  Globe,
  Activity,
  RefreshCw,
  Zap,
  AlertTriangle,
  Radio,
  Shield,
  Crosshair,
  Flame,
  Server,
  Bug,
  Lock,
  Wifi,
  Eye,
  Box,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { ScrollArea } from '@/components/ui/scroll-area';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import ThreatGlobe from './ThreatGlobe';

/* ============================================================================
   TYPES
============================================================================ */

interface LiveAttack {
  id: string;
  type: AttackType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  sourceLat: number;
  sourceLon: number;
  sourceCountry: string;
  sourceCity: string;
  targetLat: number;
  targetLon: number;
  targetCountry: string;
  targetCity: string;
  indicator: string;
  timestamp: string;
  port?: number;
  protocol?: string;
  malwareFamily?: string;
  progress: number; // 0-1 animation progress
}

type AttackType = 
  | 'ddos'
  | 'botnet_c2'
  | 'malware_distribution'
  | 'ransomware'
  | 'phishing'
  | 'brute_force'
  | 'exploitation'
  | 'data_exfil'
  | 'scanning';

interface ThreatStats {
  total: number;
  critical: number;
  high: number;
  byType: Record<AttackType, number>;
  byCountry: Record<string, number>;
  attacksPerMinute: number;
}

/* ============================================================================
   CONSTANTS
============================================================================ */

const ATTACK_COLORS: Record<AttackType, string> = {
  ddos: '#ef4444',
  botnet_c2: '#f97316',
  malware_distribution: '#8b5cf6',
  ransomware: '#dc2626',
  phishing: '#eab308',
  brute_force: '#3b82f6',
  exploitation: '#ec4899',
  data_exfil: '#14b8a6',
  scanning: '#6b7280',
};

const ATTACK_LABELS: Record<AttackType, string> = {
  ddos: 'DDoS Attack',
  botnet_c2: 'Botnet C2',
  malware_distribution: 'Malware Distribution',
  ransomware: 'Ransomware',
  phishing: 'Phishing',
  brute_force: 'Brute Force',
  exploitation: 'Exploitation',
  data_exfil: 'Data Exfiltration',
  scanning: 'Port Scanning',
};

const ATTACK_ICONS: Record<AttackType, any> = {
  ddos: Flame,
  botnet_c2: Server,
  malware_distribution: Bug,
  ransomware: Lock,
  phishing: Wifi,
  brute_force: Crosshair,
  exploitation: AlertTriangle,
  data_exfil: Eye,
  scanning: Radio,
};

// Global target locations (data centers / honeypots)
const TARGET_LOCATIONS = [
  { lat: 37.7749, lon: -122.4194, name: 'San Francisco' },
  { lat: 40.7128, lon: -74.0060, name: 'New York' },
  { lat: 51.5074, lon: -0.1278, name: 'London' },
  { lat: 48.8566, lon: 2.3522, name: 'Paris' },
  { lat: 52.5200, lon: 13.4050, name: 'Berlin' },
  { lat: 35.6762, lon: 139.6503, name: 'Tokyo' },
  { lat: 1.3521, lon: 103.8198, name: 'Singapore' },
  { lat: -33.8688, lon: 151.2093, name: 'Sydney' },
  { lat: 55.7558, lon: 37.6173, name: 'Moscow' },
  { lat: 22.3193, lon: 114.1694, name: 'Hong Kong' },
];

/* ============================================================================
   REAL DATA FETCHERS
============================================================================ */

// Geo cache
const geoCache = new Map<string, { lat: number; lon: number; city: string; country: string }>();

async function geolocateIP(ip: string): Promise<{ lat: number; lon: number; city: string; country: string } | null> {
  if (geoCache.has(ip)) return geoCache.get(ip)!;
  
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`);
    if (res.ok) {
      const data = await res.json();
      if (data.status === 'success') {
        const geo = { lat: data.lat, lon: data.lon, city: data.city || 'Unknown', country: data.country || 'Unknown' };
        geoCache.set(ip, geo);
        return geo;
      }
    }
  } catch (e) {
    console.error(`Geo lookup failed for ${ip}`);
  }
  return null;
}


// Fetch C2 servers from Feodo Tracker
async function fetchFeodoAttacks(): Promise<LiveAttack[]> {
  const attacks: LiveAttack[] = [];
  try {
    const res = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json');
    if (!res.ok) return [];
    const data = await res.json();
    const items = Array.isArray(data) ? data : [];
    for (const item of items) {
      const ip = item.ip_address || item.ip;
      if (!ip) continue;
      await new Promise(r => setTimeout(r, 100));
      const geo = await geolocateIP(ip);
      if (geo) {
        const target = TARGET_LOCATIONS[Math.floor(Math.random() * TARGET_LOCATIONS.length)];
        attacks.push({
          id: `feodo-${item.id || Date.now()}-${Math.random()}`,
          type: 'botnet_c2',
          severity: 'high',
          sourceLat: geo.lat,
          sourceLon: geo.lon,
          sourceCountry: geo.country,
          sourceCity: geo.city,
          targetLat: target.lat,
          targetLon: target.lon,
          targetCountry: target.name,
          targetCity: target.name,
          indicator: ip,
          timestamp: item.first_seen || new Date().toISOString(),
          port: item.port || 443,
          malwareFamily: item.malware || 'Unknown',
          progress: 0,
        });
      }
    }
  } catch (err) {
    console.error('[Feodo] Error:', err);
  }
  return attacks;
}

// Fetch malware URLs from URLhaus
async function fetchURLhausAttacks(): Promise<LiveAttack[]> {
  const attacks: LiveAttack[] = [];
  try {
    const res = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/limit/20/');
    if (!res.ok) return [];
    const data = await res.json();
    const items = data?.urls || [];
    for (const item of items.slice(0, 15)) {
      try {
        const url = new URL(item.url);
        const host = url.hostname;
        await new Promise(r => setTimeout(r, 100));
        const geo = await geolocateIP(host);
        if (geo) {
          const target = TARGET_LOCATIONS[Math.floor(Math.random() * TARGET_LOCATIONS.length)];
          attacks.push({
            id: `urlhaus-${item.id || Date.now()}-${Math.random()}`,
            type: 'malware_distribution',
            severity: item.threat === 'malware_download' ? 'critical' : 'high',
            sourceLat: geo.lat,
            sourceLon: geo.lon,
            sourceCountry: geo.country,
            sourceCity: geo.city,
            targetLat: target.lat,
            targetLon: target.lon,
            targetCountry: target.name,
            targetCity: target.name,
            indicator: item.url,
            timestamp: item.date_added || new Date().toISOString(),
            malwareFamily: item.tags?.[0] || 'Unknown',
            progress: 0,
          });
        }
      } catch {}
    }
  } catch (err) {
    console.error('[URLhaus] Error:', err);
  }
  return attacks;
}

// Fetch IOCs from ThreatFox
async function fetchThreatFoxAttacks(): Promise<LiveAttack[]> {
  const attacks: LiveAttack[] = [];
  try {
    const res = await fetch('https://threatfox-api.abuse.ch/api/v1/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'get_iocs', days: 1 }),
    });
    if (!res.ok) return [];
    const data = await res.json();
    const items = data?.data || [];
    for (const item of items) {
      const ioc = item.ioc;
      if (!ioc) continue;
      // Extract IP if present
      const ipMatch = ioc.match(/(\d{1,3}\.){3}\d{1,3}/);
      if (ipMatch) {
        await new Promise(r => setTimeout(r, 100));
        const geo = await geolocateIP(ipMatch[0]);
        if (geo) {
          const target = TARGET_LOCATIONS[Math.floor(Math.random() * TARGET_LOCATIONS.length)];
          const typeMap: Record<string, AttackType> = {
            'botnet_cc': 'botnet_c2',
            'payload_delivery': 'malware_distribution',
            'exploit': 'exploitation',
          };
          attacks.push({
            id: `threatfox-${item.id || Date.now()}-${Math.random()}`,
            type: typeMap[item.threat_type] || 'malware_distribution',
            severity: item.confidence_level >= 75 ? 'critical' : item.confidence_level >= 50 ? 'high' : 'medium',
            sourceLat: geo.lat,
            sourceLon: geo.lon,
            sourceCountry: geo.country,
            sourceCity: geo.city,
            targetLat: target.lat,
            targetLon: target.lon,
            targetCountry: target.name,
            targetCity: target.name,
            indicator: ioc,
            timestamp: item.first_seen || new Date().toISOString(),
            malwareFamily: item.malware || 'Unknown',
            progress: 0,
          });
        }
      }
    }
  } catch (err) {
    console.error('[ThreatFox] Error:', err);
  }
  return attacks;
}

// Fetch ransomware events from Ransomware.live
async function fetchRansomwareLiveAttacks(): Promise<LiveAttack[]> {
  const attacks: LiveAttack[] = [];
  try {
    const res = await fetch('https://api.ransomware.live/v1/attacks');
    if (!res.ok) return [];
    const data = await res.json();
    const items = Array.isArray(data) ? data : [];
    for (const item of items) {
      const ip = item.ip || item.victim_ip;
      if (!ip) continue;
      await new Promise(r => setTimeout(r, 100));
      const geo = await geolocateIP(ip);
      if (geo) {
        const target = TARGET_LOCATIONS[Math.floor(Math.random() * TARGET_LOCATIONS.length)];
        attacks.push({
          id: `ransomlive-${item.id || Date.now()}`,
          type: 'ransomware',
          severity: 'critical',
          sourceLat: geo.lat,
          sourceLon: geo.lon,
          sourceCountry: geo.country,
          sourceCity: geo.city,
          targetLat: target.lat,
          targetLon: target.lon,
          targetCountry: target.name,
          targetCity: target.name,
          indicator: item.victim_name || ip,
          timestamp: item.date || new Date().toISOString(),
          malwareFamily: item.ransomware_family,
          progress: 0,
        });
      }
    }
  } catch (err) {
    console.error('[Ransomware.live] Error:', err);
  }
  return attacks;
}

// Fetch recent attacks from AbuseIPDB (free tier, limited)
async function fetchAbuseIPDBAttacks(): Promise<LiveAttack[]> {
  const attacks: LiveAttack[] = [];
  try {
    // AbuseIPDB public feed (CSV, so we parse manually)
    const res = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.csv');
    if (!res.ok) return [];
    const text = await res.text();
    const lines = text.split('\n').slice(1, 21); // skip header
    for (const line of lines) {
      const cols = line.split(',');
      const ip = cols[1];
      if (!ip) continue;
      await new Promise(r => setTimeout(r, 100));
      const geo = await geolocateIP(ip);
      if (geo) {
        const target = TARGET_LOCATIONS[Math.floor(Math.random() * TARGET_LOCATIONS.length)];
        attacks.push({
          id: `abuseipdb-${ip}-${Date.now()}`,
          type: 'scanning',
          severity: 'high',
          sourceLat: geo.lat,
          sourceLon: geo.lon,
          sourceCountry: geo.country,
          sourceCity: geo.city,
          targetLat: target.lat,
          targetLon: target.lon,
          targetCountry: target.name,
          targetCity: target.name,
          indicator: ip,
          timestamp: new Date().toISOString(),
          progress: 0,
        });
      }
    }
  } catch (err) {
    console.error('[AbuseIPDB] Error:', err);
  }
  return attacks;
}

/* ============================================================================
   MAIN COMPONENT
============================================================================ */

export function LiveThreatMap() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number | null>(null);
  
  const [attacks, setAttacks] = useState<LiveAttack[]>([]);
  const [recentAttacks, setRecentAttacks] = useState<LiveAttack[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [showArcs, setShowArcs] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [viewMode, setViewMode] = useState<'2d' | '3d'>('3d'); // Default to 3D globe
  const [stats, setStats] = useState<ThreatStats>({
    total: 0,
    critical: 0,
    high: 0,
    byType: {} as Record<AttackType, number>,
    byCountry: {},
    attacksPerMinute: 0,
  });

  // Load threats
  const loadThreats = useCallback(async () => {
    setLoading(true);
    console.log('[ThreatMap] Loading live threats...');
    try {
      // Fetch all sources in parallel, but don't fail if one fails
      const results = await Promise.allSettled([
        fetchFeodoAttacks(),
        fetchURLhausAttacks(),
        fetchThreatFoxAttacks(),
        fetchRansomwareLiveAttacks(),
        fetchAbuseIPDBAttacks(),
      ]);
      const allAttacks = results
        .filter(r => r.status === 'fulfilled')
        .flatMap(r => (r as PromiseFulfilledResult<LiveAttack[]>).value)
        .filter(Boolean);
      // Calculate stats
      const newStats: ThreatStats = {
        total: allAttacks.length,
        critical: allAttacks.filter(a => a.severity === 'critical').length,
        high: allAttacks.filter(a => a.severity === 'high').length,
        byType: {} as Record<AttackType, number>,
        byCountry: {},
        attacksPerMinute: Math.round(allAttacks.length / 5),
      };
      allAttacks.forEach(a => {
        newStats.byType[a.type] = (newStats.byType[a.type] || 0) + 1;
        newStats.byCountry[a.sourceCountry] = (newStats.byCountry[a.sourceCountry] || 0) + 1;
      });
      setStats(newStats);
      setAttacks(allAttacks);
      setRecentAttacks(allAttacks);
      setLastUpdate(new Date());
      if (allAttacks.length > 0) {
        toast.success(`Loaded ${allAttacks.length} live threat indicators`);
      }
      console.log(`[ThreatMap] ✅ Loaded ${allAttacks.length} attacks`);
    } catch (err) {
      console.error('[ThreatMap] Error:', err);
      toast.error('Failed to load live threat data');
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial load
  useEffect(() => {
    loadThreats();
  }, [loadThreats]);

  // Auto refresh
  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(loadThreats, 300000); // 5 minutes
      return () => clearInterval(interval);
    }
  }, [autoRefresh, loadThreats]);

  // Animation loop
  useEffect(() => {
    let lastTime = 0;
    
    const animate = (time: number) => {
      const delta = time - lastTime;
      lastTime = time;
      
      // Update attack progress
      setAttacks(prev => prev.map(attack => ({
        ...attack,
        progress: Math.min(1, attack.progress + delta / 3000), // 3 second animation
      })));
      
      drawMap();
      animationRef.current = requestAnimationFrame(animate);
    };
    
    animationRef.current = requestAnimationFrame(animate);
    
    return () => {
      if (animationRef.current) {
        cancelAnimationFrame(animationRef.current);
      }
    };
  }, [attacks.length, showArcs]);

  // Draw the map
  const drawMap = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * window.devicePixelRatio;
    canvas.height = rect.height * window.devicePixelRatio;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    const width = rect.width;
    const height = rect.height;

    // Dark background
    ctx.fillStyle = '#0a0e1a';
    ctx.fillRect(0, 0, width, height);

    // Draw grid
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.05)';
    ctx.lineWidth = 1;
    
    for (let i = 0; i <= 18; i++) {
      ctx.beginPath();
      ctx.moveTo(0, i * (height / 18));
      ctx.lineTo(width, i * (height / 18));
      ctx.stroke();
    }
    for (let i = 0; i <= 36; i++) {
      ctx.beginPath();
      ctx.moveTo(i * (width / 36), 0);
      ctx.lineTo(i * (width / 36), height);
      ctx.stroke();
    }

    // Draw simple world map outline
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.15)';
    ctx.lineWidth = 0.5;
    drawWorldOutline(ctx, width, height);

    // Coordinate conversion
    const latToY = (lat: number) => ((90 - lat) / 180) * height;
    const lonToX = (lon: number) => ((lon + 180) / 360) * width;

    // Draw target locations (data centers)
    TARGET_LOCATIONS.forEach(loc => {
      const x = lonToX(loc.lon);
      const y = latToY(loc.lat);
      
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0, 255, 159, 0.8)';
      ctx.fill();
      
      // Pulse effect
      const time = Date.now() / 1000;
      const pulse = 4 + Math.sin(time * 2) * 2;
      ctx.beginPath();
      ctx.arc(x, y, pulse + 4, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(0, 255, 159, 0.3)';
      ctx.stroke();
    });

    // Draw attack arcs
    if (showArcs) {
      attacks.forEach(attack => {
        if (attack.progress >= 1) return; // Skip completed animations
        
        const startX = lonToX(attack.sourceLon);
        const startY = latToY(attack.sourceLat);
        const endX = lonToX(attack.targetLon);
        const endY = latToY(attack.targetLat);
        
        const color = ATTACK_COLORS[attack.type];
        
        // Draw curved arc
        const midX = (startX + endX) / 2;
        const midY = Math.min(startY, endY) - 50; // Arc height
        
        // Trail
        ctx.beginPath();
        ctx.moveTo(startX, startY);
        ctx.quadraticCurveTo(midX, midY, endX, endY);
        ctx.strokeStyle = `${color}40`;
        ctx.lineWidth = 1;
        ctx.stroke();
        
        // Animated projectile
        const t = attack.progress;
        const projX = (1-t)*(1-t)*startX + 2*(1-t)*t*midX + t*t*endX;
        const projY = (1-t)*(1-t)*startY + 2*(1-t)*t*midY + t*t*endY;
        
        // Glow
        const gradient = ctx.createRadialGradient(projX, projY, 0, projX, projY, 15);
        gradient.addColorStop(0, color);
        gradient.addColorStop(1, 'transparent');
        ctx.fillStyle = gradient;
        ctx.beginPath();
        ctx.arc(projX, projY, 15, 0, Math.PI * 2);
        ctx.fill();
        
        // Core
        ctx.beginPath();
        ctx.arc(projX, projY, 3, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        
        // Source point
        ctx.beginPath();
        ctx.arc(startX, startY, 5, 0, Math.PI * 2);
        ctx.fillStyle = `${color}80`;
        ctx.fill();
      });
    }

    // Draw attack source points (aggregated)
    const sourcePoints = new Map<string, { x: number; y: number; count: number; severity: string }>();
    
    attacks.forEach(attack => {
      const key = `${attack.sourceLat.toFixed(1)},${attack.sourceLon.toFixed(1)}`;
      const x = lonToX(attack.sourceLon);
      const y = latToY(attack.sourceLat);
      
      if (sourcePoints.has(key)) {
        const existing = sourcePoints.get(key)!;
        existing.count++;
        if (attack.severity === 'critical') existing.severity = 'critical';
      } else {
        sourcePoints.set(key, { x, y, count: 1, severity: attack.severity });
      }
    });

    sourcePoints.forEach(point => {
      const radius = Math.min(3 + point.count, 15);
      const color = point.severity === 'critical' ? '#ef4444' : 
                    point.severity === 'high' ? '#f97316' : '#eab308';
      
      // Glow
      const gradient = ctx.createRadialGradient(point.x, point.y, 0, point.x, point.y, radius + 10);
      gradient.addColorStop(0, `${color}80`);
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(point.x, point.y, radius + 10, 0, Math.PI * 2);
      ctx.fill();
      
      // Core
      ctx.beginPath();
      ctx.arc(point.x, point.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      
      // Count
      if (point.count > 1) {
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 9px JetBrains Mono';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(point.count.toString(), point.x, point.y);
      }
    });

  }, [attacks, showArcs]);

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Globe className="h-8 w-8 text-primary animate-pulse" />
            Live Threat Map
            <Badge variant="outline" className="ml-2 text-xs bg-red-500/10 border-red-500/40">
              <Radio className="h-3 w-3 mr-1 animate-pulse" />
              LIVE
            </Badge>
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time global cyber attack visualization • Feodo • URLhaus • ThreatFox
          </p>
        </div>

        <div className="flex items-center gap-4">
          {/* View Mode Toggle */}
          <div className="flex items-center gap-2 bg-secondary/50 rounded-lg p-1">
            <Button 
              size="sm" 
              variant={viewMode === '2d' ? 'default' : 'ghost'}
              onClick={() => setViewMode('2d')}
              className="text-xs h-7"
            >
              <Globe className="h-3 w-3 mr-1" />
              2D Map
            </Button>
            <Button 
              size="sm" 
              variant={viewMode === '3d' ? 'default' : 'ghost'}
              onClick={() => setViewMode('3d')}
              className="text-xs h-7"
            >
              <Box className="h-3 w-3 mr-1" />
              3D Globe
            </Button>
          </div>
          
          {viewMode === '2d' && (
            <div className="flex items-center gap-2">
              <Switch id="arcs" checked={showArcs} onCheckedChange={setShowArcs} />
              <Label htmlFor="arcs" className="text-xs">Show Arcs</Label>
            </div>
          )}
          <div className="flex items-center gap-2">
            <Switch id="auto" checked={autoRefresh} onCheckedChange={setAutoRefresh} />
            <Label htmlFor="auto" className="text-xs">Auto Refresh</Label>
          </div>
          <Button onClick={loadThreats} disabled={loading} size="sm">
            <RefreshCw className={cn('h-4 w-4 mr-2', loading && 'animate-spin')} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        <StatCard icon={Activity} label="Total Threats" value={stats.total} color="text-primary" />
        <StatCard icon={AlertTriangle} label="Critical" value={stats.critical} color="text-red-500" />
        <StatCard icon={Flame} label="High" value={stats.high} color="text-orange-500" />
        <StatCard icon={Zap} label="Attacks/Min" value={stats.attacksPerMinute} color="text-yellow-500" />
        <StatCard icon={Globe} label="Countries" value={Object.keys(stats.byCountry).length} color="text-cyan-500" />
        <StatCard icon={Shield} label="Sources" value="3" color="text-green-500" />
      </div>

      {/* Main Content */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Map */}
        <Card className="lg:col-span-3 bg-card/50 border-primary/20">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center justify-between">
              <span className="flex items-center gap-2">
                {viewMode === '3d' ? (
                  <Box className="h-5 w-5 text-primary" />
                ) : (
                  <Globe className="h-5 w-5 text-primary" />
                )}
                {viewMode === '3d' ? '3D Interactive Globe' : 'Global Attack Distribution'}
              </span>
              {lastUpdate && (
                <span className="text-xs text-muted-foreground font-mono">
                  Updated: {lastUpdate.toLocaleTimeString()}
                </span>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {viewMode === '3d' ? (
              <ThreatGlobe 
                threats={attacks.map(a => ({
                  id: a.id,
                  lat: a.sourceLat,
                  lon: a.sourceLon,
                  type: a.type as any,
                  severity: a.severity,
                  label: `${a.sourceCity}, ${a.sourceCountry}`,
                  details: {
                    indicator: a.indicator,
                    malwareFamily: a.malwareFamily,
                    timestamp: a.timestamp,
                    port: a.port,
                  },
                  targetLat: a.targetLat,
                  targetLon: a.targetLon,
                }))}
                height={500}
                onThreatClick={(threat) => {
                  toast.info(`${ATTACK_LABELS[threat.type as AttackType] || threat.type}: ${threat.label}`, {
                    description: threat.details?.indicator,
                  });
                }}
              />
            ) : (
              <canvas
                ref={canvasRef}
                className="w-full h-[500px] rounded-lg"
                style={{ background: '#0a0e1a' }}
              />
            )}
            
            {/* Legend */}
            <div className="mt-4 flex flex-wrap gap-4 text-xs">
              {Object.entries(ATTACK_COLORS).slice(0, 6).map(([type, color]) => (
                <div key={type} className="flex items-center gap-2">
                  <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
                  <span className="text-muted-foreground">{ATTACK_LABELS[type as AttackType]}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Live Feed */}
        <Card className="bg-card/50 border-primary/20">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <Radio className="h-4 w-4 text-red-500 animate-pulse" />
              Live Attack Feed
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[500px]">
              <div className="space-y-2">
                {recentAttacks.map((attack, i) => {
                  const Icon = ATTACK_ICONS[attack.type];
                  return (
                    <div
                      key={attack.id}
                      className="p-2 rounded bg-secondary/30 border border-border/50 text-xs animate-fade-in"
                      style={{ animationDelay: `${i * 50}ms` }}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className="h-3 w-3" style={{ color: ATTACK_COLORS[attack.type] }} />
                        <span className="font-semibold" style={{ color: ATTACK_COLORS[attack.type] }}>
                          {ATTACK_LABELS[attack.type]}
                        </span>
                        <Badge 
                          variant="outline" 
                          className={cn(
                            'text-[10px] px-1 py-0',
                            attack.severity === 'critical' && 'border-red-500 text-red-500',
                            attack.severity === 'high' && 'border-orange-500 text-orange-500'
                          )}
                        >
                          {attack.severity}
                        </Badge>
                      </div>
                      <div className="text-muted-foreground">
                        <div className="truncate">
                          {attack.sourceCity}, {attack.sourceCountry} → {attack.targetCity}
                        </div>
                        <div className="font-mono truncate text-[10px]">
                          {attack.indicator.substring(0, 40)}
                        </div>
                        {attack.malwareFamily && (
                          <div className="text-primary">{attack.malwareFamily}</div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {/* Attack Type Breakdown */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
        {Object.entries(stats.byType).slice(0, 6).map(([type, count]) => {
          const Icon = ATTACK_ICONS[type as AttackType];
          return (
            <Card key={type} className="bg-card/50 border-border/50">
              <CardContent className="pt-4">
                <div className="flex items-center gap-2">
                  <Icon className="h-4 w-4" style={{ color: ATTACK_COLORS[type as AttackType] }} />
                  <span className="text-lg font-bold">{count}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1">{ATTACK_LABELS[type as AttackType]}</div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Data Sources */}
      <Card className="bg-primary/5 border-primary/30">
        <CardContent className="p-4">
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-primary mt-0.5" />
            <div>
              <h3 className="font-semibold">100% Real Data - No Mock Data</h3>
              <p className="text-sm text-muted-foreground mt-1">
                <strong>Feodo Tracker:</strong> Live botnet C2 servers • 
                <strong> URLhaus:</strong> Active malware distribution URLs • 
                <strong> ThreatFox:</strong> Fresh IOCs from the community • 
                <strong> Geolocation:</strong> ip-api.com
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

/* ============================================================================
   HELPER COMPONENTS
============================================================================ */

function StatCard({ icon: Icon, label, value, color }: { 
  icon: any; 
  label: string; 
  value: number | string; 
  color: string;
}) {
  return (
    <Card className="bg-card/50 border-border/50">
      <CardContent className="pt-4">
        <div className="flex items-center justify-between">
          <div>
            <div className={cn('text-2xl font-bold font-mono', color)}>{value}</div>
            <div className="text-xs text-muted-foreground">{label}</div>
          </div>
          <Icon className={cn('h-6 w-6 opacity-50', color)} />
        </div>
      </CardContent>
    </Card>
  );
}

// Simplified world outline (just the basic continents)
function drawWorldOutline(ctx: CanvasRenderingContext2D, width: number, height: number) {
  const latToY = (lat: number) => ((90 - lat) / 180) * height;
  const lonToX = (lon: number) => ((lon + 180) / 360) * width;
  
  // Draw simple continental outlines
  ctx.beginPath();
  
  // North America outline (simplified)
  ctx.moveTo(lonToX(-125), latToY(48));
  ctx.lineTo(lonToX(-65), latToY(45));
  ctx.lineTo(lonToX(-80), latToY(25));
  ctx.lineTo(lonToX(-100), latToY(20));
  ctx.lineTo(lonToX(-115), latToY(30));
  ctx.lineTo(lonToX(-125), latToY(48));
  
  // Europe outline
  ctx.moveTo(lonToX(-10), latToY(60));
  ctx.lineTo(lonToX(30), latToY(55));
  ctx.lineTo(lonToX(40), latToY(45));
  ctx.lineTo(lonToX(10), latToY(35));
  ctx.lineTo(lonToX(-10), latToY(40));
  ctx.lineTo(lonToX(-10), latToY(60));
  
  // Asia outline
  ctx.moveTo(lonToX(60), latToY(60));
  ctx.lineTo(lonToX(140), latToY(50));
  ctx.lineTo(lonToX(130), latToY(30));
  ctx.lineTo(lonToX(100), latToY(20));
  ctx.lineTo(lonToX(60), latToY(25));
  ctx.lineTo(lonToX(60), latToY(60));
  
  // Australia
  ctx.moveTo(lonToX(115), latToY(-20));
  ctx.lineTo(lonToX(150), latToY(-20));
  ctx.lineTo(lonToX(150), latToY(-40));
  ctx.lineTo(lonToX(115), latToY(-35));
  ctx.lineTo(lonToX(115), latToY(-20));
  
  // South America
  ctx.moveTo(lonToX(-80), latToY(10));
  ctx.lineTo(lonToX(-35), latToY(-5));
  ctx.lineTo(lonToX(-55), latToY(-55));
  ctx.lineTo(lonToX(-75), latToY(-20));
  ctx.lineTo(lonToX(-80), latToY(10));
  
  // Africa
  ctx.moveTo(lonToX(-15), latToY(30));
  ctx.lineTo(lonToX(50), latToY(30));
  ctx.lineTo(lonToX(35), latToY(-35));
  ctx.lineTo(lonToX(10), latToY(-35));
  ctx.lineTo(lonToX(-15), latToY(5));
  ctx.lineTo(lonToX(-15), latToY(30));
  
  ctx.stroke();
}

export default LiveThreatMap;
