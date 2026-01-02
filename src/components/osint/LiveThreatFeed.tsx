// src/components/osint/LiveThreatFeed.tsx
// REAL-TIME THREAT INTELLIGENCE VISUALIZATION WITH LEAFLET MAPS
// Integrates APTmap, MISP feeds, and LLM processing

import { useState, useEffect, useRef } from 'react';
import { Activity, RefreshCw, Globe, Zap, AlertTriangle, MapPin, Target, Shield, Users, Layers } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { fetchLiveThreatMap, ThreatPoint } from '@/services/realTimeThreatService';
import { getAPTThreatMapData, fetchAPTMapData, getAPTStats, type APTThreatPoint } from '@/services/aptMapService';
import { fetchAllThreatFeeds, getMalwareThreatMapData, type ThreatFeedSummary, type MalwareThreatPoint } from '@/services/mispFeedService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

// Extended union type for combined threat points with optional properties
type CombinedThreatPoint = (ThreatPoint | APTThreatPoint | MalwareThreatPoint) & {
  aptName?: string;
  malwareFamily?: string;
  aliases?: string[];
  count?: number;
  threatType?: string;
  type?: string;
  city?: string;
  indicator?: string;
  source?: string;
  timestamp?: string;
};

// Add Leaflet styling to document head
if (typeof document !== 'undefined') {
  const leafletStyle = document.createElement('style');
  leafletStyle.textContent = `
    .custom-threat-popup .leaflet-popup-content-wrapper {
      background: #1e293b !important;
      color: #fff !important;
      border-radius: 8px !important;
      padding: 0 !important;
    }
    .custom-threat-popup .leaflet-popup-tip {
      background: #1e293b !important;
    }
    .custom-threat-marker {
      border: none !important;
      background: transparent !important;
    }
    .leaflet-container {
      background: #0a0e27 !important;
    }
    .leaflet-control-zoom {
      background: rgba(30, 41, 59, 0.9) !important;
      border: 1px solid rgba(59, 130, 246, 0.3) !important;
    }
    .leaflet-control-zoom a {
      background: transparent !important;
      color: #fff !important;
      border-bottom: 1px solid rgba(59, 130, 246, 0.3) !important;
    }
    .leaflet-control-zoom a:hover {
      background: rgba(59, 130, 246, 0.2) !important;
    }
  `;
  if (!document.querySelector('#leaflet-threat-styles')) {
    leafletStyle.id = 'leaflet-threat-styles';
    document.head.appendChild(leafletStyle);
  }
}

/* ============================================================================
   LEAFLET MAP COMPONENT FOR THREAT VISUALIZATION
============================================================================ */

interface LeafletThreatMapProps {
  threats: CombinedThreatPoint[];
  activeView: 'all' | 'apt' | 'malware' | 'c2';
  mapStyle: 'dark' | 'satellite' | 'street';
  onThreatClick?: (threat: CombinedThreatPoint) => void;
}

function LeafletThreatMap({ threats, activeView, mapStyle, onThreatClick }: LeafletThreatMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const markersRef = useRef<any[]>([]);

  useEffect(() => {
    if (!mapRef.current) return;

    // Initialize map if not already created
    if (!mapInstanceRef.current) {
      mapInstanceRef.current = createLeafletMap(mapRef.current, mapStyle);
    }

    // Clear existing markers
    markersRef.current.forEach(marker => marker.remove());
    markersRef.current = [];

    // Filter threats based on active view
    const filteredThreats = filterThreatsByView(threats, activeView);

    // Add threat markers
    filteredThreats.forEach(threat => {
      const marker = createThreatMarker(threat, onThreatClick);
      if (marker) {
        markersRef.current.push(marker);
        marker.addTo(mapInstanceRef.current);
      }
    });

  }, [threats, activeView, mapStyle, onThreatClick]);

  // Update map style when changed
  useEffect(() => {
    if (mapInstanceRef.current && typeof window !== 'undefined' && (window as any).L) {
      const L = (window as any).L;
      
      // Remove existing tile layers
      mapInstanceRef.current.eachLayer((layer: any) => {
        if (layer instanceof L.TileLayer) {
          mapInstanceRef.current.removeLayer(layer);
        }
      });

      // Add new tile layer based on style
      let tileLayer;
      switch (mapStyle) {
        case 'dark':
          tileLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
            subdomains: 'abcd',
            maxZoom: 18
          });
          break;
        case 'satellite':
          tileLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
            attribution: 'Tiles &copy; Esri',
            maxZoom: 18
          });
          break;
        case 'street':
          tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 18
          });
          break;
      }
      
      tileLayer.addTo(mapInstanceRef.current);
    }
  }, [mapStyle]);

  return <div ref={mapRef} style={{ height: '600px', width: '100%' }} className="rounded-lg overflow-hidden" />;
}

// Leaflet map creation with style support
function createLeafletMap(container: HTMLElement, mapStyle: 'dark' | 'satellite' | 'street' = 'dark') {
  // Create script and link elements for Leaflet
  if (!document.querySelector('link[href*="leaflet.css"]')) {
    const link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
    document.head.appendChild(link);
  }

  if (!document.querySelector('script[src*="leaflet.js"]')) {
    const script = document.createElement('script');
    script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
    document.head.appendChild(script);
  }

  // Wait for Leaflet to load, then create map
  const checkLeaflet = () => {
    if (typeof window !== 'undefined' && (window as any).L) {
      const L = (window as any).L;
      const map = L.map(container).setView([20, 0], 2);
      
      // Add tile layer based on style
      let tileLayer;
      switch (mapStyle) {
        case 'dark':
          tileLayer = L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; OpenStreetMap contributors &copy; CARTO',
            subdomains: 'abcd',
            maxZoom: 18
          });
          break;
        case 'satellite':
          tileLayer = L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', {
            attribution: 'Tiles &copy; Esri',
            maxZoom: 18
          });
          break;
        case 'street':
          tileLayer = L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            attribution: '&copy; OpenStreetMap contributors',
            maxZoom: 18
          });
          break;
      }
      
      tileLayer.addTo(map);
      return map;
    } else {
      setTimeout(checkLeaflet, 100);
      return null;
    }
  };

  return checkLeaflet();
}

function filterThreatsByView(threats: CombinedThreatPoint[], activeView: 'all' | 'apt' | 'malware' | 'c2'): CombinedThreatPoint[] {
  if (activeView === 'all') return threats;
  
  return threats.filter(threat => {
    if (activeView === 'apt') return 'aptName' in threat;
    if (activeView === 'malware') return 'malwareFamily' in threat;
    if (activeView === 'c2') return 'threatType' in threat;
    return false;
  });
}

function createThreatMarker(threat: CombinedThreatPoint, onClick?: (threat: CombinedThreatPoint) => void) {
  if (typeof window === 'undefined' || !(window as any).L) return null;
  
  const L = (window as any).L;
  
  // Determine threat type and styling - check for name property (APTThreatPoint) or aptName
  const isAPT = 'name' in threat && 'aliasCount' in threat;
  const isMalware = 'malwareFamily' in threat && !isAPT;
  const threatTypeValue = isAPT ? 'apt' : isMalware ? 'malware' : 'c2';
  
  const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  };
  
  const color = severityColors[threat.severity];
  // Use count from ThreatPoint, or default to 1
  const threatCount = 'count' in threat ? (threat.count || 1) : 1;
  const size = Math.min(12 + threatCount * 2, 24);
  
  // Create custom icon based on threat type
  let iconHtml = '';
  
  if (threatTypeValue === 'apt') {
    // Triangle for APT groups
    iconHtml = `
      <div style="
        width: 0;
        height: 0;
        border-left: ${size/2}px solid transparent;
        border-right: ${size/2}px solid transparent;
        border-bottom: ${size}px solid ${color};
        filter: drop-shadow(0 0 6px ${color});
        ${threat.severity === 'critical' ? 'animation: pulse 2s infinite;' : ''}
      "></div>
    `;
  } else if (threatTypeValue === 'malware') {
    // Square for malware
    iconHtml = `
      <div style="
        width: ${size}px;
        height: ${size}px;
        background: ${color};
        border: 2px solid rgba(255,255,255,0.8);
        filter: drop-shadow(0 0 6px ${color});
        ${threat.severity === 'critical' ? 'animation: pulse 2s infinite;' : ''}
      "></div>
    `;
  } else {
    // Circle for C2 servers
    iconHtml = `
      <div style="
        width: ${size}px;
        height: ${size}px;
        background: ${color};
        border-radius: 50%;
        border: 2px solid rgba(255,255,255,0.8);
        filter: drop-shadow(0 0 6px ${color});
        ${threat.severity === 'critical' ? 'animation: pulse 2s infinite;' : ''}
      "></div>
    `;
  }
  
  // Add count label if > 1
  if (threatCount > 1) {
    iconHtml += `
      <div style="
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        color: white;
        font-size: 10px;
        font-weight: bold;
        text-shadow: 1px 1px 2px rgba(0,0,0,0.8);
      ">${threatCount}</div>
    `;
  }
  
  // Add pulsing animation CSS
  iconHtml += `
    <style>
      @keyframes pulse {
        0% { transform: scale(1); opacity: 1; }
        50% { transform: scale(1.3); opacity: 0.7; }
        100% { transform: scale(1); opacity: 1; }
      }
    </style>
  `;

  const icon = L.divIcon({
    className: 'custom-threat-marker',
    html: iconHtml,
    iconSize: [size + 8, size + 8],
    iconAnchor: [(size + 8) / 2, (size + 8) / 2],
  });

  const marker = L.marker([threat.lat, threat.lon], { icon });
  
  // Create detailed popup content
  const threatName = 'aptName' in threat ? threat.aptName : 
                    'malwareFamily' in threat ? threat.malwareFamily :
                    'threatType' in threat ? threat.threatType : 'Unknown';
                    
  const popupContent = `
    <div style="color: #fff; background: #1e293b; padding: 12px; border-radius: 8px; min-width: 200px;">
      <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
        <span style="
          background: ${color}; 
          color: white; 
          padding: 2px 6px; 
          border-radius: 4px; 
          font-size: 10px; 
          font-weight: bold;
        ">${threat.severity.toUpperCase()}</span>
        <h3 style="margin: 0; color: ${color}; font-size: 14px;">${threatName}</h3>
      </div>
      
      <div style="font-size: 12px; line-height: 1.4; color: #cbd5e1;">
        <div style="margin: 4px 0;"><strong>Location:</strong> ${'city' in threat ? `${threat.city}, ` : ''}${threat.country}</div>
        
        ${'indicator' in threat ? `
          <div style="margin: 4px 0;"><strong>Indicator:</strong><br>
            <code style="font-family: monospace; background: #334155; padding: 2px 4px; border-radius: 3px; font-size: 11px; word-break: break-all;">${threat.indicator}</code>
          </div>
        ` : ''}
        
        ${'aptName' in threat ? `
          <div style="margin: 4px 0;"><strong>APT Group:</strong> ${threat.aptName}</div>
          <div style="margin: 4px 0;"><strong>Aliases:</strong> ${threat.aliases?.slice(0, 3).join(', ') || 'None'}</div>
        ` : ''}
        
        ${'malwareFamily' in threat ? `
          <div style="margin: 4px 0;"><strong>Malware:</strong> ${threat.malwareFamily}</div>
          <div style="margin: 4px 0;"><strong>Type:</strong> ${threat.type || 'Unknown'}</div>
        ` : ''}
        
        ${'source' in threat ? `<div style="margin: 4px 0;"><strong>Source:</strong> ${threat.source}</div>` : ''}
        
        <div style="margin: 4px 0;"><strong>Incidents:</strong> ${threat.count || 1}</div>
        
        ${'timestamp' in threat ? `
          <div style="margin: 6px 0 0 0; color: #94a3b8; font-size: 11px;">
            ${new Date(threat.timestamp).toLocaleString()}
          </div>
        ` : ''}
      </div>
    </div>
  `;

  marker.bindPopup(popupContent, {
    maxWidth: 300,
    className: 'custom-threat-popup'
  });
  
  if (onClick) {
    marker.on('click', () => onClick(threat));
  }

  return marker;
}

// Main LiveThreatFeed component
export function LiveThreatFeed() {
  // Data state management
  const [threats, setThreats] = useState<ThreatPoint[]>([]);
  const [aptThreats, setAptThreats] = useState<APTThreatPoint[]>([]);
  const [malwareThreats, setMalwareThreats] = useState<MalwareThreatPoint[]>([]);
  const [feedSummary, setFeedSummary] = useState<ThreatFeedSummary | null>(null);
  const [aptStats, setAptStats] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  
  // Map control state
  const [activeView, setActiveView] = useState<'all' | 'apt' | 'malware' | 'c2'>('all');
  const [mapStyle, setMapStyle] = useState<'dark' | 'satellite' | 'street'>('dark');
  const [selectedThreat, setSelectedThreat] = useState<CombinedThreatPoint | null>(null);
  const [combinedThreats, setCombinedThreats] = useState<CombinedThreatPoint[]>([]);

  useEffect(() => {
    loadAllThreats();
  }, []);

  useEffect(() => {
    if (autoRefresh) {
      const interval = setInterval(loadAllThreats, 300000); // 5 minutes
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  // Combine all threat data when any source updates
  useEffect(() => {
    const combined: CombinedThreatPoint[] = [
      ...threats,
      ...aptThreats,
      ...malwareThreats
    ];
    setCombinedThreats(combined);
  }, [threats, aptThreats, malwareThreats]);

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

  const handleThreatClick = (threat: CombinedThreatPoint) => {
    setSelectedThreat(threat);
    const threatName = 'aptName' in threat ? threat.aptName : 
                      'malwareFamily' in threat ? threat.malwareFamily :
                      threat.threatType || 'Unknown';
    toast.info(`Selected: ${threatName} - ${threat.severity.toUpperCase()} threat in ${threat.country}`);
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

      {/* Interactive Map */}
      <Card className="bg-card border-border">
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="flex items-center gap-2 text-foreground">
            <MapPin className="h-5 w-5 text-primary" />
            Global Threat Distribution
          </CardTitle>
          
          {/* Map Style Controls */}
          <div className="flex items-center gap-2">
            <div className="text-sm text-muted-foreground flex items-center gap-2">
              <Layers className="h-4 w-4" />
              Map Style:
            </div>
            <div className="flex gap-1">
              {(['dark', 'satellite', 'street'] as const).map((style) => (
                <Button
                  key={style}
                  variant={mapStyle === style ? 'default' : 'outline'}
                  size="sm"
                  onClick={() => setMapStyle(style)}
                  className="capitalize px-3 py-1 h-8"
                >
                  {style}
                </Button>
              ))}
            </div>
          </div>
        </CardHeader>
        <CardContent className="relative p-4">
          <LeafletThreatMap 
            threats={combinedThreats}
            activeView={activeView}
            mapStyle={mapStyle}
            onThreatClick={handleThreatClick}
          />

          
          {/* Selected Threat Info Panel */}
          {selectedThreat && (
            <div className="mt-4 bg-secondary/50 border border-border rounded-lg p-4">
              <h3 className="font-semibold text-foreground flex items-center gap-2 mb-3">
                <Badge className={cn(
                  selectedThreat.severity === 'critical' ? 'bg-red-500' :
                  selectedThreat.severity === 'high' ? 'bg-orange-500' :
                  selectedThreat.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-500'
                )}>
                  {selectedThreat.severity.toUpperCase()}
                </Badge>
                Selected Threat Details
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedThreat(null)}
                  className="ml-auto h-6 w-6 p-0"
                >
                  ×
                </Button>
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                <div>
                  <div className="font-medium mb-2">Threat Information</div>
                  <div className="space-y-1 text-muted-foreground">
                    <div><strong>Type:</strong> 
                      {'threatType' in selectedThreat ? selectedThreat.threatType : 
                       'aptName' in selectedThreat ? 'APT Group' :
                       'malwareFamily' in selectedThreat ? 'Malware' : 'Unknown'}
                    </div>
                    <div><strong>Name:</strong> 
                      {'aptName' in selectedThreat ? selectedThreat.aptName : 
                       'malwareFamily' in selectedThreat ? selectedThreat.malwareFamily :
                       selectedThreat.threatType || 'Unknown'}
                    </div>
                    <div><strong>Location:</strong> {'city' in selectedThreat ? `${selectedThreat.city}, ` : ''}{selectedThreat.country}</div>
                    <div><strong>Incidents:</strong> {selectedThreat.count || 1}</div>
                  </div>
                </div>
                
                <div>
                  <div className="font-medium mb-2">Additional Details</div>
                  <div className="space-y-1 text-muted-foreground">
                    {'indicator' in selectedThreat && (
                      <div><strong>Indicator:</strong> 
                        <code className="ml-2 font-mono bg-background px-2 py-1 rounded text-xs break-all">
                          {selectedThreat.indicator}
                        </code>
                      </div>
                    )}
                    {'aptName' in selectedThreat && selectedThreat.aliases && (
                      <div><strong>Aliases:</strong> {selectedThreat.aliases.slice(0, 3).join(', ')}</div>
                    )}
                    {'malwareFamily' in selectedThreat && selectedThreat.type && (
                      <div><strong>Malware Type:</strong> {selectedThreat.type}</div>
                    )}
                    {'source' in selectedThreat && (
                      <div><strong>Source:</strong> {selectedThreat.source}</div>
                    )}
                    {'timestamp' in selectedThreat && (
                      <div><strong>Last Seen:</strong> {new Date(selectedThreat.timestamp).toLocaleString()}</div>
                    )}
                  </div>
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
