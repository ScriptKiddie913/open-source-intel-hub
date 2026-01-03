// src/components/osint/LiveThreatFeed.tsx
// REAL-TIME THREAT INTELLIGENCE VISUALIZATION WITH LEAFLET MAPS
// Integrates APTmap, MISP feeds, and LLM processing

import { useState, useEffect, useRef } from 'react';
import { Activity, RefreshCw, Globe, Zap, AlertTriangle, MapPin, Target, Shield, Users, Layers, Search, X, Hash, FileType, Lock, Database, ExternalLink, Code, Crosshair, Building, Calendar, Link2, Wrench, FileText, Info } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Input } from '@/components/ui/input';
import { fetchLiveThreatMap, ThreatPoint } from '@/services/realTimeThreatService';
import { getAPTThreatMapData, fetchAPTMapData, getAPTStats, searchAPTGroups, searchMalwareData, getMalwareStats, getAPTGroupByName, type APTThreatPoint, type APTSearchResult, type MalwareSearchResult, type APTGroup } from '@/services/aptMapService';
import { fetchAllThreatFeeds, getMalwareThreatMapData, type ThreatFeedSummary, type MalwareThreatPoint } from '@/services/mispFeedService';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';

type CombinedThreatPoint = ThreatPoint | APTThreatPoint | MalwareThreatPoint;

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
  
  // Determine threat type and styling
  const threatType = 'aptName' in threat ? 'apt' : 'malwareFamily' in threat ? 'malware' : 'c2';
  const severityColors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
  };
  
  const color = severityColors[threat.severity];
  const size = Math.min(12 + (threat.count || 1) * 2, 24);
  
  // Create custom icon based on threat type
  let iconHtml = '';
  
  if (threatType === 'apt') {
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
  } else if (threatType === 'malware') {
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
  if ((threat.count || 0) > 1) {
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
      ">${threat.count}</div>
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

  // Search state
  const [searchQuery, setSearchQuery] = useState('');
  const [searchType, setSearchType] = useState<'apt' | 'malware'>('apt');
  const [aptSearchResults, setAptSearchResults] = useState<APTSearchResult | null>(null);
  const [malwareSearchResults, setMalwareSearchResults] = useState<MalwareSearchResult | null>(null);
  const [isSearching, setIsSearching] = useState(false);
  const [showSearchResults, setShowSearchResults] = useState(false);

  // APT Detail popup state
  const [selectedAPTGroup, setSelectedAPTGroup] = useState<APTGroup | null>(null);
  const [showAPTDetailPopup, setShowAPTDetailPopup] = useState(false);
  const [loadingAPTDetails, setLoadingAPTDetails] = useState(false);

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

  // Search handler
  const handleSearch = async () => {
    if (!searchQuery.trim()) {
      toast.error('Please enter a search term');
      return;
    }

    setIsSearching(true);
    setShowSearchResults(true);

    try {
      if (searchType === 'apt') {
        const results = await searchAPTGroups(searchQuery);
        setAptSearchResults(results);
        setMalwareSearchResults(null);
        toast.success(`Found ${results.totalCount} APT groups matching "${searchQuery}"`);
      } else {
        const results = await searchMalwareData(searchQuery);
        setMalwareSearchResults(results);
        setAptSearchResults(null);
        toast.success(`Found ${results.totalMatches} malware data entries matching "${searchQuery}"`);
      }
    } catch (error) {
      console.error('Search failed:', error);
      toast.error('Search failed. Please try again.');
    } finally {
      setIsSearching(false);
    }
  };

  const clearSearch = () => {
    setSearchQuery('');
    setAptSearchResults(null);
    setMalwareSearchResults(null);
    setShowSearchResults(false);
  };

  const handleThreatClick = async (threat: CombinedThreatPoint) => {
    setSelectedThreat(threat);
    const threatName = 'name' in threat ? threat.name : 
                      'malwareFamily' in threat ? threat.malwareFamily :
                      'Unknown';
    
    // If it's an APT threat, fetch full details
    if ('type' in threat && threat.type === 'apt' && 'name' in threat) {
      setLoadingAPTDetails(true);
      try {
        const fullDetails = await getAPTGroupByName(threat.name);
        if (fullDetails) {
          setSelectedAPTGroup(fullDetails);
          setShowAPTDetailPopup(true);
          toast.success(`Loaded full details for ${fullDetails.name}`);
        } else {
          toast.info(`Selected: ${threatName} - ${threat.severity.toUpperCase()} threat`);
        }
      } catch (error) {
        console.error('Failed to load APT details:', error);
        toast.error('Failed to load APT group details');
      } finally {
        setLoadingAPTDetails(false);
      }
    } else {
      toast.info(`Selected: ${threatName} - ${threat.severity.toUpperCase()} threat in ${threat.country}`);
    }
  };

  const closeAPTDetailPopup = () => {
    setShowAPTDetailPopup(false);
    setSelectedAPTGroup(null);
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
      {/* Loading Overlay for APT Details */}
      {loadingAPTDetails && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-[9998]">
          <div className="bg-card border border-border rounded-lg p-6 flex items-center gap-3">
            <RefreshCw className="h-6 w-6 text-primary animate-spin" />
            <span className="text-foreground">Loading APT Group Details...</span>
          </div>
        </div>
      )}

      {/* APT Group Detail Popup Modal */}
      {showAPTDetailPopup && selectedAPTGroup && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[9999] p-4">
          <div className="bg-card border border-border rounded-xl w-full max-w-4xl max-h-[90vh] overflow-hidden shadow-2xl">
            {/* Header */}
            <div className="bg-gradient-to-r from-purple-600/20 to-blue-600/20 border-b border-border p-4">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <div className="bg-purple-500/20 p-2 rounded-lg">
                    <Users className="h-6 w-6 text-purple-400" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold text-foreground">{selectedAPTGroup.name}</h2>
                    <div className="flex items-center gap-2 mt-1">
                      <Badge className={selectedAPTGroup.active ? 'bg-green-500' : 'bg-gray-500'}>
                        {selectedAPTGroup.active ? 'Active' : 'Inactive'}
                      </Badge>
                      <Badge variant="outline" className="text-xs">
                        {selectedAPTGroup.country}
                      </Badge>
                      {selectedAPTGroup.sponsor && (
                        <Badge variant="outline" className="text-xs bg-red-500/10 text-red-400">
                          State-Sponsored: {selectedAPTGroup.sponsor}
                        </Badge>
                      )}
                    </div>
                  </div>
                </div>
                <Button variant="ghost" size="sm" onClick={closeAPTDetailPopup} className="h-8 w-8 p-0">
                  <X className="h-5 w-5" />
                </Button>
              </div>
            </div>

            {/* Content */}
            <div className="overflow-y-auto max-h-[calc(90vh-120px)] p-4 space-y-4">
              {/* Aliases */}
              {selectedAPTGroup.aliases.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Info className="h-4 w-4 text-primary" />
                    Also Known As
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAPTGroup.aliases.map((alias, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {alias}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Description */}
              <div className="bg-secondary/30 rounded-lg p-3">
                <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                  <FileText className="h-4 w-4 text-primary" />
                  Description
                </div>
                <p className="text-sm text-muted-foreground leading-relaxed whitespace-pre-wrap">
                  {selectedAPTGroup.description || 'No description available.'}
                </p>
              </div>

              {/* Key Details Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <Card className="bg-secondary/30">
                  <CardContent className="p-3 text-center">
                    <Building className="h-4 w-4 mx-auto mb-1 text-blue-400" />
                    <div className="text-lg font-bold text-foreground">{selectedAPTGroup.country}</div>
                    <div className="text-xs text-muted-foreground">Origin Country</div>
                  </CardContent>
                </Card>
                <Card className="bg-secondary/30">
                  <CardContent className="p-3 text-center">
                    <Wrench className="h-4 w-4 mx-auto mb-1 text-orange-400" />
                    <div className="text-lg font-bold text-foreground">{selectedAPTGroup.tools.length}</div>
                    <div className="text-xs text-muted-foreground">Tools Used</div>
                  </CardContent>
                </Card>
                <Card className="bg-secondary/30">
                  <CardContent className="p-3 text-center">
                    <Crosshair className="h-4 w-4 mx-auto mb-1 text-red-400" />
                    <div className="text-lg font-bold text-foreground">{selectedAPTGroup.targets.length}</div>
                    <div className="text-xs text-muted-foreground">Target Countries</div>
                  </CardContent>
                </Card>
                <Card className="bg-secondary/30">
                  <CardContent className="p-3 text-center">
                    <Code className="h-4 w-4 mx-auto mb-1 text-cyan-400" />
                    <div className="text-lg font-bold text-foreground">{selectedAPTGroup.ttps.length}</div>
                    <div className="text-xs text-muted-foreground">TTPs</div>
                  </CardContent>
                </Card>
              </div>

              {/* Motivations */}
              {selectedAPTGroup.motivations.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Target className="h-4 w-4 text-primary" />
                    Motivations
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAPTGroup.motivations.map((motivation, idx) => (
                      <Badge key={idx} className="bg-purple-500/20 text-purple-300 text-xs">
                        {motivation}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Target Sectors */}
              {selectedAPTGroup.targetCategories.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Crosshair className="h-4 w-4 text-red-400" />
                    Target Sectors
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAPTGroup.targetCategories.map((sector, idx) => (
                      <Badge key={idx} className="bg-red-500/20 text-red-300 text-xs">
                        {sector}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Target Countries */}
              {selectedAPTGroup.targets.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Globe className="h-4 w-4 text-green-400" />
                    Target Countries/Regions
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {selectedAPTGroup.targets.map((target, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {target}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Tools & Malware */}
              {selectedAPTGroup.tools.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Wrench className="h-4 w-4 text-orange-400" />
                    Tools & Malware
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-48 overflow-y-auto">
                    {selectedAPTGroup.tools.map((tool, idx) => (
                      <div key={idx} className="bg-background/50 rounded p-2">
                        <div className="font-medium text-sm text-foreground">{tool.name}</div>
                        {tool.category && (
                          <Badge variant="outline" className="text-xs mt-1">{tool.category}</Badge>
                        )}
                        {tool.description && (
                          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{tool.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* TTPs (MITRE ATT&CK) */}
              {selectedAPTGroup.ttps.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Code className="h-4 w-4 text-cyan-400" />
                    MITRE ATT&CK TTPs
                  </div>
                  <div className="flex flex-wrap gap-1 max-h-32 overflow-y-auto">
                    {selectedAPTGroup.ttps.map((ttp, idx) => (
                      <a
                        key={idx}
                        href={`https://attack.mitre.org/techniques/${ttp.techniqueID.replace('.', '/')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs bg-cyan-500/20 text-cyan-300 px-2 py-1 rounded hover:bg-cyan-500/30 transition-colors"
                      >
                        {ttp.techniqueID}
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Operations */}
              {selectedAPTGroup.operations.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Calendar className="h-4 w-4 text-yellow-400" />
                    Known Operations/Campaigns
                  </div>
                  <div className="space-y-1">
                    {selectedAPTGroup.operations.map((op, idx) => (
                      <div key={idx} className="text-sm text-muted-foreground bg-background/50 rounded px-2 py-1">
                        • {op}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* External Links */}
              {selectedAPTGroup.externalLinks.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Link2 className="h-4 w-4 text-blue-400" />
                    External References & Reports
                  </div>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {selectedAPTGroup.externalLinks.map((link, idx) => (
                      <a
                        key={idx}
                        href={link.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-start gap-2 text-sm text-blue-400 hover:text-blue-300 bg-background/50 rounded p-2 transition-colors"
                      >
                        <ExternalLink className="h-4 w-4 mt-0.5 flex-shrink-0" />
                        <div>
                          <div className="break-all">{link.description || link.url}</div>
                          {link.description && (
                            <div className="text-xs text-muted-foreground break-all">{link.url}</div>
                          )}
                        </div>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Sources */}
              {selectedAPTGroup.sources.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Database className="h-4 w-4 text-purple-400" />
                    Data Sources
                  </div>
                  <div className="space-y-2">
                    {selectedAPTGroup.sources.map((source, idx) => (
                      <div key={idx} className="bg-background/50 rounded p-2">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm text-foreground">{source.name}</span>
                          {source.url && (
                            <a
                              href={source.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-blue-400 hover:text-blue-300"
                            >
                              <ExternalLink className="h-3 w-3" />
                            </a>
                          )}
                        </div>
                        {source.description && (
                          <p className="text-xs text-muted-foreground mt-1">{source.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Malware Samples */}
              {selectedAPTGroup.malwareSamples.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <AlertTriangle className="h-4 w-4 text-red-400" />
                    Malware Samples
                  </div>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {selectedAPTGroup.malwareSamples.map((sample, idx) => (
                      <div key={idx} className="bg-background/50 rounded p-2">
                        <div className="text-sm text-foreground">{sample.description}</div>
                        {sample.hash && (
                          <code className="text-xs text-orange-400 font-mono break-all">
                            Hash: {sample.hash}
                          </code>
                        )}
                        {sample.url && (
                          <a
                            href={sample.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 mt-1"
                          >
                            <ExternalLink className="h-3 w-3" />
                            View Sample
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* IOCs */}
              {selectedAPTGroup.iocs.length > 0 && (
                <div className="bg-secondary/30 rounded-lg p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-foreground mb-2">
                    <Hash className="h-4 w-4 text-orange-400" />
                    Indicators of Compromise (IOCs)
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-1 max-h-32 overflow-y-auto">
                    {selectedAPTGroup.iocs.map((ioc, idx) => (
                      <code key={idx} className="text-xs text-orange-300 font-mono bg-background/50 rounded px-2 py-1 break-all">
                        {ioc}
                      </code>
                    ))}
                  </div>
                </div>
              )}

              {/* Metadata Footer */}
              <div className="border-t border-border pt-3 mt-4 flex items-center justify-between text-xs text-muted-foreground">
                <div className="flex items-center gap-4">
                  <span><strong>UUID:</strong> {selectedAPTGroup.uuid}</span>
                  {selectedAPTGroup.firstSeen && (
                    <span><strong>First Seen:</strong> {selectedAPTGroup.firstSeen}</span>
                  )}
                  <span><strong>Confidence:</strong> {selectedAPTGroup.attributionConfidence}%</span>
                </div>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={closeAPTDetailPopup}>
                    Close
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

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

      {/* Search Section */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-foreground text-lg">
            <Search className="h-5 w-5 text-primary" />
            Search Threat Intelligence
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-3">
            {/* Search Type Toggle */}
            <div className="flex gap-2">
              <Button
                variant={searchType === 'apt' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSearchType('apt')}
              >
                <Users className="h-4 w-4 mr-2" />
                APT Groups
              </Button>
              <Button
                variant={searchType === 'malware' ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSearchType('malware')}
              >
                <Database className="h-4 w-4 mr-2" />
                Malware Data
              </Button>
            </div>
            
            {/* Search Input */}
            <div className="flex-1 flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder={searchType === 'apt' 
                    ? "Search APT groups by name, country, target sector, tools..." 
                    : "Search malware hashes, file types, imports, certificates..."}
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                  className="pl-10 bg-background"
                />
                {searchQuery && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={clearSearch}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 h-6 w-6 p-0"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                )}
              </div>
              <Button onClick={handleSearch} disabled={isSearching}>
                {isSearching ? (
                  <RefreshCw className="h-4 w-4 animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                <span className="ml-2">Search</span>
              </Button>
            </div>
          </div>

          {/* Search Results */}
          {showSearchResults && (
            <div className="mt-4 border-t border-border pt-4">
              {/* APT Search Results */}
              {aptSearchResults && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold text-foreground">
                      Found {aptSearchResults.totalCount} APT Groups
                    </h3>
                    <Button variant="ghost" size="sm" onClick={clearSearch}>
                      <X className="h-4 w-4 mr-1" /> Clear
                    </Button>
                  </div>
                  
                  {aptSearchResults.groups.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 max-h-96 overflow-y-auto">
                      {aptSearchResults.groups.map((group) => (
                        <Card 
                          key={group.id} 
                          className="bg-secondary/50 border-border hover:border-primary/50 transition-colors cursor-pointer"
                          onClick={async () => {
                            setLoadingAPTDetails(true);
                            try {
                              const fullDetails = await getAPTGroupByName(group.name);
                              if (fullDetails) {
                                setSelectedAPTGroup(fullDetails);
                                setShowAPTDetailPopup(true);
                              }
                            } catch (error) {
                              console.error('Failed to load APT details:', error);
                              toast.error('Failed to load APT group details');
                            } finally {
                              setLoadingAPTDetails(false);
                            }
                          }}
                        >
                          <CardContent className="p-3">
                            <div className="flex items-start justify-between mb-2">
                              <div className="font-medium text-foreground">{group.name}</div>
                              <Badge variant={group.active ? 'default' : 'secondary'} className="text-xs">
                                {group.active ? 'Active' : 'Inactive'}
                              </Badge>
                            </div>
                            <div className="text-xs text-muted-foreground space-y-1">
                              <div><strong>Country:</strong> {group.country}</div>
                              {group.aliases.length > 0 && (
                                <div><strong>Aliases:</strong> {group.aliases.slice(0, 3).join(', ')}</div>
                              )}
                              {group.targetCategories.length > 0 && (
                                <div><strong>Targets:</strong> {group.targetCategories.slice(0, 3).join(', ')}</div>
                              )}
                              {group.tools.length > 0 && (
                                <div><strong>Tools:</strong> {group.tools.slice(0, 3).map(t => t.name).join(', ')}</div>
                              )}
                            </div>
                            {group.description && (
                              <p className="text-xs text-muted-foreground mt-2 line-clamp-2">
                                {group.description.slice(0, 150)}...
                              </p>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">
                      No APT groups found matching "{searchQuery}"
                    </div>
                  )}

                  {/* Statistics */}
                  {aptSearchResults.totalCount > 0 && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                      <Card className="bg-secondary/30">
                        <CardContent className="p-3 text-center">
                          <div className="text-lg font-bold text-purple-500">{aptSearchResults.activeGroups}</div>
                          <div className="text-xs text-muted-foreground">Active Groups</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-secondary/30">
                        <CardContent className="p-3 text-center">
                          <div className="text-lg font-bold text-cyan-500">{Object.keys(aptSearchResults.byCountry).length}</div>
                          <div className="text-xs text-muted-foreground">Countries</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-secondary/30">
                        <CardContent className="p-3 text-center">
                          <div className="text-lg font-bold text-orange-500">{Object.keys(aptSearchResults.byTargetSector).length}</div>
                          <div className="text-xs text-muted-foreground">Target Sectors</div>
                        </CardContent>
                      </Card>
                      <Card className="bg-secondary/30">
                        <CardContent className="p-3 text-center">
                          <div className="text-lg font-bold text-primary">{aptSearchResults.totalCount}</div>
                          <div className="text-xs text-muted-foreground">Total Matches</div>
                        </CardContent>
                      </Card>
                    </div>
                  )}
                </div>
              )}

              {/* Malware Search Results */}
              {malwareSearchResults && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold text-foreground">
                      Found {malwareSearchResults.totalMatches} Malware Data Entries
                    </h3>
                    <Button variant="ghost" size="sm" onClick={clearSearch}>
                      <X className="h-4 w-4 mr-1" /> Clear
                    </Button>
                  </div>

                  {malwareSearchResults.totalMatches > 0 ? (
                    <Tabs defaultValue="hashes" className="w-full">
                      <TabsList className="grid w-full grid-cols-4">
                        <TabsTrigger value="hashes" className="flex items-center gap-1">
                          <Hash className="h-3 w-3" />
                          Hashes ({malwareSearchResults.hashes.length})
                        </TabsTrigger>
                        <TabsTrigger value="filetypes" className="flex items-center gap-1">
                          <FileType className="h-3 w-3" />
                          File Types ({malwareSearchResults.fileTypes.length})
                        </TabsTrigger>
                        <TabsTrigger value="imports" className="flex items-center gap-1">
                          <Database className="h-3 w-3" />
                          Imports ({malwareSearchResults.imports.length})
                        </TabsTrigger>
                        <TabsTrigger value="certificates" className="flex items-center gap-1">
                          <Lock className="h-3 w-3" />
                          Certs ({malwareSearchResults.certificates.length})
                        </TabsTrigger>
                      </TabsList>

                      <TabsContent value="hashes" className="mt-4">
                        {malwareSearchResults.hashes.length > 0 ? (
                          <div className="space-y-2 max-h-64 overflow-y-auto">
                            {malwareSearchResults.hashes.slice(0, 50).map((hash) => (
                              <Card key={hash.id} className="bg-secondary/50">
                                <CardContent className="p-3 font-mono text-xs">
                                  <div className="grid grid-cols-1 gap-1">
                                    <div><strong className="text-muted-foreground">MD5:</strong> <span className="text-orange-400">{hash.MD5}</span></div>
                                    <div><strong className="text-muted-foreground">SHA256:</strong> <span className="text-cyan-400 break-all">{hash.SHA256}</span></div>
                                  </div>
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center text-muted-foreground py-4">No matching hashes</div>
                        )}
                      </TabsContent>

                      <TabsContent value="filetypes" className="mt-4">
                        {malwareSearchResults.fileTypes.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto">
                            {malwareSearchResults.fileTypes.map((ft) => (
                              <Card key={ft.id} className="bg-secondary/50">
                                <CardContent className="p-3 flex justify-between items-center">
                                  <span className="text-sm text-foreground truncate">{ft.filetype}</span>
                                  <Badge variant="outline">{ft.count}</Badge>
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center text-muted-foreground py-4">No matching file types</div>
                        )}
                      </TabsContent>

                      <TabsContent value="imports" className="mt-4">
                        {malwareSearchResults.imports.length > 0 ? (
                          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-64 overflow-y-auto">
                            {malwareSearchResults.imports.map((imp) => (
                              <Card key={imp.id} className="bg-secondary/50">
                                <CardContent className="p-3 flex justify-between items-center">
                                  <span className="text-sm font-mono text-foreground truncate">{imp.import_name}</span>
                                  <Badge variant="outline">{imp.count}</Badge>
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center text-muted-foreground py-4">No matching imports</div>
                        )}
                      </TabsContent>

                      <TabsContent value="certificates" className="mt-4">
                        {malwareSearchResults.certificates.length > 0 ? (
                          <div className="space-y-2 max-h-64 overflow-y-auto">
                            {malwareSearchResults.certificates.map((cert) => (
                              <Card key={cert.id} className="bg-secondary/50">
                                <CardContent className="p-3 flex justify-between items-center">
                                  <span className="text-sm text-foreground truncate flex-1">{cert.certificate}</span>
                                  <Badge variant="outline" className="ml-2">{cert.count}</Badge>
                                </CardContent>
                              </Card>
                            ))}
                          </div>
                        ) : (
                          <div className="text-center text-muted-foreground py-4">No matching certificates</div>
                        )}
                      </TabsContent>
                    </Tabs>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">
                      No malware data found matching "{searchQuery}"
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

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
