// src/components/osint/LiveThreatFeed.tsx
// REAL-TIME CYBER THREAT MAP - 100% REAL DATA FROM LIVE ENDPOINTS
// NO MOCK DATA - Uses Feodo, URLhaus, ThreatFox, APTmap APIs

import { useState, useEffect, useRef } from 'react';
import { Activity, RefreshCw, Globe, Zap, AlertTriangle, MapPin, Target, Shield, Radio, Loader } from 'lucide-react';
import { fetchFeodoC2Servers, fetchURLhausRecent, fetchThreatFoxIOCs } from '@/services/mispFeedService';
import { getAPTThreatMapData } from '@/services/aptMapService';

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
    @keyframes attack-pulse {
      0% { transform: scale(1); opacity: 1; }
      50% { transform: scale(1.5); opacity: 0.5; }
      100% { transform: scale(1); opacity: 1; }
    }
  `;
  if (!document.querySelector('#leaflet-threat-styles')) {
    leafletStyle.id = 'leaflet-threat-styles';
    document.head.appendChild(leafletStyle);
  }
}

interface RealThreat {
  id: string;
  timestamp: Date;
  lat: number;
  lon: number;
  country: string;
  city?: string;
  threatType: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  indicator: string;
  port?: number;
  malware?: string;
  source: 'Feodo' | 'URLhaus' | 'ThreatFox' | 'APTmap';
  status?: string;
  confidence?: number;
}

// IP Geolocation using ip-api.com (free, no key required)
async function geolocateIP(ip: string): Promise<{ lat: number; lon: number; country: string; city: string } | null> {
  try {
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`);
    const data = await response.json();
    
    if (data.status === 'success') {
      return {
        lat: data.lat,
        lon: data.lon,
        country: data.country,
        city: data.city || 'Unknown'
      };
    }
  } catch (error) {
    console.error('[Geolocation] Failed for IP:', ip, error);
  }
  return null;
}

function LeafletThreatMap({ threats }: { threats: RealThreat[] }) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<any>(null);
  const markersLayerRef = useRef<any>(null);

  useEffect(() => {
    if (!mapRef.current || typeof window === 'undefined') return;

    const initMap = () => {
      if (!(window as any).L) {
        setTimeout(initMap, 100);
        return;
      }

      const L = (window as any).L;

      if (!mapInstanceRef.current) {
        mapInstanceRef.current = L.map(mapRef.current).setView([20, 0], 2);
        
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
          attribution: '&copy; OpenStreetMap',
          subdomains: 'abcd',
          maxZoom: 18
        }).addTo(mapInstanceRef.current);

        markersLayerRef.current = L.layerGroup().addTo(mapInstanceRef.current);
      }
    };

    if (!document.querySelector('link[href*="leaflet.css"]')) {
      const link = document.createElement('link');
      link.rel = 'stylesheet';
      link.href = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
      document.head.appendChild(link);
    }

    if (!document.querySelector('script[src*="leaflet.js"]')) {
      const script = document.createElement('script');
      script.src = 'https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
      script.onload = initMap;
      document.head.appendChild(script);
    } else {
      initMap();
    }
  }, []);

  useEffect(() => {
    if (!mapInstanceRef.current || !(window as any).L) return;

    const L = (window as any).L;
    markersLayerRef.current?.clearLayers();

    threats.forEach((threat) => {
      const color = {
        critical: '#ef4444',
        high: '#f97316',
        medium: '#eab308',
        low: '#3b82f6'
      }[threat.severity];

      const size = Math.min(14 + (threat.confidence || 50) / 10, 24);

      const iconHtml = `
        <div style="
          width: ${size}px;
          height: ${size}px;
          background: ${color};
          border-radius: 50%;
          border: 2px solid rgba(255,255,255,0.8);
          filter: drop-shadow(0 0 8px ${color});
          ${threat.severity === 'critical' ? 'animation: attack-pulse 2s infinite;' : ''}
        "></div>
      `;

      const icon = L.divIcon({
        className: 'custom-threat-marker',
        html: iconHtml,
        iconSize: [size + 4, size + 4],
        iconAnchor: [(size + 4) / 2, (size + 4) / 2],
      });

      const marker = L.marker([threat.lat, threat.lon], { icon });
      
      const popupContent = `
        <div style="background: #1e293b; color: #fff; padding: 12px; border-radius: 8px; min-width: 250px;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <span style="
              background: ${color}; 
              color: white; 
              padding: 2px 6px; 
              border-radius: 4px; 
              font-size: 10px; 
              font-weight: bold;
            ">${threat.severity.toUpperCase()}</span>
            <h3 style="margin: 0; color: ${color}; font-size: 14px;">${threat.threatType}</h3>
          </div>
          
          <div style="font-size: 12px; line-height: 1.6; color: #cbd5e1;">
            <div style="margin: 4px 0;"><strong>Location:</strong> ${threat.city || 'Unknown'}, ${threat.country}</div>
            <div style="margin: 4px 0;"><strong>Indicator:</strong><br>
              <code style="font-family: monospace; background: #334155; padding: 2px 4px; border-radius: 3px; font-size: 11px; word-break: break-all;">${threat.indicator}</code>
            </div>
            ${threat.port ? `<div style="margin: 4px 0;"><strong>Port:</strong> ${threat.port}</div>` : ''}
            ${threat.malware ? `<div style="margin: 4px 0;"><strong>Malware:</strong> ${threat.malware}</div>` : ''}
            ${threat.confidence ? `<div style="margin: 4px 0;"><strong>Confidence:</strong> ${threat.confidence}%</div>` : ''}
            <div style="margin: 4px 0;"><strong>Source:</strong> ${threat.source}</div>
            ${threat.status ? `<div style="margin: 4px 0;"><strong>Status:</strong> <span style="color: ${threat.status === 'online' ? '#22c55e' : '#94a3b8'};">${threat.status.toUpperCase()}</span></div>` : ''}
            <div style="margin: 6px 0 0 0; color: #94a3b8; font-size: 11px;">
              ${threat.timestamp.toLocaleString()}
            </div>
          </div>
        </div>
      `;

      marker.bindPopup(popupContent, {
        maxWidth: 300,
        className: 'custom-threat-popup'
      });
      
      markersLayerRef.current.addLayer(marker);
    });
  }, [threats]);

  return <div ref={mapRef} style={{ height: '600px', width: '100%' }} className="rounded-lg overflow-hidden" />;
}

export function LiveThreatFeed() {
  const [threats, setThreats] = useState<RealThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [liveMode, setLiveMode] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    c2Servers: 0,
    malwareURLs: 0,
  });

  // Fetch real threat data from all sources
  const fetchRealThreats = async () => {
    setLoading(true);
    const allThreats: RealThreat[] = [];

    try {
      console.log('[LiveThreatFeed] Fetching REAL threat data...');

      // 1. Fetch Feodo C2 Servers (REAL botnet C2s)
      const feodoServers = await fetchFeodoC2Servers();
      console.log('[Feodo] Fetched', feodoServers.length, 'real C2 servers');
      
      for (const server of feodoServers.slice(0, 50)) {
        if (server.country) {
          const geo = await geolocateIP(server.ip);
          
          if (geo) {
            allThreats.push({
              id: server.id,
              timestamp: new Date(server.firstSeen),
              lat: geo.lat,
              lon: geo.lon,
              country: geo.country,
              city: geo.city,
              threatType: 'Botnet C2 Server',
              severity: server.status === 'online' ? 'critical' : 'high',
              indicator: server.ip,
              port: server.port,
              malware: server.malwareFamily,
              source: 'Feodo',
              status: server.status,
              confidence: 95,
            });
          }
        }
        
        // Rate limiting for geolocation API
        await new Promise(resolve => setTimeout(resolve, 150));
      }

      // 2. Fetch URLhaus malware URLs (REAL malware distribution)
      const urlhausData = await fetchURLhausRecent();
      console.log('[URLhaus] Fetched', urlhausData.length, 'real malware URLs');
      
      for (const entry of urlhausData.slice(0, 30)) {
        try {
          const url = new URL(entry.url);
          const hostname = url.hostname;
          
          // Try to resolve hostname to IP for geolocation
          const geo = await geolocateIP(hostname);
          
          if (geo) {
            allThreats.push({
              id: entry.id,
              timestamp: new Date(entry.dateAdded),
              lat: geo.lat,
              lon: geo.lon,
              country: geo.country,
              city: geo.city,
              threatType: 'Malware Distribution URL',
              severity: entry.urlStatus === 'online' ? 'high' : 'medium',
              indicator: entry.url,
              malware: entry.threat,
              source: 'URLhaus',
              status: entry.urlStatus,
              confidence: 85,
            });
          }
        } catch (e) {
          // Skip invalid URLs
        }
        
        await new Promise(resolve => setTimeout(resolve, 150));
      }

      // 3. Fetch ThreatFox IOCs (REAL indicators of compromise)
      const threatfoxData = await fetchThreatFoxIOCs(7);
      console.log('[ThreatFox] Fetched', threatfoxData.length, 'real IOCs');
      
      for (const ioc of threatfoxData.slice(0, 30)) {
        if (ioc.iocType.includes('ip')) {
          const ip = ioc.ioc.split(':')[0];
          const geo = await geolocateIP(ip);
          
          if (geo) {
            allThreats.push({
              id: ioc.id,
              timestamp: new Date(ioc.firstSeen),
              lat: geo.lat,
              lon: geo.lon,
              country: geo.country,
              city: geo.city,
              threatType: ioc.threatType || 'IOC',
              severity: ioc.confidenceLevel > 80 ? 'critical' : ioc.confidenceLevel > 60 ? 'high' : 'medium',
              indicator: ioc.ioc,
              malware: ioc.malwarePrintable,
              source: 'ThreatFox',
              confidence: ioc.confidenceLevel,
            });
          }
          
          await new Promise(resolve => setTimeout(resolve, 150));
        }
      }

      // 4. Fetch APT threat map data (REAL APT group locations)
      const aptData = await getAPTThreatMapData();
      console.log('[APTmap] Fetched', aptData.length, 'real APT groups');
      
      aptData.forEach(apt => {
        allThreats.push({
          id: apt.id,
          timestamp: new Date(),
          lat: apt.lat,
          lon: apt.lon,
          country: apt.country,
          threatType: 'APT Group',
          severity: apt.severity,
          indicator: apt.name,
          malware: apt.ttps.join(', '),
          source: 'APTmap',
          confidence: 90,
        });
      });

      console.log('[LiveThreatFeed] Total REAL threats loaded:', allThreats.length);
      setThreats(allThreats);
      setLastUpdate(new Date());

    } catch (error) {
      console.error('[LiveThreatFeed] Error fetching real threats:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchRealThreats();
  }, []);

  useEffect(() => {
    if (!liveMode) return;

    // Refresh every 5 minutes with real data
    const interval = setInterval(() => {
      console.log('[LiveThreatFeed] Auto-refreshing real threat data...');
      fetchRealThreats();
    }, 300000);

    return () => clearInterval(interval);
  }, [liveMode]);

  useEffect(() => {
    setStats({
      total: threats.length,
      critical: threats.filter(t => t.severity === 'critical').length,
      high: threats.filter(t => t.severity === 'high').length,
      medium: threats.filter(t => t.severity === 'medium').length,
      c2Servers: threats.filter(t => t.source === 'Feodo').length,
      malwareURLs: threats.filter(t => t.source === 'URLhaus').length,
    });
  }, [threats]);

  const recentThreats = threats.slice(-20).reverse();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Globe className="h-8 w-8 text-blue-400" />
          <h1 className="text-3xl font-bold">Live Cyber Threat Map</h1>
          {liveMode && (
            <div className="flex items-center gap-2 ml-4">
              <Radio className="h-5 w-5 text-red-500 animate-pulse" />
              <span className="text-red-500 font-semibold">LIVE - REAL DATA</span>
            </div>
          )}
        </div>
        <p className="text-slate-400">
          Real-time data from Feodo Tracker, URLhaus, ThreatFox, APTmap - NO MOCK DATA
        </p>
      </div>

      <div className="flex items-center gap-4 mb-6">
        <button
          onClick={() => setLiveMode(!liveMode)}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            liveMode 
              ? 'bg-red-500/20 border border-red-500 text-red-400' 
              : 'bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700'
          }`}
        >
          <Activity className={`inline-block h-4 w-4 mr-2 ${liveMode ? 'animate-pulse' : ''}`} />
          {liveMode ? 'LIVE MODE' : 'Start Live Feed'}
        </button>
        
        <button
          onClick={fetchRealThreats}
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-700 transition-colors disabled:opacity-50"
        >
          {loading ? (
            <Loader className="inline-block h-4 w-4 mr-2 animate-spin" />
          ) : (
            <RefreshCw className="inline-block h-4 w-4 mr-2" />
          )}
          Refresh Real Data
        </button>

        <div className="ml-auto text-sm text-slate-400 font-mono">
          Last Update: {lastUpdate?.toLocaleTimeString() || 'Never'}
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-6 gap-4 mb-6">
        {[
          { label: 'Total Threats', value: stats.total, color: 'text-blue-400', icon: Target },
          { label: 'Critical', value: stats.critical, color: 'text-red-500', icon: AlertTriangle },
          { label: 'High', value: stats.high, color: 'text-orange-500', icon: Shield },
          { label: 'Medium', value: stats.medium, color: 'text-yellow-500', icon: Zap },
          { label: 'C2 Servers', value: stats.c2Servers, color: 'text-purple-400', icon: Activity },
          { label: 'Malware URLs', value: stats.malwareURLs, color: 'text-pink-400', icon: Globe },
        ].map((stat) => (
          <div key={stat.label} className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
            <stat.icon className={`h-5 w-5 ${stat.color} mb-2`} />
            <div className={`text-2xl font-bold font-mono ${stat.color}`}>{stat.value}</div>
            <div className="text-xs text-slate-400 mt-1">{stat.label}</div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold flex items-center gap-2">
                <MapPin className="h-5 w-5 text-blue-400" />
                Real Threat Locations
              </h2>
            </div>
            {loading ? (
              <div className="h-[600px] flex items-center justify-center">
                <Loader className="h-12 w-12 animate-spin text-blue-400" />
                <span className="ml-4">Loading real threat data...</span>
              </div>
            ) : (
              <LeafletThreatMap threats={threats} />
            )}
          </div>
        </div>

        <div className="lg:col-span-1">
          <div className="bg-slate-900/50 border border-slate-800 rounded-lg p-4 h-[680px] flex flex-col">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <Activity className="h-5 w-5 text-blue-400" />
              Recent Real Threats
            </h2>
            
            <div className="flex-1 overflow-y-auto space-y-2 pr-2" style={{ scrollbarWidth: 'thin' }}>
              {recentThreats.map((threat) => {
                const severityColor = {
                  critical: 'border-red-500 bg-red-500/10',
                  high: 'border-orange-500 bg-orange-500/10',
                  medium: 'border-yellow-500 bg-yellow-500/10',
                  low: 'border-blue-500 bg-blue-500/10'
                }[threat.severity];

                return (
                  <div key={threat.id} className={`border-l-4 ${severityColor} bg-slate-800/50 p-3 rounded-r text-sm`}>
                    <div className="flex items-start justify-between mb-2">
                      <span className="font-semibold text-slate-200">{threat.threatType}</span>
                      <span className="text-xs px-2 py-1 rounded bg-slate-700">{threat.source}</span>
                    </div>
                    
                    <div className="space-y-1 text-xs text-slate-300">
                      <div>
                        <span className="text-slate-500">Location:</span> {threat.city || 'Unknown'}, {threat.country}
                      </div>
                      <div className="font-mono text-xs break-all">
                        <span className="text-slate-500">Indicator:</span> {threat.indicator}
                      </div>
                      {threat.malware && (
                        <div>
                          <span className="text-slate-500">Malware:</span>{' '}
                          <span className="text-red-400">{threat.malware}</span>
                        </div>
                      )}
                      {threat.status && (
                        <div>
                          <span className="text-slate-500">Status:</span>{' '}
                          <span className={threat.status === 'online' ? 'text-red-400' : 'text-slate-400'}>
                            {threat.status.toUpperCase()}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      <div className="mt-6 bg-green-500/10 border border-green-500/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <Zap className="h-5 w-5 text-green-400 mt-0.5" />
          <div>
            <h3 className="font-semibold text-green-400 mb-1">✅ 100% REAL DATA SOURCES</h3>
            <p className="text-sm text-slate-300">
              <strong>Feodo Tracker:</strong> Real botnet C2 servers • 
              <strong>URLhaus:</strong> Real malware distribution URLs • 
              <strong>ThreatFox:</strong> Real IOCs • 
              <strong>APTmap:</strong> Real APT group locations • 
              <strong>NO MOCK DATA</strong>
            </p>
          </div>
        </div>
      </div>

      <style>{`
        ::-webkit-scrollbar {
          width: 6px;
        }
        ::-webkit-scrollbar-track {
          background: rgba(15, 23, 42, 0.5);
        }
        ::-webkit-scrollbar-thumb {
          background: rgba(71, 85, 105, 0.5);
          border-radius: 3px;
        }
      `}</style>
    </div>
  );
}

export default LiveThreatFeed;
