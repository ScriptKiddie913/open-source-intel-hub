// src/components/osint/MaltegoGraph.tsx
// Maltego-style relationship mapping with entity expansion

import { useEffect, useRef, useState } from 'react';
import { Search, Loader2, Plus, Trash2, Download, ZoomIn, ZoomOut, Expand } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import { resolveDNS, getAllRecords } from '@/services/dnsService';
import { getIPGeolocation } from '@/services/ipService';
import { searchCertificates } from '@/services/certService';

type EntityType = 'domain' | 'ip' | 'email' | 'person' | 'organization' | 'phone' | 'hash' | 'url';

interface GraphNode {
  id: string;
  label: string;
  type: EntityType;
  x: number;
  y: number;
  vx: number;
  vy: number;
  color: string;
  data: any;
  expanded: boolean;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
  type: string;
}

const ENTITY_COLORS: Record<EntityType, string> = {
  domain: '#00FF9F',
  ip: '#00D9FF',
  email: '#FF6B9D',
  person: '#FFD93D',
  organization: '#A78BFA',
  phone: '#FFA500',
  hash: '#FF4444',
  url: '#00FFAA',
};

export function MaltegoGraph() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [query, setQuery] = useState('');
  const [entityType, setEntityType] = useState<EntityType>('domain');
  const [loading, setLoading] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [dragNode, setDragNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    const interval = setInterval(simulatePhysics, 30);
    return () => clearInterval(interval);
  }, [nodes]);

  useEffect(() => {
    drawGraph();
  }, [nodes, edges, zoom, pan, selectedNode]);

  // Simple force-directed layout
  const simulatePhysics = () => {
    if (nodes.length === 0) return;

    const newNodes = nodes.map(node => ({ ...node }));

    // Apply forces
    for (let i = 0; i < newNodes.length; i++) {
      for (let j = i + 1; j < newNodes.length; j++) {
        const dx = newNodes[j].x - newNodes[i].x;
        const dy = newNodes[j].y - newNodes[i].y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = (200 * 200) / (dist * dist);

        newNodes[i].vx -= (dx / dist) * force * 0.01;
        newNodes[i].vy -= (dy / dist) * force * 0.01;
        newNodes[j].vx += (dx / dist) * force * 0.01;
        newNodes[j].vy += (dy / dist) * force * 0.01;
      }
    }

    // Apply edge forces (attraction)
    edges.forEach(edge => {
      const from = newNodes.find(n => n.id === edge.from);
      const to = newNodes.find(n => n.id === edge.to);
      if (!from || !to) return;

      const dx = to.x - from.x;
      const dy = to.y - from.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const force = (dist - 150) * 0.01;

      from.vx += (dx / dist) * force;
      from.vy += (dy / dist) * force;
      to.vx -= (dx / dist) * force;
      to.vy -= (dy / dist) * force;
    });

    // Apply velocity and damping
    newNodes.forEach(node => {
      node.x += node.vx;
      node.y += node.vy;
      node.vx *= 0.9;
      node.vy *= 0.9;
    });

    setNodes(newNodes);
  };

  const drawGraph = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    // Clear
    ctx.fillStyle = '#0a0e27';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    ctx.save();
    ctx.translate(pan.x + canvas.width / 2, pan.y + canvas.height / 2);
    ctx.scale(zoom, zoom);

    // Draw edges
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.3)';
    ctx.lineWidth = 2 / zoom;
    edges.forEach((edge) => {
      const from = nodes.find(n => n.id === edge.from);
      const to = nodes.find(n => n.id === edge.to);

      if (from && to) {
        ctx.beginPath();
        ctx.moveTo(from.x, from.y);
        ctx.lineTo(to.x, to.y);
        ctx.stroke();

        // Edge label
        const midX = (from.x + to.x) / 2;
        const midY = (from.y + to.y) / 2;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
        ctx.font = `${10 / zoom}px JetBrains Mono`;
        ctx.textAlign = 'center';
        ctx.fillText(edge.label, midX, midY);
      }
    });

    // Draw nodes
    nodes.forEach((node) => {
      const radius = 30 / zoom;

      // Node circle with glow
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius + 5, 0, Math.PI * 2);
      const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, radius + 5);
      gradient.addColorStop(0, node.color + '40');
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.fill();

      // Node body
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = node.color + '40';
      ctx.fill();
      ctx.strokeStyle = node.color;
      ctx.lineWidth = 3 / zoom;
      ctx.stroke();

      // Icon based on type
      ctx.fillStyle = '#FFFFFF';
      ctx.font = `bold ${16 / zoom}px sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const icon = getEntityIcon(node.type);
      ctx.fillText(icon, node.x, node.y);

      // Label
      ctx.fillStyle = '#FFFFFF';
      ctx.font = `${12 / zoom}px JetBrains Mono`;
      ctx.textAlign = 'center';
      ctx.fillText(node.label.slice(0, 20), node.x, node.y + radius + 20 / zoom);

      // Selection highlight
      if (selectedNode?.id === node.id) {
        ctx.strokeStyle = '#00FF9F';
        ctx.lineWidth = 4 / zoom;
        ctx.beginPath();
        ctx.arc(node.x, node.y, radius + 10, 0, Math.PI * 2);
        ctx.stroke();
      }

      // Expansion indicator
      if (node.expanded) {
        ctx.fillStyle = '#FFD93D';
        ctx.beginPath();
        ctx.arc(node.x + radius, node.y - radius, 8 / zoom, 0, Math.PI * 2);
        ctx.fill();
      }
    });

    ctx.restore();
  };

  const getEntityIcon = (type: EntityType): string => {
    const icons = {
      domain: '🌐',
      ip: '📡',
      email: '📧',
      person: '👤',
      organization: '🏢',
      phone: '📞',
      hash: '#',
      url: '🔗',
    };
    return icons[type] || '●';
  };

  const handleCanvasClick = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left - canvas.width / 2 - pan.x) / zoom;
    const y = (e.clientY - rect.top - canvas.height / 2 - pan.y) / zoom;

    const clicked = nodes.find(node => {
      const dx = x - node.x;
      const dy = y - node.y;
      return Math.sqrt(dx * dx + dy * dy) < 30;
    });

    if (clicked) {
      setSelectedNode(clicked);
    } else {
      setSelectedNode(null);
    }
  };

  const handleCanvasMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const rect = canvas.getBoundingClientRect();
    const x = (e.clientX - rect.left - canvas.width / 2 - pan.x) / zoom;
    const y = (e.clientY - rect.top - canvas.height / 2 - pan.y) / zoom;

    const node = nodes.find(n => {
      const dx = x - n.x;
      const dy = y - n.y;
      return Math.sqrt(dx * dx + dy * dy) < 30;
    });

    if (node) {
      setDragNode(node);
      setDragStart({ x: e.clientX, y: e.clientY });
    } else {
      setIsDragging(true);
      setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
    }
  };

  const handleCanvasMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (dragNode) {
      const dx = (e.clientX - dragStart.x) / zoom;
      const dy = (e.clientY - dragStart.y) / zoom;
      
      setNodes(nodes.map(n => 
        n.id === dragNode.id 
          ? { ...n, x: n.x + dx, y: n.y + dy, vx: 0, vy: 0 }
          : n
      ));
      
      setDragStart({ x: e.clientX, y: e.clientY });
    } else if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleCanvasMouseUp = () => {
    setIsDragging(false);
    setDragNode(null);
  };

  const addEntity = async () => {
    if (!query.trim()) {
      toast.error('Enter an entity value');
      return;
    }

    setLoading(true);

    try {
      const id = `${entityType}-${query}-${Date.now()}`;
      const newNode: GraphNode = {
        id,
        label: query,
        type: entityType,
        x: Math.random() * 200 - 100,
        y: Math.random() * 200 - 100,
        vx: 0,
        vy: 0,
        color: ENTITY_COLORS[entityType],
        data: {},
        expanded: false,
      };

      setNodes([...nodes, newNode]);
      setQuery('');
      toast.success(`Added ${entityType}: ${query}`);
    } catch (error) {
      toast.error('Failed to add entity');
    } finally {
      setLoading(false);
    }
  };

  const expandEntity = async (node: GraphNode) => {
    if (node.expanded) {
      toast.info('Entity already expanded');
      return;
    }

    setLoading(true);

    try {
      const newNodes: GraphNode[] = [];
      const newEdges: GraphEdge[] = [];

      if (node.type === 'domain') {
        // Expand domain -> IPs, subdomains
        const dns = await getAllRecords(node.label);
        
        dns.records
          .filter(r => r.type === 'A')
          .slice(0, 5)
          .forEach(record => {
            const ipId = `ip-${record.data}`;
            if (!nodes.find(n => n.id === ipId)) {
              newNodes.push({
                id: ipId,
                label: record.data,
                type: 'ip',
                x: node.x + Math.random() * 200 - 100,
                y: node.y + Math.random() * 200 - 100,
                vx: 0,
                vy: 0,
                color: ENTITY_COLORS.ip,
                data: record,
                expanded: false,
              });
              newEdges.push({
                from: node.id,
                to: ipId,
                label: 'resolves_to',
                type: 'dns',
              });
            }
          });

        const certs = await searchCertificates(node.label);
        const subdomains = new Set<string>();
        certs.slice(0, 20).forEach(cert => {
          cert.nameValue?.split('\n').forEach(name => {
            if (name.endsWith(node.label) && name !== node.label) {
              subdomains.add(name);
            }
          });
        });

        Array.from(subdomains).slice(0, 5).forEach(subdomain => {
          const subId = `domain-${subdomain}`;
          if (!nodes.find(n => n.id === subId)) {
            newNodes.push({
              id: subId,
              label: subdomain,
              type: 'domain',
              x: node.x + Math.random() * 200 - 100,
              y: node.y + Math.random() * 200 - 100,
              vx: 0,
              vy: 0,
              color: ENTITY_COLORS.domain,
              data: {},
              expanded: false,
            });
            newEdges.push({
              from: node.id,
              to: subId,
              label: 'subdomain',
              type: 'hierarchy',
            });
          }
        });
      } else if (node.type === 'ip') {
        // Expand IP -> geolocation, org
        const geo = await getIPGeolocation(node.label);
        
        if (geo) {
          const orgId = `org-${geo.org}`;
          if (!nodes.find(n => n.id === orgId)) {
            newNodes.push({
              id: orgId,
              label: geo.org,
              type: 'organization',
              x: node.x + Math.random() * 200 - 100,
              y: node.y + Math.random() * 200 - 100,
              vx: 0,
              vy: 0,
              color: ENTITY_COLORS.organization,
              data: geo,
              expanded: false,
            });
            newEdges.push({
              from: node.id,
              to: orgId,
              label: 'owned_by',
              type: 'ownership',
            });
          }
        }
      }

      setNodes([...nodes, ...newNodes]);
      setEdges([...edges, ...newEdges]);
      setNodes(prev => prev.map(n => n.id === node.id ? { ...n, expanded: true } : n));
      
      toast.success(`Expanded ${node.label} - found ${newNodes.length} entities`);
    } catch (error) {
      toast.error('Failed to expand entity');
    } finally {
      setLoading(false);
    }
  };

  const clearGraph = () => {
    setNodes([]);
    setEdges([]);
    setSelectedNode(null);
    toast.info('Graph cleared');
  };

  const exportGraph = () => {
    const data = { nodes, edges };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'osint-graph.json';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Graph exported');
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Maltego-Style Graph</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Interactive relationship mapping with entity expansion
        </p>
      </div>

      <Card className="bg-card border-border">
        <CardContent className="p-4 space-y-4">
          <div className="flex gap-3">
            <Select value={entityType} onValueChange={(v) => setEntityType(v as EntityType)}>
              <SelectTrigger className="w-[180px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {Object.keys(ENTITY_COLORS).map(type => (
                  <SelectItem key={type} value={type}>{type}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addEntity()}
              placeholder="Enter entity value..."
              className="flex-1 bg-background"
            />
            
            <Button onClick={addEntity} disabled={loading} className="min-w-[120px]">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4 mr-2" />}
              Add
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setZoom(z => Math.min(z + 0.2, 3))}>
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={() => setZoom(z => Math.max(z - 0.2, 0.3))}>
              <ZoomOut className="h-4 w-4" />
            </Button>
            <div className="text-xs font-mono text-muted-foreground px-2">
              {Math.round(zoom * 100)}%
            </div>
            <div className="flex-1" />
            {selectedNode && (
              <Button variant="outline" size="sm" onClick={() => expandEntity(selectedNode)}>
                <Expand className="h-4 w-4 mr-2" />
                Expand
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={exportGraph}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={clearGraph}>
              <Trash2 className="h-4 w-4 mr-2" />
              Clear
            </Button>
          </div>
        </CardContent>
      </Card>

      <canvas
        ref={canvasRef}
        className="w-full h-[700px] rounded-lg border border-border bg-[#0a0e27] cursor-move"
        onClick={handleCanvasClick}
        onMouseDown={handleCanvasMouseDown}
        onMouseMove={handleCanvasMouseMove}
        onMouseUp={handleCanvasMouseUp}
        onMouseLeave={handleCanvasMouseUp}
      />

      {selectedNode && (
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <h3 className="font-semibold mb-2">Selected: {selectedNode.label}</h3>
            <div className="text-sm space-y-1">
              <div><strong>Type:</strong> {selectedNode.type}</div>
              <div><strong>Expanded:</strong> {selectedNode.expanded ? 'Yes' : 'No'}</div>
              {Object.keys(selectedNode.data).length > 0 && (
                <pre className="text-xs bg-secondary p-2 rounded mt-2 overflow-auto max-h-32">
                  {JSON.stringify(selectedNode.data, null, 2)}
                </pre>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
