// src/components/osint/GraphVisualization.tsx
import { useEffect, useRef, useState } from 'react';
import { Search, Loader2, Plus, Trash2, Download, ZoomIn, ZoomOut } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { toast } from 'sonner';

interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'ip' | 'email' | 'person' | 'organization' | 'phone';
  x: number;
  y: number;
  color: string;
}

interface GraphEdge {
  from: string;
  to: string;
  label: string;
}

export function GraphVisualization() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const nodeColors = {
    domain: '#00FF9F',
    ip: '#00D9FF',
    email: '#FF6B9D',
    person: '#FFD93D',
    organization: '#A78BFA',
    phone: '#FFA500',
  };

  useEffect(() => {
    drawGraph();
  }, [nodes, edges, zoom, pan]);

  const drawGraph = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;

    // Clear canvas
    ctx.fillStyle = 'hsl(220 20% 4%)';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Apply zoom and pan
    ctx.save();
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    // Draw edges
    ctx.strokeStyle = 'rgba(0, 255, 159, 0.3)';
    ctx.lineWidth = 2;
    edges.forEach((edge) => {
      const fromNode = nodes.find((n) => n.id === edge.from);
      const toNode = nodes.find((n) => n.id === edge.to);

      if (fromNode && toNode) {
        ctx.beginPath();
        ctx.moveTo(fromNode.x, fromNode.y);
        ctx.lineTo(toNode.x, toNode.y);
        ctx.stroke();

        // Draw edge label
        const midX = (fromNode.x + toNode.x) / 2;
        const midY = (fromNode.y + toNode.y) / 2;
        ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
        ctx.font = '10px JetBrains Mono';
        ctx.fillText(edge.label, midX, midY);
      }
    });

    // Draw nodes
    nodes.forEach((node) => {
      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, 30, 0, Math.PI * 2);
      ctx.fillStyle = node.color + '40';
      ctx.fill();
      ctx.strokeStyle = node.color;
      ctx.lineWidth = 3;
      ctx.stroke();

      // Node label
      ctx.fillStyle = '#FFFFFF';
      ctx.font = '12px JetBrains Mono';
      ctx.textAlign = 'center';
      ctx.fillText(node.label, node.x, node.y - 40);

      // Node type
      ctx.font = '9px JetBrains Mono';
      ctx.fillStyle = 'rgba(255, 255, 255, 0.6)';
      ctx.fillText(node.type, node.x, node.y + 50);
    });

    ctx.restore();
  };

  const handleSearch = async () => {
    if (!query.trim()) {
      toast.error('Please enter a search query');
      return;
    }

    setLoading(true);

    try {
      // Detect query type
      const type = detectQueryType(query);
      
      // Add root node
      const rootNode: GraphNode = {
        id: query,
        label: query,
        type,
        x: 400,
        y: 300,
        color: nodeColors[type],
      };

      // Simulate fetching related entities
      const relatedNodes: GraphNode[] = [];
      const relatedEdges: GraphEdge[] = [];

      // Add some related nodes based on type
      if (type === 'domain') {
        // Add IP nodes
        for (let i = 0; i < 3; i++) {
          const ip = `192.168.1.${Math.floor(Math.random() * 255)}`;
          relatedNodes.push({
            id: ip,
            label: ip,
            type: 'ip',
            x: 400 + Math.cos((i * 2 * Math.PI) / 3) * 150,
            y: 300 + Math.sin((i * 2 * Math.PI) / 3) * 150,
            color: nodeColors.ip,
          });
          relatedEdges.push({
            from: query,
            to: ip,
            label: 'resolves_to',
          });
        }

        // Add email nodes
        const email = `admin@${query}`;
        relatedNodes.push({
          id: email,
          label: email,
          type: 'email',
          x: 400 + 200,
          y: 300,
          color: nodeColors.email,
        });
        relatedEdges.push({
          from: query,
          to: email,
          label: 'whois_email',
        });
      } else if (type === 'ip') {
        // Add domain nodes
        const domains = ['example.com', 'test.org', 'demo.net'];
        domains.forEach((domain, i) => {
          relatedNodes.push({
            id: domain,
            label: domain,
            type: 'domain',
            x: 400 + Math.cos((i * 2 * Math.PI) / 3) * 150,
            y: 300 + Math.sin((i * 2 * Math.PI) / 3) * 150,
            color: nodeColors.domain,
          });
          relatedEdges.push({
            from: query,
            to: domain,
            label: 'hosts',
          });
        });
      }

      setNodes([rootNode, ...relatedNodes]);
      setEdges(relatedEdges);
      toast.success(`Added ${relatedNodes.length + 1} nodes to graph`);
    } catch (error) {
      toast.error('Failed to build graph');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  const detectQueryType = (query: string): GraphNode['type'] => {
    if (query.includes('@')) return 'email';
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query)) return 'ip';
    if (query.includes('.')) return 'domain';
    if (/^\+?\d+$/.test(query)) return 'phone';
    return 'person';
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    setIsDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    if (isDragging) {
      setPan({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y,
      });
    }
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const handleZoomIn = () => setZoom((z) => Math.min(z + 0.1, 3));
  const handleZoomOut = () => setZoom((z) => Math.max(z - 0.1, 0.3));

  const handleClear = () => {
    setNodes([]);
    setEdges([]);
    setSelectedNode(null);
    toast.info('Graph cleared');
  };

  const handleExport = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    canvas.toBlob((blob) => {
      if (blob) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'osint-graph.png';
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Graph exported');
      }
    });
  };

  return (
    <div className="p-6 space-y-6 animate-fade-in">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-foreground">Graph Visualization</h1>
        <p className="text-muted-foreground text-sm mt-1">
          Maltego-style relationship mapping and intelligence graphing
        </p>
      </div>

      {/* Controls */}
      <Card className="bg-card border-border">
        <CardContent className="p-4 space-y-4">
          {/* Search */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
                placeholder="Enter domain, IP, email, or name..."
                className="pl-10 bg-background"
              />
            </div>
            <Button onClick={handleSearch} disabled={loading} className="min-w-[120px]">
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <>
                  <Plus className="h-4 w-4 mr-2" />
                  Add
                </>
              )}
            </Button>
          </div>

          {/* Toolbar */}
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleZoomIn}>
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button variant="outline" size="sm" onClick={handleZoomOut}>
              <ZoomOut className="h-4 w-4" />
            </Button>
            <div className="text-xs font-mono text-muted-foreground px-2">
              {Math.round(zoom * 100)}%
            </div>
            <div className="flex-1" />
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={handleClear}>
              <Trash2 className="h-4 w-4 mr-2" />
              Clear
            </Button>
          </div>

          {/* Legend */}
          <div className="flex flex-wrap gap-3 pt-3 border-t border-border">
            {Object.entries(nodeColors).map(([type, color]) => (
              <div key={type} className="flex items-center gap-2">
                <div
                  className="w-3 h-3 rounded-full border-2"
                  style={{ backgroundColor: color + '40', borderColor: color }}
                />
                <span className="text-xs text-muted-foreground capitalize">{type}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Graph Canvas */}
      <Card className="bg-card border-border">
        <CardContent className="p-0">
          <canvas
            ref={canvasRef}
            className="w-full h-[600px] cursor-move"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
          />
        </CardContent>
      </Card>

      {/* Stats */}
      {nodes.length > 0 && (
        <Card className="bg-card border-border">
          <CardContent className="p-4">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-2xl font-bold font-mono text-primary">{nodes.length}</div>
                <div className="text-xs text-muted-foreground">Nodes</div>
              </div>
              <div>
                <div className="text-2xl font-bold font-mono text-accent">{edges.length}</div>
                <div className="text-xs text-muted-foreground">Connections</div>
              </div>
              <div>
                <div className="text-2xl font-bold font-mono text-success">
                  {new Set(nodes.map((n) => n.type)).size}
                </div>
                <div className="text-xs text-muted-foreground">Entity Types</div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
