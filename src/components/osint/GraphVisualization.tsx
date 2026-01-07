// src/components/osint/GraphVisualization.tsx
// Maltego-style Interactive Graph with Real Data

import { useState, useRef, useEffect, useCallback } from 'react';
import {
  Network,
  Plus,
  Play,
  Trash2,
  Save,
  Upload,
  Download,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Settings,
  Info,
  Loader2,
  Search,
  Grid,
  Move,
  MousePointer,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuTrigger,
  ContextMenuSeparator,
  ContextMenuSub,
  ContextMenuSubContent,
  ContextMenuSubTrigger,
} from '@/components/ui/context-menu';
import { toast } from 'sonner';
import { cn } from '@/lib/utils';
import {
  type GraphNode,
  type GraphEdge,
  type GraphData,
  type EntityType,
  type TransformType,
  ENTITY_CONFIG,
  AVAILABLE_TRANSFORMS,
  createEntity,
  executeTransform,
} from '@/services/graphService';

export function GraphVisualization() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  const [graphData, setGraphData] = useState<GraphData>({
    nodes: [],
    edges: [],
  });

  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);
  const [draggingNode, setDraggingNode] = useState<GraphNode | null>(null);
  const [dragOffset, setDragOffset] = useState({ x: 0, y: 0 });

  const [viewOffset, setViewOffset] = useState({ x: 0, y: 0 });
  const [viewScale, setViewScale] = useState(1);
  const [isPanning, setIsPanning] = useState(false);
  const [panStart, setPanStart] = useState({ x: 0, y: 0 });

  const [showAddDialog, setShowAddDialog] = useState(false);
  const [newEntityType, setNewEntityType] = useState<EntityType>('domain');
  const [newEntityValue, setNewEntityValue] = useState('');

  const [showPropertiesPanel, setShowPropertiesPanel] = useState(false);
  const [transforming, setTransforming] = useState(false);

  const [contextMenuNode, setContextMenuNode] = useState<GraphNode | null>(null);
  const [contextMenuPos, setContextMenuPos] = useState({ x: 0, y:  0 });

  /* ============================================================================
     CANVAS RENDERING
  ============================================================================ */

  const drawGraph = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    // Set canvas size
    canvas.width = canvas.offsetWidth;
    canvas. height = canvas.offsetHeight;

    // Clear canvas
    ctx. fillStyle = '#0a0e27';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    // Draw grid
    ctx.strokeStyle = 'rgba(100, 116, 139, 0.1)';
    ctx.lineWidth = 1;

    const gridSize = 50 * viewScale;
    const offsetX = viewOffset.x % gridSize;
    const offsetY = viewOffset.y % gridSize;

    for (let x = offsetX; x < canvas.width; x += gridSize) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }

    for (let y = offsetY; y < canvas. height; y += gridSize) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    ctx.save();
    ctx.translate(viewOffset.x, viewOffset.y);
    ctx.scale(viewScale, viewScale);

    // Draw edges
    graphData.edges.forEach(edge => {
      const sourceNode = graphData.nodes.find(n => n.id === edge.source);
      const targetNode = graphData.nodes.find(n => n.id === edge.target);

      if (! sourceNode || !targetNode) return;

      ctx.beginPath();
      ctx.moveTo(sourceNode.position.x, sourceNode.position.y);
      ctx.lineTo(targetNode.position.x, targetNode. position.y);
      ctx.strokeStyle = edge.color || '#64748b';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Draw arrow
      const angle = Math.atan2(
        targetNode.position.y - sourceNode.position.y,
        targetNode.position.x - sourceNode.position.x
      );

      const arrowSize = 10;
      const arrowX = targetNode.position.x - Math.cos(angle) * (targetNode.size || 50) / 2;
      const arrowY = targetNode.position.y - Math.sin(angle) * (targetNode.size || 50) / 2;

      ctx.beginPath();
      ctx.moveTo(arrowX, arrowY);
      ctx.lineTo(
        arrowX - arrowSize * Math.cos(angle - Math.PI / 6),
        arrowY - arrowSize * Math.sin(angle - Math.PI / 6)
      );
      ctx.lineTo(
        arrowX - arrowSize * Math.cos(angle + Math.PI / 6),
        arrowY - arrowSize * Math.sin(angle + Math.PI / 6)
      );
      ctx.closePath();
      ctx.fillStyle = edge.color || '#64748b';
      ctx.fill();

      // Draw edge label
      const midX = (sourceNode.position. x + targetNode.position.x) / 2;
      const midY = (sourceNode.position.y + targetNode.position. y) / 2;

      ctx.font = '10px Inter, sans-serif';
      ctx. fillStyle = '#94a3b8';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(edge. label, midX, midY - 10);
    });

    // Draw nodes
    graphData.nodes.forEach(node => {
      const size = node.size || 50;
      const isSelected = selectedNode?.id === node.id;
      const isHovered = hoveredNode?.id === node.id;

      // Node shadow/glow
      if (isSelected || isHovered) {
        ctx.shadowBlur = 20;
        ctx.shadowColor = node.color || '#3b82f6';
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(node.position.x, node.position.y, size / 2, 0, Math.PI * 2);
      ctx.fillStyle = node.color || '#3b82f6';
      ctx.fill();

      if (isSelected) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 3;
        ctx.stroke();
      }

      ctx.shadowBlur = 0;

      // Node icon
      ctx.font = `${size / 2}px Arial`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillStyle = '#ffffff';
      ctx.fillText(node.icon || '⚫', node.position.x, node.position.y);

      // Node label
      ctx. font = 'bold 12px Inter, sans-serif';
      ctx.fillStyle = '#ffffff';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';

      const label = node.label. length > 20 ? node.label.substring(0, 20) + '...' : node.label;
      ctx.fillText(label, node.position.x, node.position.y + size / 2 + 5);

      // Risk indicator
      if (node.metadata?. riskLevel) {
        const riskColors = {
          low: '#10b981',
          medium: '#f59e0b',
          high: '#f97316',
          critical: '#ef4444',
        };

        ctx.beginPath();
        ctx.arc(
          node.position.x + size / 2 - 5,
          node.position.y - size / 2 + 5,
          8,
          0,
          Math.PI * 2
        );
        ctx.fillStyle = riskColors[node.metadata.riskLevel];
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2;
        ctx.stroke();
      }
    });

    ctx.restore();
  }, [graphData, selectedNode, hoveredNode, viewOffset, viewScale]);

  useEffect(() => {
    drawGraph();
  }, [drawGraph]);

  /* ============================================================================
     MOUSE INTERACTIONS
  ============================================================================ */

  const getMousePos = (e: React. MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };

    const rect = canvas.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left - viewOffset.x) / viewScale,
      y: (e. clientY - rect.top - viewOffset.y) / viewScale,
    };
  };

  const getNodeAtPosition = (x: number, y: number): GraphNode | null => {
    for (let i = graphData.nodes.length - 1; i >= 0; i--) {
      const node = graphData.nodes[i];
      const size = node.size || 50;
      const distance = Math.sqrt(
        Math.pow(x - node.position.x, 2) + Math.pow(y - node.position.y, 2)
      );

      if (distance <= size / 2) {
        return node;
      }
    }
    return null;
  };

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const pos = getMousePos(e);
    const node = getNodeAtPosition(pos.x, pos.y);

    if (e.button === 2) {
      // Right click
      if (node) {
        setContextMenuNode(node);
        setContextMenuPos({ x: e.clientX, y: e. clientY });
      }
      return;
    }

    if (node) {
      setSelectedNode(node);
      setDraggingNode(node);
      setDragOffset({
        x: pos.x - node.position.x,
        y: pos.y - node.position.y,
      });
    } else {
      setSelectedNode(null);
      setIsPanning(true);
      setPanStart({ x: e.clientX - viewOffset.x, y: e. clientY - viewOffset.y });
    }
  };

  const handleMouseMove = (e:  React.MouseEvent<HTMLCanvasElement>) => {
    const pos = getMousePos(e);

    if (draggingNode) {
      setGraphData(prev => ({
        ... prev,
        nodes: prev. nodes.map(node =>
          node.id === draggingNode.id
            ? {
                ...node,
                position: {
                  x: pos.x - dragOffset.x,
                  y: pos.y - dragOffset.y,
                },
              }
            : node
        ),
      }));
      return;
    }

    if (isPanning) {
      setViewOffset({
        x: e.clientX - panStart.x,
        y: e.clientY - panStart.y,
      });
      return;
    }

    const node = getNodeAtPosition(pos.x, pos.y);
    setHoveredNode(node);
  };

  const handleMouseUp = () => {
    setDraggingNode(null);
    setIsPanning(false);
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setViewScale(prev => Math.max(0.1, Math.min(3, prev * delta)));
  };

  /* ============================================================================
     ENTITY OPERATIONS
  ============================================================================ */

  const addEntity = () => {
    if (!newEntityValue.trim()) {
      toast.error('Please enter a value');
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas) return;

    const newNode = createEntity(
      newEntityType,
      newEntityValue. trim(),
      {
        x: (canvas.width / 2 - viewOffset.x) / viewScale,
        y: (canvas.height / 2 - viewOffset. y) / viewScale,
      }
    );

    setGraphData(prev => ({
      ...prev,
      nodes: [... prev.nodes, newNode],
    }));

    setNewEntityValue('');
    setShowAddDialog(false);
    toast.success(`Added ${newEntityType}:  ${newEntityValue}`);
  };

  const deleteNode = (nodeId: string) => {
    setGraphData(prev => ({
      nodes: prev.nodes.filter(n => n.id !== nodeId),
      edges: prev.edges.filter(e => e.source !== nodeId && e.target !== nodeId),
    }));
    setSelectedNode(null);
    toast.success('Entity deleted');
  };

  const runTransform = async (transformId: TransformType, node: GraphNode) => {
    setTransforming(true);
    toast.info(`Running ${transformId}...`);

    try {
      const { nodes:  newNodes, edges: newEdges } = await executeTransform(transformId, node);

      if (newNodes.length === 0) {
        toast.warning('No results found');
        return;
      }

      setGraphData(prev => ({
        nodes: [...prev.nodes, ...newNodes],
        edges: [...prev.edges, ...newEdges],
      }));

      toast.success(`Added ${newNodes.length} new entities`);
    } catch (error) {
      console.error('Transform error:', error);
      toast.error('Transform failed');
    } finally {
      setTransforming(false);
    }
  };

  const clearGraph = () => {
    if (confirm('Clear entire graph?')) {
      setGraphData({ nodes: [], edges: [] });
      setSelectedNode(null);
      toast.success('Graph cleared');
    }
  };

  const exportGraph = () => {
    const data = JSON.stringify(graphData, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL. createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `osint-graph-${Date.now()}.json`;
    a.click();
    toast.success('Graph exported');
  };

  const importGraph = (e: React. ChangeEvent<HTMLInputElement>) => {
    const file = e. target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const data = JSON.parse(event.target?.result as string);
        setGraphData(data);
        toast.success('Graph imported');
      } catch (error) {
        toast.error('Invalid graph file');
      }
    };
    reader.readAsText(file);
  };

  const centerGraph = () => {
    if (graphData.nodes.length === 0) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    const avgX = graphData.nodes.reduce((sum, n) => sum + n.position. x, 0) / graphData.nodes.length;
    const avgY = graphData.nodes. reduce((sum, n) => sum + n.position.y, 0) / graphData.nodes.length;

    setViewOffset({
      x: canvas.width / 2 - avgX * viewScale,
      y: canvas.height / 2 - avgY * viewScale,
    });
  };

  /* ============================================================================
     LAYOUT ALGORITHMS
  ============================================================================ */

  const autoLayout = () => {
    if (graphData.nodes.length === 0) return;

    const canvas = canvasRef.current;
    if (!canvas) return;

    // Simple circular layout
    const centerX = canvas.width / 2 / viewScale;
    const centerY = canvas.height / 2 / viewScale;
    const radius = 200;

    setGraphData(prev => ({
      ... prev,
      nodes: prev. nodes.map((node, idx) => {
        const angle = (idx / prev.nodes.length) * 2 * Math.PI;
        return {
          ...node,
          position: {
            x: centerX + radius * Math.cos(angle),
            y: centerY + radius * Math.sin(angle),
          },
        };
      }),
    }));

    toast.success('Layout applied');
  };

  /* ============================================================================
     RENDER
  ============================================================================ */

  return (
    <div className="h-screen flex flex-col bg-background">
      {/* Toolbar */}
      <div className="border-b border-border p-3 flex items-center justify-between bg-card">
        <div className="flex items-center gap-2">
          <Network className="h-6 w-6 text-primary" />
          <h1 className="text-xl font-bold">Graph Intelligence</h1>
          <Badge variant="secondary">{graphData.nodes.length} entities</Badge>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="default"
            size="sm"
            onClick={() => setShowAddDialog(true)}
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Entity
          </Button>

          <Button variant="outline" size="sm" onClick={autoLayout}>
            <Grid className="h-4 w-4 mr-2" />
            Auto Layout
          </Button>

          <Button variant="outline" size="sm" onClick={centerGraph}>
            <Maximize2 className="h-4 w-4 mr-2" />
            Center
          </Button>

          <Button variant="outline" size="sm" onClick={() => setViewScale(1)}>
            <ZoomIn className="h-4 w-4 mr-2" />
            Reset Zoom
          </Button>

          <Button variant="outline" size="sm" onClick={exportGraph}>
            <Download className="h-4 w-4 mr-2" />
            Export
          </Button>

          <label>
            <Button variant="outline" size="sm" asChild>
              <span>
                <Upload className="h-4 w-4 mr-2" />
                Import
              </span>
            </Button>
            <input
              type="file"
              accept=".json"
              className="hidden"
              onChange={importGraph}
            />
          </label>

          <Button variant="destructive" size="sm" onClick={clearGraph}>
            <Trash2 className="h-4 w-4 mr-2" />
            Clear
          </Button>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex relative" ref={containerRef}>
        {/* Canvas */}
        <div className="flex-1 relative">
          <canvas
            ref={canvasRef}
            className="w-full h-full cursor-move"
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
            onContextMenu={(e) => e.preventDefault()}
          />

          {/* Canvas Overlay Info */}
          <div className="absolute bottom-4 left-4 bg-card/90 backdrop-blur border border-border rounded-lg p-3 space-y-2 text-xs">
            <div className="flex items-center gap-2">
              <MousePointer className="h-3 w-3" />
              <span>Left Click: Select • Right Click: Context Menu</span>
            </div>
            <div className="flex items-center gap-2">
              <Move className="h-3 w-3" />
              <span>Drag Node:  Move • Drag Canvas: Pan</span>
            </div>
            <div className="flex items-center gap-2">
              <ZoomIn className="h-3 w-3" />
              <span>Scroll: Zoom • Zoom:  {(viewScale * 100).toFixed(0)}%</span>
            </div>
          </div>

          {/* Loading Overlay */}
          {transforming && (
            <div className="absolute inset-0 bg-background/80 backdrop-blur flex items-center justify-center">
              <Card>
                <CardContent className="pt-6 flex items-center gap-3">
                  <Loader2 className="h-6 w-6 animate-spin text-primary" />
                  <span>Running transform...</span>
                </CardContent>
              </Card>
            </div>
          )}
        </div>

        {/* Properties Panel */}
        {selectedNode && (
          <div className="w-80 border-l border-border bg-card overflow-y-auto">
            <div className="p-4 border-b border-border">
              <div className="flex items-center justify-between mb-2">
                <h3 className="font-bold">Entity Properties</h3>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedNode(null)}
                >
                  ✕
                </Button>
              </div>

              <div className="flex items-center gap-3 mb-4">
                <div
                  className="w-12 h-12 rounded-full flex items-center justify-center text-2xl"
                  style={{ backgroundColor: selectedNode.color }}
                >
                  {selectedNode.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="text-xs text-muted-foreground uppercase">
                    {selectedNode. type}
                  </div>
                  <div className="font-semibold truncate">{selectedNode.label}</div>
                </div>
              </div>

              {selectedNode.metadata?.riskLevel && (
                <Badge
                  variant="outline"
                  className={cn(
                    'w-full justify-center',
                    selectedNode.metadata.riskLevel === 'critical' && 'border-red-500 text-red-500',
                    selectedNode.metadata. riskLevel === 'high' && 'border-orange-500 text-orange-500',
                    selectedNode.metadata.riskLevel === 'medium' && 'border-yellow-500 text-yellow-500',
                    selectedNode.metadata. riskLevel === 'low' && 'border-green-500 text-green-500'
                  )}
                >
                  {selectedNode.metadata.riskLevel. toUpperCase()} RISK
                </Badge>
              )}
            </div>

            {/* Properties */}
            <div className="p-4 space-y-3">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Value</div>
                <div className="text-sm font-mono bg-secondary p-2 rounded break-all">
                  {selectedNode.value}
                </div>
              </div>

              {Object.keys(selectedNode.properties).length > 0 && (
                <div>
                  <div className="text-xs text-muted-foreground mb-2">Additional Properties</div>
                  <div className="space-y-2">
                    {Object.entries(selectedNode.properties).map(([key, value]) => (
                      <div key={key} className="text-sm">
                        <span className="text-muted-foreground">{key}:</span>{' '}
                        <span className="font-mono">{JSON.stringify(value)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Available Transforms */}
            <div className="p-4 border-t border-border">
              <div className="text-sm font-semibold mb-3">Available Transforms</div>
              <div className="space-y-2">
                {AVAILABLE_TRANSFORMS.filter(t =>
                  t.supportedTypes.includes(selectedNode. type)
                ).map(transform => (
                  <Button
                    key={transform.id}
                    variant="outline"
                    size="sm"
                    className="w-full justify-start"
                    onClick={() => runTransform(transform.id, selectedNode)}
                    disabled={transforming}
                  >
                    <span className="mr-2">{transform.icon}</span>
                    {transform.name}
                  </Button>
                ))}
              </div>
            </div>

            {/* Actions */}
            <div className="p-4 border-t border-border">
              <Button
                variant="destructive"
                size="sm"
                className="w-full"
                onClick={() => deleteNode(selectedNode.id)}
              >
                <Trash2 className="h-4 w-4 mr-2" />
                Delete Entity
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Add Entity Dialog */}
      <Dialog open={showAddDialog} onOpenChange={setShowAddDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add New Entity</DialogTitle>
            <DialogDescription>
              Create a new entity to start your investigation
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <label className="text-sm font-medium mb-2 block">Entity Type</label>
              <Select
                value={newEntityType}
                onValueChange={(v) => setNewEntityType(v as EntityType)}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(ENTITY_CONFIG).map(([type, config]) => (
                    <SelectItem key={type} value={type}>
                      <span className="flex items-center gap-2">
                        <span>{config.icon}</span>
                        <span>{type}</span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">Value</label>
              <Input
                value={newEntityValue}
                onChange={(e) => setNewEntityValue(e.target.value)}
                placeholder="Enter domain, IP, email, etc..."
                onKeyDown={(e) => e.key === 'Enter' && addEntity()}
              />
            </div>

            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setShowAddDialog(false)}>
                Cancel
              </Button>
              <Button onClick={addEntity}>
                <Plus className="h-4 w-4 mr-2" />
                Add Entity
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Context Menu */}
      {contextMenuNode && (
        <div
          className="fixed z-50"
          style={{ left: contextMenuPos.x, top: contextMenuPos.y }}
        >
          <Card className="w-64">
            <CardContent className="p-2">
              <div className="text-xs font-semibold mb-2 px-2 py-1">
                {contextMenuNode.label}
              </div>
              <div className="space-y-1">
                {AVAILABLE_TRANSFORMS.filter(t =>
                  t.supportedTypes.includes(contextMenuNode. type)
                ).map(transform => (
                  <button
                    key={transform.id}
                    className="w-full text-left px-2 py-1 text-sm hover:bg-secondary rounded"
                    onClick={() => {
                      runTransform(transform.id, contextMenuNode);
                      setContextMenuNode(null);
                    }}
                  >
                    <span className="mr-2">{transform.icon}</span>
                    {transform. name}
                  </button>
                ))}
                <div className="border-t border-border my-1" />
                <button
                  className="w-full text-left px-2 py-1 text-sm hover:bg-secondary rounded text-destructive"
                  onClick={() => {
                    deleteNode(contextMenuNode.id);
                    setContextMenuNode(null);
                  }}
                >
                  <Trash2 className="h-3 w-3 inline mr-2" />
                  Delete
                </button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}
