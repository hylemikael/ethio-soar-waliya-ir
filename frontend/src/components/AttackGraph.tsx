import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
  Server,
  User,
  Globe,
  Terminal,
  FileText,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Info,
  Filter,
  X,
  Layers,
  ShieldAlert,
  RotateCw,
  Route,
  ArrowRight,
} from 'lucide-react';
import { GraphSnapshot, GraphNode, GraphEdge, EntityType, AttackPath } from '../types';

interface AttackGraphProps {
  graph: GraphSnapshot | null;
  onSelectEntityForTimeline?: (entityId: string) => void;
  onSelectEventForTimeline?: (eventId: string) => void;
  onRefreshGraph?: () => Promise<void>;
  selectedEntityId?: string | null;
  isRefreshing?: boolean;
}

interface LayoutNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

const MAX_DISPLAY_NODES = 45;

export const AttackGraph: React.FC<AttackGraphProps> = ({
  graph,
  onSelectEntityForTimeline,
  onSelectEventForTimeline,
  onRefreshGraph,
  selectedEntityId,
  isRefreshing = false,
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [selectedAttackPathId, setSelectedAttackPathId] = useState<string | null>(null);
  const [activeStepIndex, setActiveStepIndex] = useState<number | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const [startPan, setStartPan] = useState({ x: 0, y: 0 });
  const svgRef = useRef<SVGSVGElement | null>(null);

  // Synchronize internal node selection with external prop
  useEffect(() => {
    if (selectedEntityId && graph?.nodes) {
      const match = graph.nodes.find((n) => n.id === selectedEntityId);
      if (match) {
        setSelectedNode(match);
        setSelectedEdge(null);
      }
    }
  }, [selectedEntityId, graph]);

  // Set initial attack path if available
  useEffect(() => {
    if (graph?.attack_paths && graph.attack_paths.length > 0 && !selectedAttackPathId) {
      setSelectedAttackPathId(graph.attack_paths[0].path_id);
    }
  }, [graph, selectedAttackPathId]);

  // Active attack path object
  const activeAttackPath = useMemo<AttackPath | null>(() => {
    if (!graph?.attack_paths || !selectedAttackPathId) return null;
    return graph.attack_paths.find((p) => p.path_id === selectedAttackPathId) || null;
  }, [graph, selectedAttackPathId]);

  // Nodes and edges in selected attack path
  const attackPathElements = useMemo(() => {
    if (!activeAttackPath) return { nodeIds: new Set<string>(), edgeKeys: new Set<string>() };
    const nodeIds = new Set<string>();
    const edgeKeys = new Set<string>();
    nodeIds.add(activeAttackPath.entry_node);
    nodeIds.add(activeAttackPath.target_node);
    activeAttackPath.steps.forEach((s) => {
      nodeIds.add(s.source);
      nodeIds.add(s.target);
      edgeKeys.add(`${s.source}->${s.target}`);
    });
    return { nodeIds, edgeKeys };
  }, [activeAttackPath]);

  // Bounded nodes and edges
  const { boundedNodes, boundedEdges, isBounded } = useMemo(() => {
    if (!graph || !graph.nodes) {
      return { boundedNodes: [], boundedEdges: [], isBounded: false };
    }

    const isExceeded = graph.nodes.length > MAX_DISPLAY_NODES;
    const nodes = isExceeded ? graph.nodes.slice(0, MAX_DISPLAY_NODES) : graph.nodes;
    const nodeIds = new Set(nodes.map((n) => n.id));
    const edges = (graph.edges || []).filter(
      (e) => nodeIds.has(e.source) && nodeIds.has(e.target)
    );

    return {
      boundedNodes: nodes,
      boundedEdges: edges,
      isBounded: isExceeded,
    };
  }, [graph]);

  // Layout positions: stable circular / force simulation
  const layoutNodes = useMemo<LayoutNode[]>(() => {
    if (boundedNodes.length === 0) return [];

    const width = 800;
    const height = 500;
    const cx = width / 2;
    const cy = height / 2;

    // Initial radial placement
    const nodes: LayoutNode[] = boundedNodes.map((n, i) => {
      const angle = (i / boundedNodes.length) * 2 * Math.PI;
      const radius = boundedNodes.length === 1 ? 0 : Math.min(230, 75 + boundedNodes.length * 9);
      return {
        ...n,
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
        vx: 0,
        vy: 0,
      };
    });

    // Run simple force relaxation iterations
    const iterations = 60;
    const k = Math.sqrt((width * height) / (nodes.length || 1));

    for (let iter = 0; iter < iterations; iter++) {
      // Repulsion between all node pairs
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 320) {
            const force = (k * k) / dist;
            const fx = (dx / dist) * force * 0.05;
            const fy = (dy / dist) * force * 0.05;
            nodes[i].x -= fx;
            nodes[i].y -= fy;
            nodes[j].x += fx;
            nodes[j].y += fy;
          }
        }
      }

      // Attraction along edges
      for (const edge of boundedEdges) {
        const source = nodes.find((n) => n.id === edge.source);
        const target = nodes.find((n) => n.id === edge.target);
        if (source && target) {
          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const force = (dist * dist) / k;
          const fx = (dx / dist) * force * 0.03;
          const fy = (dy / dist) * force * 0.03;
          source.x += fx;
          source.y += fy;
          target.x -= fx;
          target.y -= fy;
        }
      }

      // Gravity towards center
      for (const node of nodes) {
        node.x += (cx - node.x) * 0.02;
        node.y += (cy - node.y) * 0.02;
      }
    }

    return nodes;
  }, [boundedNodes, boundedEdges]);

  const nodeMap = useMemo(() => {
    const map = new Map<string, LayoutNode>();
    layoutNodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [layoutNodes]);

  // Connected node IDs for highlighting
  const connectedNodeIds = useMemo(() => {
    if (!selectedNode) return new Set<string>();
    const ids = new Set<string>([selectedNode.id]);
    boundedEdges.forEach((e) => {
      if (e.source === selectedNode.id) ids.add(e.target);
      if (e.target === selectedNode.id) ids.add(e.source);
    });
    return ids;
  }, [selectedNode, boundedEdges]);

  // Panning handlers
  const handleMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    setStartPan({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (!isPanning) return;
    setPan({
      x: e.clientX - startPan.x,
      y: e.clientY - startPan.y,
    });
  };

  const handleMouseUp = () => {
    setIsPanning(false);
  };

  const handleZoom = (delta: number) => {
    setZoom((prev) => Math.max(0.4, Math.min(2.5, prev + delta)));
  };

  const handleResetView = () => {
    setZoom(1);
    setPan({ x: 0, y: 0 });
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  const getNodeIcon = (type: EntityType) => {
    switch (type) {
      case 'Host':
        return <Server className="w-4 h-4 text-cyan-400" />;
      case 'User':
        return <User className="w-4 h-4 text-amber-400" />;
      case 'IPAddress':
        return <Globe className="w-4 h-4 text-emerald-400" />;
      case 'Process':
        return <Terminal className="w-4 h-4 text-purple-400" />;
      case 'File':
        return <FileText className="w-4 h-4 text-rose-400" />;
      case 'Alert':
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case 'Indicator':
        return <Info className="w-4 h-4 text-orange-400" />;
      default:
        return <Layers className="w-4 h-4 text-blue-400" />;
    }
  };

  const getNodeColors = (type: EntityType) => {
    switch (type) {
      case 'Host':
        return { fill: '#082f49', stroke: '#0284c7', text: '#38bdf8' };
      case 'User':
        return { fill: '#451a03', stroke: '#d97706', text: '#fbbf24' };
      case 'IPAddress':
        return { fill: '#022c22', stroke: '#059669', text: '#34d399' };
      case 'Process':
        return { fill: '#2e1065', stroke: '#7c3aed', text: '#c084fc' };
      case 'File':
        return { fill: '#4c0519', stroke: '#e11d48', text: '#fb7185' };
      case 'Alert':
        return { fill: '#450a0a', stroke: '#dc2626', text: '#f87171' };
      case 'Indicator':
        return { fill: '#431407', stroke: '#ea580c', text: '#fb923c' };
      default:
        return { fill: '#1e293b', stroke: '#64748b', text: '#cbd5e1' };
    }
  };

  if (!graph || boundedNodes.length === 0) {
    return (
      <div className="h-96 rounded-xl border border-border bg-[#0b101d] flex flex-col items-center justify-center p-6 text-center">
        <ShieldAlert className="w-10 h-10 text-slate-500 mb-3" />
        <h4 className="text-sm font-semibold text-white">No Entity Correlation Graph Available</h4>
        <p className="text-xs text-slate-400 max-w-md mt-1">
          Telemetry for this incident has not yet established correlated entity relationships, or the graph snapshot is empty.
        </p>
        {onRefreshGraph && (
          <button
            onClick={() => onRefreshGraph()}
            disabled={isRefreshing}
            className="mt-4 flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors disabled:opacity-50"
          >
            <RotateCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            <span>Reconstruct Graph from Evidence</span>
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Attack Paths Selector Header (if paths detected) */}
      {graph.attack_paths && graph.attack_paths.length > 0 && (
        <div className="rounded-xl border border-amber-900/60 bg-amber-950/20 p-3 space-y-2.5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <Route className="w-4 h-4 text-amber-400" />
              <span className="text-xs font-bold uppercase tracking-wider text-amber-300">
                Discovered Attack Progressions ({graph.attack_paths.length})
              </span>
            </div>
            <div className="flex items-center space-x-1.5 flex-wrap">
              {graph.attack_paths.map((path, idx) => {
                const isSelected = selectedAttackPathId === path.path_id;
                return (
                  <button
                    key={path.path_id}
                    onClick={() => {
                      setSelectedAttackPathId(path.path_id);
                      setActiveStepIndex(null);
                      setSelectedNode(null);
                      setSelectedEdge(null);
                    }}
                    className={`px-2.5 py-1 rounded text-xs font-mono transition-all flex items-center space-x-1.5 border ${
                      isSelected
                        ? 'bg-amber-600/30 text-amber-200 border-amber-500 shadow-sm'
                        : 'bg-surface-elevated text-slate-400 border-border hover:text-white'
                    }`}
                  >
                    <span>Path {idx + 1}</span>
                    <span className="text-[10px] opacity-75 font-sans">({path.hop_count} hops)</span>
                    <span
                      className={`text-[9px] px-1 py-0.2 rounded uppercase font-sans font-bold ${
                        path.risk_severity === 'CRITICAL'
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : 'bg-amber-950 text-amber-300 border border-amber-800'
                      }`}
                    >
                      {path.risk_severity}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Stepper for Active Attack Path */}
          {activeAttackPath && (
            <div className="pt-2 border-t border-amber-900/40 flex items-center space-x-2 overflow-x-auto text-xs py-1">
              <span className="text-[11px] font-mono text-slate-400 shrink-0">Progression:</span>
              <button
                onClick={() => {
                  setActiveStepIndex(null);
                  setSelectedEdge(null);
                }}
                className={`px-2 py-0.5 rounded text-[11px] font-mono shrink-0 transition-colors ${
                  activeStepIndex === null
                    ? 'bg-amber-500/30 text-amber-300 border border-amber-500/50'
                    : 'bg-surface text-slate-400 hover:text-white'
                }`}
              >
                All Steps
              </button>
              {activeAttackPath.steps.map((step, idx) => {
                const isActive = activeStepIndex === idx;
                return (
                  <div key={idx} className="flex items-center space-x-1 shrink-0">
                    <ArrowRight className="w-3 h-3 text-slate-600 shrink-0" />
                    <button
                      onClick={() => {
                        setActiveStepIndex(idx);
                        // Find matching edge
                        const match = boundedEdges.find(
                          (e) => e.source === step.source && e.target === step.target
                        );
                        if (match) setSelectedEdge(match);
                      }}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors flex items-center space-x-1 ${
                        isActive
                          ? 'bg-cyan-500/30 text-cyan-200 border border-cyan-400'
                          : 'bg-surface text-slate-400 hover:text-white border border-border'
                      }`}
                    >
                      <span className="font-bold text-[10px] text-amber-400">Step {step.step_order}:</span>
                      <span>{step.source.split(':').pop()}</span>
                      <span className="text-slate-500 text-[10px]">[{step.relation}]</span>
                      <span>{step.target.split(':').pop()}</span>
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Main Canvas Card */}
      <div className="relative rounded-xl border border-border bg-[#080d1a] overflow-hidden select-none">
        {/* Graph Control Toolbar */}
        <div className="absolute top-3 left-3 z-10 flex items-center space-x-1.5 bg-[#0d1424]/90 backdrop-blur-md p-1.5 rounded-lg border border-border shadow-lg">
          <button
            onClick={() => handleZoom(0.2)}
            title="Zoom In"
            className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700/60 transition-colors"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => handleZoom(-0.2)}
            title="Zoom Out"
            className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700/60 transition-colors"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleResetView}
            title="Reset / Fit View"
            className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700/60 transition-colors"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          {onRefreshGraph && (
            <button
              onClick={() => onRefreshGraph()}
              disabled={isRefreshing}
              title="Refresh Graph from Stored Events"
              className="p-1.5 rounded text-slate-400 hover:text-white hover:bg-slate-700/60 transition-colors disabled:opacity-50"
            >
              <RotateCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-blue-400' : ''}`} />
            </button>
          )}
          <span className="text-[11px] font-mono text-slate-400 px-2 border-l border-border">
            {Math.round(zoom * 100)}%
          </span>
        </div>

        {/* Bounded Graph Info Pill */}
        {isBounded && (
          <div className="absolute top-3 right-3 z-10 flex items-center space-x-1.5 bg-amber-950/80 border border-amber-800/80 text-amber-300 px-3 py-1 rounded-md text-[11px]">
            <Info className="w-3.5 h-3.5 shrink-0" />
            <span>Graph bounded to top {MAX_DISPLAY_NODES} active entities for forensic readability</span>
          </div>
        )}

        {/* SVG Attack Graph Canvas */}
        <svg
          ref={svgRef}
          viewBox="0 0 800 500"
          className="w-full h-[520px] cursor-grab active:cursor-grabbing"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onClick={() => {
            setSelectedNode(null);
            setSelectedEdge(null);
          }}
        >
          <defs>
            <marker
              id="graph-arrow"
              viewBox="0 0 10 10"
              refX="32"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
            </marker>
            <marker
              id="graph-arrow-active"
              viewBox="0 0 10 10"
              refX="32"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
            </marker>
            <marker
              id="graph-arrow-path"
              viewBox="0 0 10 10"
              refX="32"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b" />
            </marker>
          </defs>

          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges */}
            {boundedEdges.map((edge, idx) => {
              const src = nodeMap.get(edge.source);
              const tgt = nodeMap.get(edge.target);
              if (!src || !tgt) return null;

              const edgeKey = `${edge.source}->${edge.target}`;
              const isInAttackPath = attackPathElements.edgeKeys.has(edgeKey);
              const isSelectedEdge =
                selectedEdge &&
                selectedEdge.source === edge.source &&
                selectedEdge.target === edge.target;

              const isHighlighted =
                isSelectedEdge ||
                (selectedNode &&
                  (edge.source === selectedNode.id || edge.target === selectedNode.id));

              const midX = (src.x + tgt.x) / 2;
              const midY = (src.y + tgt.y) / 2;

              let strokeColor = '#334155';
              let markerEnd = 'url(#graph-arrow)';
              let strokeWidth = 1.5;

              if (isInAttackPath) {
                strokeColor = '#f59e0b';
                markerEnd = 'url(#graph-arrow-path)';
                strokeWidth = 2.5;
              }
              if (isHighlighted) {
                strokeColor = '#38bdf8';
                markerEnd = 'url(#graph-arrow-active)';
                strokeWidth = 3;
              }

              return (
                <g
                  key={`${edge.source}-${edge.target}-${idx}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedEdge(edge);
                    setSelectedNode(null);
                  }}
                  className="cursor-pointer"
                >
                  <line
                    x1={src.x}
                    y1={src.y}
                    x2={tgt.x}
                    y2={tgt.y}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={edge.relation === 'ACCESSED' ? '4 2' : 'none'}
                    markerEnd={markerEnd}
                    opacity={
                      (selectedNode && !isHighlighted) ||
                      (selectedAttackPathId && !isInAttackPath && !isHighlighted)
                        ? 0.25
                        : 0.95
                    }
                    className="transition-all duration-200"
                  />
                  {/* Edge relationship badge */}
                  <g transform={`translate(${midX}, ${midY})`}>
                    <rect
                      x={-42}
                      y={-10}
                      width={84}
                      height={20}
                      rx={4}
                      fill="#0f172a"
                      stroke={
                        isHighlighted
                          ? '#0284c7'
                          : isInAttackPath
                          ? '#b45309'
                          : '#1e293b'
                      }
                      strokeWidth={1}
                      opacity={
                        (selectedNode && !isHighlighted) ||
                        (selectedAttackPathId && !isInAttackPath && !isHighlighted)
                          ? 0.3
                          : 0.95
                      }
                    />
                    <text
                      x={0}
                      y={3.5}
                      textAnchor="middle"
                      fontSize={8.5}
                      fontWeight={600}
                      fill={
                        isHighlighted
                          ? '#7dd3fc'
                          : isInAttackPath
                          ? '#fcd34d'
                          : '#94a3b8'
                      }
                      fontFamily="monospace"
                    >
                      {edge.relation}
                    </text>
                  </g>
                </g>
              );
            })}

            {/* Nodes */}
            {layoutNodes.map((node) => {
              const colors = getNodeColors(node.type);
              const isSelected = selectedNode?.id === node.id;
              const isConnected = connectedNodeIds.has(node.id);
              const isInAttackPath = attackPathElements.nodeIds.has(node.id);
              const isDimmed =
                (selectedNode && !isConnected) ||
                (selectedAttackPathId && !isInAttackPath && !selectedNode);

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(node);
                    setSelectedEdge(null);
                  }}
                  className="cursor-pointer transition-transform duration-150 hover:scale-105"
                  opacity={isDimmed ? 0.25 : 1}
                >
                  {/* Outer Selection or Path Ring */}
                  {isSelected && (
                    <circle
                      r={26}
                      fill="none"
                      stroke="#38bdf8"
                      strokeWidth={2}
                      strokeDasharray="4 2"
                      className="animate-spin"
                      style={{ animationDuration: '8s' }}
                    />
                  )}
                  {isInAttackPath && !isSelected && (
                    <circle
                      r={24}
                      fill="none"
                      stroke="#f59e0b"
                      strokeWidth={1.8}
                      strokeDasharray="3 1"
                    />
                  )}

                  {/* Main Node Circle */}
                  <circle
                    r={20}
                    fill={colors.fill}
                    stroke={
                      isSelected
                        ? '#38bdf8'
                        : isInAttackPath
                        ? '#f59e0b'
                        : colors.stroke
                    }
                    strokeWidth={isSelected || isInAttackPath ? 2.5 : 1.8}
                    filter="drop-shadow(0 4px 6px rgba(0, 0, 0, 0.4))"
                  />

                  {/* Icon / Fallback Symbol */}
                  <text
                    x={0}
                    y={4}
                    textAnchor="middle"
                    fontSize={9.5}
                    fontWeight={700}
                    fill={colors.text}
                    fontFamily="monospace"
                  >
                    {node.type.substring(0, 2).toUpperCase()}
                  </text>

                  {/* Node Label Below */}
                  <text
                    x={0}
                    y={32}
                    textAnchor="middle"
                    fontSize={9.5}
                    fontWeight={600}
                    fill={isSelected ? '#ffffff' : '#cbd5e1'}
                    className="pointer-events-none drop-shadow"
                  >
                    {node.label.length > 20 ? `${node.label.substring(0, 18)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Graph Legend & Integrity Note */}
        <div className="p-3 bg-[#0a0f1d] border-t border-border flex flex-wrap items-center justify-between text-xs gap-3">
          <div className="flex items-center space-x-3.5 flex-wrap">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
              Entities:
            </span>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-500" />
              <span className="text-slate-300 text-[11px]">Host</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-slate-300 text-[11px]">User</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span className="text-slate-300 text-[11px]">IP Address</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
              <span className="text-slate-300 text-[11px]">Process</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span className="text-slate-300 text-[11px]">File</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span className="text-slate-300 text-[11px]">Alert</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
              <span className="text-slate-300 text-[11px]">Indicator</span>
            </div>
          </div>

          <div className="text-[11px] text-slate-500 italic max-w-lg text-right">
            Evidence-backed relationships only. Provenance and confidence verified against event records.
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="absolute top-3 right-3 z-20 w-84 bg-[#0d1424]/95 backdrop-blur-md rounded-xl border border-blue-500/40 p-4 shadow-2xl space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                {getNodeIcon(selectedNode.type)}
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block">
                    {selectedNode.type} Entity
                  </span>
                  <span className="text-xs font-bold text-white font-mono break-all">
                    {selectedNode.label}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white p-1 rounded"
                title="Close panel"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                Composite Identifier:
              </span>
              <span className="text-xs font-mono text-cyan-300 bg-surface px-2 py-1 rounded block border border-border break-all">
                {selectedNode.id}
              </span>
            </div>

            {/* Observations count */}
            {selectedNode.observation_count && (
              <div className="flex items-center justify-between text-xs bg-surface p-2 rounded border border-border">
                <span className="text-slate-400">Total Observations:</span>
                <span className="font-mono text-white font-bold">{selectedNode.observation_count}</span>
              </div>
            )}

            {/* Node Properties */}
            {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1.5">
                  Observed Properties:
                </span>
                <div className="max-h-36 overflow-y-auto space-y-1 text-[11px] font-mono bg-surface p-2 rounded border border-border">
                  {Object.entries(selectedNode.properties).map(([k, v]) => (
                    <div key={k} className="flex justify-between border-b border-border/40 pb-0.5">
                      <span className="text-slate-400">{k}:</span>
                      <span className="text-white text-right break-all ml-2">
                        {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* MITRE ATT&CK Techniques on Node */}
            {(() => {
              const rawMitre = selectedNode.properties?.mitre_attack_ids || selectedNode.properties?.mitre_ids;
              if (!Array.isArray(rawMitre) || rawMitre.length === 0) return null;
              const mitreList = rawMitre as string[];
              return (
                <div>
                  <span className="text-[10px] uppercase font-mono text-purple-400 font-bold block mb-1">
                    MITRE ATT&CK Techniques:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {mitreList.map((tid) => (
                      <a
                        key={String(tid)}
                        href={`https://attack.mitre.org/techniques/${String(tid).replace('.', '/')}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2 py-0.5 rounded bg-purple-950/60 border border-purple-500/50 text-purple-300 font-mono text-[10px] font-bold hover:bg-purple-800/60 transition-colors"
                      >
                        {String(tid)}
                      </a>
                    ))}
                  </div>
                </div>
              );
            })()}

            {/* Action button: filter timeline */}
            {onSelectEntityForTimeline && (
              <button
                onClick={() => onSelectEntityForTimeline(selectedNode.id)}
                className="w-full flex items-center justify-center space-x-2 px-3 py-1.5 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/40 text-xs font-medium transition-colors"
              >
                <Filter className="w-3.5 h-3.5" />
                <span>Filter Forensic Timeline to this Entity</span>
              </button>
            )}
          </div>
        )}

        {/* Selected Edge Details Drawer */}
        {selectedEdge && (
          <div className="absolute top-3 right-3 z-20 w-84 bg-[#0d1424]/95 backdrop-blur-md rounded-xl border border-cyan-500/40 p-4 shadow-2xl space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                <Route className="w-4 h-4 text-cyan-400" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 block">
                    Relationship Inspection
                  </span>
                  <span className="text-xs font-bold text-cyan-300 font-mono">
                    {selectedEdge.relation}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedEdge(null)}
                className="text-slate-400 hover:text-white p-1 rounded"
                title="Close panel"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1 text-xs bg-surface p-2.5 rounded border border-border font-mono">
              <div className="flex items-center space-x-1.5 text-slate-300">
                <span className="text-slate-400 text-[10px]">SRC:</span>
                <span className="text-cyan-300 font-bold break-all">{selectedEdge.source}</span>
              </div>
              <div className="flex items-center space-x-1.5 text-slate-300">
                <span className="text-slate-400 text-[10px]">TGT:</span>
                <span className="text-amber-300 font-bold break-all">{selectedEdge.target}</span>
              </div>
            </div>

            {/* Confidence & Provenance Badges */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-surface p-2 rounded border border-border">
                <span className="text-[10px] text-slate-400 block uppercase">Confidence</span>
                <span className="text-xs font-bold text-emerald-400 font-mono">
                  {Math.round((selectedEdge.confidence ?? 1.0) * 100)}%
                </span>
              </div>
              <div className="bg-surface p-2 rounded border border-border">
                <span className="text-[10px] text-slate-400 block uppercase">Provenance</span>
                <span className="text-xs font-bold text-blue-400 font-mono truncate block">
                  {selectedEdge.provenance || 'telemetry'}
                </span>
              </div>
            </div>

            {/* Description if present */}
            {selectedEdge.description && (
              <p className="text-xs text-slate-300 bg-surface/70 p-2 rounded border border-border/60 italic">
                {selectedEdge.description}
              </p>
            )}

            {/* Evidence References */}
            {selectedEdge.evidence_event_ids && selectedEdge.evidence_event_ids.length > 0 && (
              <div>
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                  Supporting Event Evidence ({selectedEdge.evidence_event_ids.length}):
                </span>
                <div className="space-y-1 max-h-28 overflow-y-auto font-mono text-[11px]">
                  {selectedEdge.evidence_event_ids.map((evId) => (
                    <div
                      key={evId}
                      className="flex items-center justify-between bg-surface px-2 py-1 rounded border border-border hover:border-cyan-500/50 transition-colors"
                    >
                      <span className="text-slate-300 truncate mr-2">{evId}</span>
                      {onSelectEventForTimeline && (
                        <button
                          onClick={() => onSelectEventForTimeline(evId)}
                          className="text-[10px] text-cyan-400 hover:text-cyan-200 shrink-0 font-bold"
                        >
                          View
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
