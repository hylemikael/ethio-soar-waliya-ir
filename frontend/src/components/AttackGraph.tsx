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
        return <Server className="w-4 h-4 text-blue-600" />;
      case 'User':
        return <User className="w-4 h-4 text-amber-600" />;
      case 'IPAddress':
        return <Globe className="w-4 h-4 text-emerald-600" />;
      case 'Process':
        return <Terminal className="w-4 h-4 text-purple-600" />;
      case 'File':
        return <FileText className="w-4 h-4 text-rose-600" />;
      case 'Alert':
        return <ShieldAlert className="w-4 h-4 text-red-600" />;
      case 'Indicator':
        return <Info className="w-4 h-4 text-orange-600" />;
      default:
        return <Layers className="w-4 h-4 text-gray-600" />;
    }
  };

  const getNodeColors = (type: EntityType) => {
    switch (type) {
      case 'Host':
        return { fill: '#E0F2FE', stroke: '#0284C7', text: '#0369A1' };
      case 'User':
        return { fill: '#FEF3C7', stroke: '#D97706', text: '#B45309' };
      case 'IPAddress':
        return { fill: '#DCFCE7', stroke: '#059669', text: '#047857' };
      case 'Process':
        return { fill: '#F3E8FF', stroke: '#7C3AED', text: '#6D28D9' };
      case 'File':
        return { fill: '#FFE4E6', stroke: '#E11D48', text: '#BE123C' };
      case 'Alert':
        return { fill: '#FEE2E2', stroke: '#DC2626', text: '#B91C1C' };
      case 'Indicator':
        return { fill: '#FFEDD5', stroke: '#EA580C', text: '#C2410C' };
      default:
        return { fill: '#F1F5F9', stroke: '#64748B', text: '#475569' };
    }
  };

  if (!graph || boundedNodes.length === 0) {
    return (
      <div className="h-96 rounded-lg border border-gray-200 bg-white flex flex-col items-center justify-center p-6 text-center shadow-sm">
        <ShieldAlert className="w-10 h-10 text-gray-400 mb-3" />
        <h4 className="text-sm font-semibold text-gray-900">No Entity Correlation Graph Available</h4>
        <p className="text-xs text-gray-500 max-w-md mt-1">
          Telemetry for this incident has not yet established correlated entity relationships, or the graph snapshot is empty.
        </p>
        {onRefreshGraph && (
          <button
            onClick={() => onRefreshGraph()}
            disabled={isRefreshing}
            className="mt-4 flex items-center space-x-2 px-3 py-1.5 rounded bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition-colors shadow-sm disabled:opacity-50"
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
        <div className="rounded-lg border border-amber-200 bg-amber-50/50 p-3 space-y-2.5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center space-x-2">
              <Route className="w-4 h-4 text-amber-600" />
              <span className="text-xs font-bold uppercase tracking-wider text-amber-900">
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
                        ? 'bg-amber-100 text-amber-900 border-amber-300 shadow-sm font-semibold'
                        : 'bg-white text-gray-600 border-gray-200 hover:bg-gray-50'
                    }`}
                  >
                    <span>Path {idx + 1}</span>
                    <span className="text-[10px] text-gray-500 font-sans">({path.hop_count} hops)</span>
                    <span
                      className={`text-[9px] px-1 py-0.2 rounded uppercase font-sans font-bold ${
                        path.risk_severity === 'CRITICAL'
                          ? 'bg-red-100 text-red-800 border border-red-200'
                          : 'bg-amber-100 text-amber-800 border border-amber-200'
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
            <div className="pt-2 border-t border-amber-200/60 flex items-center space-x-2 overflow-x-auto text-xs py-1">
              <span className="text-xs font-mono text-gray-500 shrink-0">Progression:</span>
              <button
                onClick={() => {
                  setActiveStepIndex(null);
                  setSelectedEdge(null);
                }}
                className={`px-2 py-0.5 rounded text-xs font-mono shrink-0 transition-colors ${
                  activeStepIndex === null
                    ? 'bg-amber-200/70 text-amber-900 border border-amber-300 font-semibold'
                    : 'bg-white text-gray-600 hover:bg-gray-100 border border-gray-200'
                }`}
              >
                All Steps
              </button>
              {activeAttackPath.steps.map((step, idx) => {
                const isActive = activeStepIndex === idx;
                return (
                  <div key={idx} className="flex items-center space-x-1 shrink-0">
                    <ArrowRight className="w-3 h-3 text-gray-400 shrink-0" />
                    <button
                      onClick={() => {
                        setActiveStepIndex(idx);
                        // Find matching edge
                        const match = boundedEdges.find(
                          (e) => e.source === step.source && e.target === step.target
                        );
                        if (match) setSelectedEdge(match);
                      }}
                      className={`px-2 py-0.5 rounded text-xs font-mono transition-colors flex items-center space-x-1 ${
                        isActive
                          ? 'bg-blue-100 text-blue-900 border border-blue-300 font-semibold'
                          : 'bg-white text-gray-600 hover:bg-gray-100 border border-gray-200'
                      }`}
                    >
                      <span className="font-bold text-[10px] text-amber-700">Step {step.step_order}:</span>
                      <span>{step.source.split(':').pop()}</span>
                      <span className="text-gray-400 text-[10px]">[{step.relation}]</span>
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
      <div className="relative rounded-lg border border-gray-200 bg-white overflow-hidden select-none shadow-sm">
        {/* Graph Control Toolbar */}
        <div className="absolute top-3 left-3 z-10 flex items-center space-x-1 bg-white/95 backdrop-blur-sm p-1 rounded-md border border-gray-200 shadow-sm">
          <button
            onClick={() => handleZoom(0.2)}
            title="Zoom In"
            className="p-1.5 rounded text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={() => handleZoom(-0.2)}
            title="Zoom Out"
            className="p-1.5 rounded text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleResetView}
            title="Reset / Fit View"
            className="p-1.5 rounded text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          {onRefreshGraph && (
            <button
              onClick={() => onRefreshGraph()}
              disabled={isRefreshing}
              title="Refresh Graph from Stored Events"
              className="p-1.5 rounded text-gray-600 hover:text-gray-900 hover:bg-gray-100 transition-colors disabled:opacity-50"
            >
              <RotateCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-blue-600' : ''}`} />
            </button>
          )}
          <span className="text-xs font-mono text-gray-500 px-2 border-l border-gray-200">
            {Math.round(zoom * 100)}%
          </span>
        </div>

        {/* Bounded Graph Info Pill */}
        {isBounded && (
          <div className="absolute top-3 right-3 z-10 flex items-center space-x-1.5 bg-amber-50 border border-amber-200 text-amber-800 px-2.5 py-1 rounded text-xs shadow-sm">
            <Info className="w-3.5 h-3.5 shrink-0 text-amber-600" />
            <span>Top {MAX_DISPLAY_NODES} active entities shown</span>
          </div>
        )}

        {/* SVG Attack Graph Canvas */}
        <svg
          ref={svgRef}
          viewBox="0 0 800 500"
          className="w-full h-[520px] bg-[#F9FAFB] cursor-grab active:cursor-grabbing"
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
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#94A3B8" />
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
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#2563EB" />
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
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#D97706" />
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

              let strokeColor = '#CBD5E1';
              let markerEnd = 'url(#graph-arrow)';
              let strokeWidth = 1.5;

              if (isInAttackPath) {
                strokeColor = '#D97706';
                markerEnd = 'url(#graph-arrow-path)';
                strokeWidth = 2.5;
              }
              if (isHighlighted) {
                strokeColor = '#2563EB';
                markerEnd = 'url(#graph-arrow-active)';
                strokeWidth = 2.5;
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
                        ? 0.3
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
                      fill="#FFFFFF"
                      stroke={
                        isHighlighted
                          ? '#2563EB'
                          : isInAttackPath
                          ? '#D97706'
                          : '#E2E8F0'
                      }
                      strokeWidth={1}
                      opacity={
                        (selectedNode && !isHighlighted) ||
                        (selectedAttackPathId && !isInAttackPath && !isHighlighted)
                          ? 0.35
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
                          ? '#1D4ED8'
                          : isInAttackPath
                          ? '#B45309'
                          : '#64748B'
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
                  opacity={isDimmed ? 0.3 : 1}
                >
                  {/* Outer Selection or Path Ring */}
                  {isSelected && (
                    <circle
                      r={25}
                      fill="none"
                      stroke="#2563EB"
                      strokeWidth={2}
                      strokeDasharray="4 2"
                    />
                  )}
                  {isInAttackPath && !isSelected && (
                    <circle
                      r={24}
                      fill="none"
                      stroke="#D97706"
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
                        ? '#2563EB'
                        : isInAttackPath
                        ? '#D97706'
                        : colors.stroke
                    }
                    strokeWidth={isSelected || isInAttackPath ? 2.5 : 1.5}
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
                    fontWeight={500}
                    fill={isSelected ? '#1D4ED8' : '#374151'}
                    className="pointer-events-none"
                  >
                    {node.label.length > 20 ? `${node.label.substring(0, 18)}...` : node.label}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>

        {/* Graph Legend & Integrity Note */}
        <div className="p-3 bg-white border-t border-gray-200 flex flex-wrap items-center justify-between text-xs gap-3">
          <div className="flex items-center space-x-3.5 flex-wrap">
            <span className="text-xs font-mono text-gray-500 uppercase tracking-wider">
              Entities:
            </span>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
              <span className="text-gray-700 text-xs">Host</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-gray-700 text-xs">User</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span className="text-gray-700 text-xs">IP Address</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-500" />
              <span className="text-gray-700 text-xs">Process</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span className="text-gray-700 text-xs">File</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
              <span className="text-gray-700 text-xs">Alert</span>
            </div>
            <div className="flex items-center space-x-1">
              <span className="w-2.5 h-2.5 rounded-full bg-orange-500" />
              <span className="text-gray-700 text-xs">Indicator</span>
            </div>
          </div>

          <div className="text-xs text-gray-500 max-w-lg text-right">
            Evidence-backed relationships only. Provenance verified against event records.
          </div>
        </div>

        {/* Selected Node Details Drawer */}
        {selectedNode && (
          <div className="absolute top-3 right-3 z-20 w-80 bg-white/98 rounded-lg border border-gray-300 p-4 shadow-lg space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-gray-200">
              <div className="flex items-center space-x-2">
                {getNodeIcon(selectedNode.type)}
                <div>
                  <span className="text-[10px] uppercase font-bold text-gray-500 block">
                    {selectedNode.type} Entity
                  </span>
                  <span className="text-xs font-bold text-gray-900 font-mono break-all">
                    {selectedNode.label}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-gray-400 hover:text-gray-600 p-1 rounded"
                title="Close panel"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <span className="text-[10px] uppercase font-mono text-gray-500 block mb-1">
                Composite Identifier:
              </span>
              <span className="text-xs font-mono text-gray-800 bg-gray-50 px-2 py-1 rounded block border border-gray-200 break-all">
                {selectedNode.id}
              </span>
            </div>

            {/* Observations count */}
            {selectedNode.observation_count && (
              <div className="flex items-center justify-between text-xs bg-gray-50 p-2 rounded border border-gray-200">
                <span className="text-gray-600">Total Observations:</span>
                <span className="font-mono text-gray-900 font-bold">{selectedNode.observation_count}</span>
              </div>
            )}

            {/* Node Properties */}
            {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
              <div>
                <span className="text-[10px] uppercase font-mono text-gray-500 block mb-1.5">
                  Observed Properties:
                </span>
                <div className="max-h-36 overflow-y-auto space-y-1 text-xs font-mono bg-gray-50 p-2 rounded border border-gray-200">
                  {Object.entries(selectedNode.properties).map(([k, v]) => (
                    <div key={k} className="flex justify-between border-b border-gray-200 pb-0.5">
                      <span className="text-gray-500">{k}:</span>
                      <span className="text-gray-900 text-right break-all ml-2 font-medium">
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
                  <span className="text-[10px] uppercase font-mono text-purple-700 font-bold block mb-1">
                    MITRE ATT&CK Techniques:
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {mitreList.map((tid) => (
                      <a
                        key={String(tid)}
                        href={`https://attack.mitre.org/techniques/${String(tid).replace('.', '/')}/`}
                        target="_blank"
                        rel="noreferrer"
                        className="px-2 py-0.5 rounded bg-purple-50 border border-purple-200 text-purple-700 font-mono text-[10px] font-bold hover:bg-purple-100 transition-colors"
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
                className="w-full flex items-center justify-center space-x-2 px-3 py-1.5 rounded bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-medium transition-colors"
              >
                <Filter className="w-3.5 h-3.5" />
                <span>Filter Forensic Timeline to this Entity</span>
              </button>
            )}
          </div>
        )}

        {/* Selected Edge Details Drawer */}
        {selectedEdge && (
          <div className="absolute top-3 right-3 z-20 w-80 bg-white/98 rounded-lg border border-gray-300 p-4 shadow-lg space-y-3">
            <div className="flex items-center justify-between pb-2 border-b border-gray-200">
              <div className="flex items-center space-x-2">
                <Route className="w-4 h-4 text-blue-600" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-gray-500 block">
                    Relationship Inspection
                  </span>
                  <span className="text-xs font-bold text-blue-700 font-mono">
                    {selectedEdge.relation}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedEdge(null)}
                className="text-gray-400 hover:text-gray-600 p-1 rounded"
                title="Close panel"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-1 text-xs bg-gray-50 p-2.5 rounded border border-gray-200 font-mono">
              <div className="flex items-center space-x-1.5 text-gray-700">
                <span className="text-gray-500 text-[10px]">SRC:</span>
                <span className="text-gray-900 font-semibold break-all">{selectedEdge.source}</span>
              </div>
              <div className="flex items-center space-x-1.5 text-gray-700">
                <span className="text-gray-500 text-[10px]">TGT:</span>
                <span className="text-gray-900 font-semibold break-all">{selectedEdge.target}</span>
              </div>
            </div>

            {/* Confidence & Provenance Badges */}
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="bg-gray-50 p-2 rounded border border-gray-200">
                <span className="text-[10px] text-gray-500 block uppercase">Confidence</span>
                <span className="text-xs font-bold text-emerald-700 font-mono">
                  {Math.round((selectedEdge.confidence ?? 1.0) * 100)}%
                </span>
              </div>
              <div className="bg-gray-50 p-2 rounded border border-gray-200">
                <span className="text-[10px] text-gray-500 block uppercase">Provenance</span>
                <span className="text-xs font-bold text-blue-700 font-mono truncate block">
                  {selectedEdge.provenance || 'telemetry'}
                </span>
              </div>
            </div>

            {/* Description if present */}
            {selectedEdge.description && (
              <p className="text-xs text-gray-600 bg-gray-50 p-2 rounded border border-gray-200 italic">
                {selectedEdge.description}
              </p>
            )}

            {/* Evidence References */}
            {selectedEdge.evidence_event_ids && selectedEdge.evidence_event_ids.length > 0 && (
              <div>
                <span className="text-[10px] uppercase font-mono text-gray-500 block mb-1">
                  Supporting Event Evidence ({selectedEdge.evidence_event_ids.length}):
                </span>
                <div className="space-y-1 max-h-28 overflow-y-auto font-mono text-xs">
                  {selectedEdge.evidence_event_ids.map((evId) => (
                    <div
                      key={evId}
                      className="flex items-center justify-between bg-gray-50 px-2 py-1 rounded border border-gray-200 hover:border-blue-300 transition-colors"
                    >
                      <span className="text-gray-700 truncate mr-2">{evId}</span>
                      {onSelectEventForTimeline && (
                        <button
                          onClick={() => onSelectEventForTimeline(evId)}
                          className="text-[10px] text-blue-600 hover:text-blue-800 shrink-0 font-bold"
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