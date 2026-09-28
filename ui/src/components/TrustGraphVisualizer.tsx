import React, {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from 'react';
import { Card, CardHeader, CardTitle, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription } from '@/components/ui/alert';

// ─── Types ────────────────────────────────────────────────────────────────────

export type ReputationTier = 'Bronze' | 'Silver' | 'Gold' | 'Platinum' | 'Diamond';

export interface TrustNode {
  id: string;
  address: string;
  reputationScore: number;
  tier: ReputationTier;
  trustCount: number;
  attestations: TrustAttestation[];
}

export interface TrustAttestation {
  id: string;
  from: string;
  to: string;
  weight: number; // 0–100
  type: string;
  createdAt: number;
}

export interface TrustGraphData {
  nodes: TrustNode[];
  edges: TrustAttestation[];
}

export interface TrustGraphVisualizerProps {
  sdk: any;
  address: string;
  depth?: number; // 1–4, default 2
}

// ─── Constants ────────────────────────────────────────────────────────────────

const TIER_COLORS: Record<ReputationTier, string> = {
  Bronze: '#cd7f32',
  Silver: '#c0c0c0',
  Gold: '#ffd700',
  Platinum: '#e5e4e2',
  Diamond: '#b9f2ff',
};

const TIER_TEXT_COLORS: Record<ReputationTier, string> = {
  Bronze: '#7c4f1e',
  Silver: '#4a4a4a',
  Gold: '#7a5c00',
  Platinum: '#555',
  Diamond: '#0077aa',
};

const NODE_RADIUS = 22;
const MIN_EDGE_WIDTH = 1;
const MAX_EDGE_WIDTH = 8;
const SIM_STEPS = 200;
const REPULSION = 6000;
const ATTRACTION = 0.05;
const DAMPING = 0.85;
const IDEAL_LENGTH = 120;

// ─── Force-directed layout ────────────────────────────────────────────────────

interface SimNode {
  id: string;
  x: number;
  y: number;
  vx: number;
  vy: number;
}

function runForceLayout(
  nodes: TrustNode[],
  edges: TrustAttestation[],
  width: number,
  height: number
): Map<string, { x: number; y: number }> {
  const cx = width / 2;
  const cy = height / 2;

  const sims: SimNode[] = nodes.map((n, i) => {
    const angle = (2 * Math.PI * i) / nodes.length;
    const r = Math.min(cx, cy) * 0.6;
    return {
      id: n.id,
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
      vx: 0,
      vy: 0,
    };
  });

  const simMap = new Map(sims.map((s) => [s.id, s]));

  for (let step = 0; step < SIM_STEPS; step++) {
    // Repulsion between all node pairs
    for (let i = 0; i < sims.length; i++) {
      for (let j = i + 1; j < sims.length; j++) {
        const a = sims[i];
        const b = sims[j];
        const dx = b.x - a.x;
        const dy = b.y - a.y;
        const dist = Math.sqrt(dx * dx + dy * dy) || 1;
        const force = REPULSION / (dist * dist);
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        a.vx -= fx;
        a.vy -= fy;
        b.vx += fx;
        b.vy += fy;
      }
    }

    // Attraction along edges
    for (const edge of edges) {
      const a = simMap.get(edge.from);
      const b = simMap.get(edge.to);
      if (!a || !b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const stretch = dist - IDEAL_LENGTH;
      const force = ATTRACTION * stretch;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.vx += fx;
      a.vy += fy;
      b.vx -= fx;
      b.vy -= fy;
    }

    // Gravity toward center
    for (const s of sims) {
      s.vx += (cx - s.x) * 0.002;
      s.vy += (cy - s.y) * 0.002;
    }

    // Apply velocity with damping
    for (const s of sims) {
      s.vx *= DAMPING;
      s.vy *= DAMPING;
      s.x += s.vx;
      s.y += s.vy;
      // Keep inside bounds
      s.x = Math.max(NODE_RADIUS + 4, Math.min(width - NODE_RADIUS - 4, s.x));
      s.y = Math.max(NODE_RADIUS + 4, Math.min(height - NODE_RADIUS - 4, s.y));
    }
  }

  const result = new Map<string, { x: number; y: number }>();
  for (const s of sims) {
    result.set(s.id, { x: s.x, y: s.y });
  }
  return result;
}

// ─── Edge width helper ────────────────────────────────────────────────────────

function edgeWidth(weight: number): number {
  return MIN_EDGE_WIDTH + ((weight / 100) * (MAX_EDGE_WIDTH - MIN_EDGE_WIDTH));
}

// ─── Main Component ───────────────────────────────────────────────────────────

export const TrustGraphVisualizer: React.FC<TrustGraphVisualizerProps> = ({
  sdk,
  address,
  depth = 2,
}) => {
  const [graphData, setGraphData] = useState<TrustGraphData>({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<TrustNode | null>(null);
  const [currentDepth, setCurrentDepth] = useState<number>(
    Math.min(4, Math.max(1, depth))
  );
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isPanning, setIsPanning] = useState(false);
  const panStart = useRef<{ mx: number; my: number; px: number; py: number } | null>(null);

  const svgRef = useRef<SVGSVGElement>(null);
  const WIDTH = 700;
  const HEIGHT = 460;

  // ─── Load graph ─────────────────────────────────────────────────────────────

  const loadGraph = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    try {
      const data: TrustGraphData =
        (await sdk.reputation?.getTrustGraph?.({ address, depth: currentDepth })) ?? {
          nodes: [],
          edges: [],
        };
      setGraphData(data);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to load trust graph');
    } finally {
      setLoading(false);
    }
  }, [sdk, address, currentDepth]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  // ─── Layout ──────────────────────────────────────────────────────────────────

  const positions = useMemo(() => {
    if (graphData.nodes.length === 0) return new Map<string, { x: number; y: number }>();
    return runForceLayout(graphData.nodes, graphData.edges, WIDTH, HEIGHT);
  }, [graphData]);

  // ─── Pan handlers ────────────────────────────────────────────────────────────

  const handleMouseDown = (e: React.MouseEvent) => {
    if (e.target !== svgRef.current) return;
    setIsPanning(true);
    panStart.current = { mx: e.clientX, my: e.clientY, px: pan.x, py: pan.y };
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (!isPanning || !panStart.current) return;
    setPan({
      x: panStart.current.px + (e.clientX - panStart.current.mx),
      y: panStart.current.py + (e.clientY - panStart.current.my),
    });
  };

  const handleMouseUp = () => {
    setIsPanning(false);
    panStart.current = null;
  };

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setZoom((z) => Math.min(3, Math.max(0.3, z - e.deltaY * 0.001)));
  };

  const handleZoomIn = () => setZoom((z) => Math.min(3, z + 0.2));
  const handleZoomOut = () => setZoom((z) => Math.max(0.3, z - 0.2));
  const handleReset = () => { setZoom(1); setPan({ x: 0, y: 0 }); };

  // ─── Render ──────────────────────────────────────────────────────────────────

  const nodeMap = useMemo(
    () => new Map(graphData.nodes.map((n) => [n.id, n])),
    [graphData.nodes]
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <Card>
        <CardHeader>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <CardTitle>Trust Graph Visualizer</CardTitle>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ fontSize: 13, color: 'var(--color-text-secondary)' }}>Depth:</span>
              {[1, 2, 3, 4].map((d) => (
                <Button
                  key={d}
                  variant={currentDepth === d ? 'default' : 'outline'}
                  onClick={() => setCurrentDepth(d)}
                  aria-label={`depth ${d}`}
                  style={{ padding: '4px 10px', minWidth: 32 }}
                >
                  {d}
                </Button>
              ))}
              <Button variant="outline" onClick={loadGraph} disabled={loading} style={{ marginLeft: 8 }}>
                {loading ? '⟳' : '↺ Refresh'}
              </Button>
            </div>
          </div>
        </CardHeader>
      </Card>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* Graph + Detail panel */}
      <div style={{ display: 'flex', gap: 16 }}>
        {/* SVG canvas */}
        <Card style={{ flex: 1, overflow: 'hidden', position: 'relative' }}>
          {/* Zoom / pan controls */}
          <div style={{ position: 'absolute', top: 12, right: 12, zIndex: 10, display: 'flex', flexDirection: 'column', gap: 4 }}>
            <Button variant="outline" onClick={handleZoomIn} aria-label="zoom in" style={{ padding: '4px 8px' }}>+</Button>
            <Button variant="outline" onClick={handleZoomOut} aria-label="zoom out" style={{ padding: '4px 8px' }}>−</Button>
            <Button variant="outline" onClick={handleReset} aria-label="reset view" style={{ padding: '4px 8px', fontSize: 11 }}>⌂</Button>
          </div>

          <svg
            ref={svgRef}
            width="100%"
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            style={{ display: 'block', cursor: isPanning ? 'grabbing' : 'grab', minHeight: HEIGHT }}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
            aria-label="trust graph"
            role="img"
          >
            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {/* Edges */}
              {graphData.edges.map((edge) => {
                const from = positions.get(edge.from);
                const to = positions.get(edge.to);
                if (!from || !to) return null;
                return (
                  <line
                    key={edge.id}
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    stroke="#94a3b8"
                    strokeWidth={edgeWidth(edge.weight)}
                    strokeOpacity={0.7}
                    aria-label={`edge from ${edge.from} to ${edge.to} weight ${edge.weight}`}
                  />
                );
              })}

              {/* Nodes */}
              {graphData.nodes.map((node) => {
                const pos = positions.get(node.id);
                if (!pos) return null;
                const isSelected = selectedNode?.id === node.id;
                const fillColor = TIER_COLORS[node.tier] ?? '#94a3b8';
                const textColor = TIER_TEXT_COLORS[node.tier] ?? '#333';
                return (
                  <g
                    key={node.id}
                    transform={`translate(${pos.x},${pos.y})`}
                    onClick={() => setSelectedNode(isSelected ? null : node)}
                    style={{ cursor: 'pointer' }}
                    role="button"
                    aria-label={`node ${node.address}`}
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && setSelectedNode(isSelected ? null : node)}
                  >
                    <circle
                      r={NODE_RADIUS}
                      fill={fillColor}
                      stroke={isSelected ? '#1d4ed8' : '#64748b'}
                      strokeWidth={isSelected ? 3 : 1.5}
                    />
                    <text
                      textAnchor="middle"
                      dominantBaseline="middle"
                      fontSize={9}
                      fontWeight={600}
                      fill={textColor}
                      style={{ pointerEvents: 'none', userSelect: 'none' }}
                    >
                      {node.address.slice(0, 6)}…
                    </text>
                    <text
                      y={NODE_RADIUS + 12}
                      textAnchor="middle"
                      fontSize={9}
                      fill="#475569"
                      style={{ pointerEvents: 'none', userSelect: 'none' }}
                    >
                      {node.tier}
                    </text>
                  </g>
                );
              })}
            </g>

            {/* Empty state */}
            {graphData.nodes.length === 0 && !loading && (
              <text
                x={WIDTH / 2}
                y={HEIGHT / 2}
                textAnchor="middle"
                fontSize={14}
                fill="#94a3b8"
              >
                No trust relationships found
              </text>
            )}

            {loading && (
              <text
                x={WIDTH / 2}
                y={HEIGHT / 2}
                textAnchor="middle"
                fontSize={14}
                fill="#94a3b8"
              >
                Loading graph…
              </text>
            )}
          </svg>
        </Card>

        {/* Detail panel */}
        <div style={{ width: 220, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Legend */}
          <Card>
            <CardHeader>
              <CardTitle style={{ fontSize: 14 }}>Reputation Tiers</CardTitle>
            </CardHeader>
            <CardContent>
              {(Object.keys(TIER_COLORS) as ReputationTier[]).map((tier) => (
                <div key={tier} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <div
                    style={{
                      width: 14,
                      height: 14,
                      borderRadius: '50%',
                      backgroundColor: TIER_COLORS[tier],
                      border: '1px solid #64748b',
                      flexShrink: 0,
                    }}
                  />
                  <span style={{ fontSize: 13 }}>{tier}</span>
                </div>
              ))}
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--color-text-secondary)' }}>
                Edge thickness = attestation weight
              </div>
            </CardContent>
          </Card>

          {/* Stats */}
          <Card>
            <CardHeader>
              <CardTitle style={{ fontSize: 14 }}>Graph Stats</CardTitle>
            </CardHeader>
            <CardContent>
              <div style={{ fontSize: 13 }}>
                <div style={{ marginBottom: 4 }}>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Nodes: </span>
                  <strong>{graphData.nodes.length}</strong>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-secondary)' }}>Edges: </span>
                  <strong>{graphData.edges.length}</strong>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Node detail */}
          {selectedNode && (
            <Card>
              <CardHeader>
                <CardTitle style={{ fontSize: 14 }}>Node Detail</CardTitle>
              </CardHeader>
              <CardContent>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13 }}>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Address</span>
                    <div
                      style={{
                        fontFamily: 'monospace',
                        fontSize: 11,
                        wordBreak: 'break-all',
                        marginTop: 2,
                      }}
                    >
                      {selectedNode.address}
                    </div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Tier</span>
                    <Badge
                      style={{
                        backgroundColor: TIER_COLORS[selectedNode.tier],
                        color: TIER_TEXT_COLORS[selectedNode.tier],
                        fontSize: 11,
                      }}
                    >
                      {selectedNode.tier}
                    </Badge>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Score</span>
                    <strong>{selectedNode.reputationScore}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--color-text-secondary)' }}>Trusts</span>
                    <strong>{selectedNode.trustCount}</strong>
                  </div>
                  <div>
                    <span style={{ color: 'var(--color-text-secondary)' }}>
                      Attestations ({selectedNode.attestations.length})
                    </span>
                    {selectedNode.attestations.slice(0, 5).map((att) => (
                      <div
                        key={att.id}
                        style={{
                          marginTop: 4,
                          padding: '4px 6px',
                          background: 'var(--color-bg-tertiary)',
                          borderRadius: 4,
                          fontSize: 11,
                        }}
                      >
                        <div>{att.type}</div>
                        <div style={{ color: 'var(--color-text-secondary)' }}>
                          Weight: {att.weight}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
};
