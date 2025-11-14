import { useState, useEffect } from 'react';
import { TransformWrapper, TransformComponent } from 'react-zoom-pan-pinch';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Server, 
  Monitor, 
  Shield, 
  Skull, 
  Lock, 
  Unlock,
  Wifi,
  Database,
  AlertTriangle
} from 'lucide-react';

interface Node {
  id: string;
  label: string;
  type: 'attacker' | 'workstation' | 'server' | 'dc' | 'router';
  x: number;
  y: number;
  ip: string;
  os?: string;
  services?: string[];
  isCompromised?: boolean;
  isActive?: boolean;
}

interface Edge {
  from: string;
  to: string;
  label?: string;
  isActive?: boolean;
  trafficType?: 'attack' | 'response' | 'lateral';
}

interface InteractiveNetworkMapProps {
  network: {
    attacker: { hostname: string; ip: string };
    target: { hostname: string; ip: string };
    dc?: { hostname: string; ip: string };
    domain: string;
  };
  highlightedMachine: string | null;
  highlightedArrow: string | null;
  compromisedNodes: string[];
  onNodeClick?: (nodeId: string) => void;
  currentStep?: number;
  showTraffic?: boolean;
}

export default function InteractiveNetworkMap({
  network,
  highlightedMachine,
  highlightedArrow,
  compromisedNodes,
  onNodeClick,
  currentStep = 0,
  showTraffic = true
}: InteractiveNetworkMapProps) {
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const [trafficPackets, setTrafficPackets] = useState<Array<{ id: string; from: string; to: string }>>([]);

  // Define node positions (adjust based on your layout)
  const nodes: Node[] = [
    {
      id: 'attacker',
      label: network.attacker.hostname,
      type: 'attacker',
      x: 100,
      y: 300,
      ip: network.attacker.ip,
      os: 'Kali Linux',
      services: ['SSH', 'HTTP'],
      isCompromised: true,
      isActive: highlightedMachine === 'attacker'
    },
    {
      id: 'target',
      label: network.target.hostname,
      type: 'server',
      x: 400,
      y: 300,
      ip: network.target.ip,
      os: 'Windows Server 2019',
      services: ['RDP', 'SMB', 'WinRM'],
      isCompromised: compromisedNodes.includes('target'),
      isActive: highlightedMachine === 'target'
    },
    {
      id: 'dc',
      label: network.dc?.hostname || 'DC01',
      type: 'dc',
      x: 700,
      y: 300,
      ip: network.dc?.ip || '10.0.1.10',
      os: 'Windows Server 2019',
      services: ['LDAP', 'Kerberos', 'DNS', 'SMB'],
      isCompromised: compromisedNodes.includes('dc'),
      isActive: highlightedMachine === 'dc'
    }
  ];

  const edges: Edge[] = [
    {
      from: 'attacker',
      to: 'target',
      label: 'Initial Access',
      isActive: highlightedArrow === 'attacker-to-target',
      trafficType: 'attack'
    },
    {
      from: 'target',
      to: 'dc',
      label: 'Lateral Movement',
      isActive: highlightedArrow === 'target-to-dc',
      trafficType: 'lateral'
    }
  ];

  // Simulate traffic packets when edge is active
  useEffect(() => {
    if (highlightedArrow && showTraffic) {
      const edge = edges.find(e => 
        `${e.from}-to-${e.to}` === highlightedArrow
      );
      
      if (edge) {
        const packetId = `packet-${Date.now()}`;
        setTrafficPackets(prev => [...prev, { 
          id: packetId, 
          from: edge.from, 
          to: edge.to 
        }]);

        // Remove packet after animation
        setTimeout(() => {
          setTrafficPackets(prev => prev.filter(p => p.id !== packetId));
        }, 2000);
      }
    }
  }, [highlightedArrow, showTraffic]);

  const getNodeIcon = (type: Node['type'], isCompromised: boolean) => {
    if (isCompromised && type !== 'attacker') {
      return <Skull className="w-8 h-8 text-red-500" />;
    }
    
    switch (type) {
      case 'attacker':
        return <Monitor className="w-8 h-8 text-cyan-400" />;
      case 'dc':
        return <Database className="w-8 h-8 text-purple-400" />;
      case 'server':
        return <Server className="w-8 h-8 text-blue-400" />;
      default:
        return <Monitor className="w-8 h-8 text-gray-400" />;
    }
  };

  const getNodeColor = (node: Node) => {
    if (node.type === 'attacker') return 'rgb(34, 211, 238)'; // cyan
    if (node.isCompromised) return 'rgb(239, 68, 68)'; // red
    if (node.isActive) return 'rgb(34, 197, 94)'; // green
    return 'rgb(156, 163, 175)'; // gray
  };

  const getEdgePath = (from: Node, to: Node): string => {
    const midX = (from.x + to.x) / 2;
    const midY = (from.y + to.y) / 2;
    const offset = 30;
    
    return `M ${from.x + 50} ${from.y + 50} 
            Q ${midX} ${midY - offset} 
            ${to.x + 50} ${to.y + 50}`;
  };

  return (
    <div className="w-full h-full bg-[#0a0b0d] rounded-lg border border-white/5 overflow-hidden">
      {/* Controls */}
      <div className="absolute top-4 right-4 z-10 flex gap-2">
        <div className="bg-[#101214]/90 backdrop-blur-sm px-3 py-1.5 rounded-md text-xs text-white/60 border border-white/5">
          <Wifi className="w-3 h-3 inline mr-1" />
          {network.domain}
        </div>
        <div className="bg-[#101214]/90 backdrop-blur-sm px-3 py-1.5 rounded-md text-xs text-white/60 border border-white/5">
          Step {currentStep}
        </div>
      </div>

      <TransformWrapper
        initialScale={1}
        minScale={0.5}
        maxScale={3}
        centerOnInit
        wheel={{ smoothStep: 0.01 }}
      >
        {({ zoomIn, zoomOut, resetTransform }) => (
          <>
            {/* Zoom Controls */}
            <div className="absolute bottom-4 right-4 z-10 flex flex-col gap-2">
              <button
                onClick={() => zoomIn()}
                className="bg-[#101214]/90 backdrop-blur-sm p-2 rounded-md text-white/80 hover:text-white border border-white/5 hover:border-[#2D9CDB] transition-all"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
              </button>
              <button
                onClick={() => zoomOut()}
                className="bg-[#101214]/90 backdrop-blur-sm p-2 rounded-md text-white/80 hover:text-white border border-white/5 hover:border-[#2D9CDB] transition-all"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
                </svg>
              </button>
              <button
                onClick={() => resetTransform()}
                className="bg-[#101214]/90 backdrop-blur-sm p-2 rounded-md text-white/80 hover:text-white border border-white/5 hover:border-[#2D9CDB] transition-all"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>

            <TransformComponent
              wrapperStyle={{ width: '100%', height: '100%' }}
              contentStyle={{ width: '100%', height: '100%' }}
            >
              <svg width="900" height="600" className="w-full h-full">
                <defs>
                  {/* Glow effects */}
                  <filter id="glow">
                    <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>

                  {/* Arrow markers */}
                  <marker
                    id="arrowhead"
                    markerWidth="10"
                    markerHeight="10"
                    refX="9"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 10 3, 0 6" fill="#2D9CDB" />
                  </marker>

                  <marker
                    id="arrowhead-active"
                    markerWidth="10"
                    markerHeight="10"
                    refX="9"
                    refY="3"
                    orient="auto"
                  >
                    <polygon points="0 0, 10 3, 0 6" fill="#22c55e" />
                  </marker>
                </defs>

                {/* Edges */}
                <g className="edges">
                  {edges.map((edge, idx) => {
                    const fromNode = nodes.find(n => n.id === edge.from);
                    const toNode = nodes.find(n => n.id === edge.to);
                    if (!fromNode || !toNode) return null;

                    return (
                      <g key={idx}>
                        <motion.path
                          d={getEdgePath(fromNode, toNode)}
                          stroke={edge.isActive ? '#22c55e' : '#2D9CDB'}
                          strokeWidth={edge.isActive ? 3 : 2}
                          fill="none"
                          markerEnd={edge.isActive ? 'url(#arrowhead-active)' : 'url(#arrowhead)'}
                          opacity={edge.isActive ? 1 : 0.3}
                          initial={{ pathLength: 0 }}
                          animate={{ 
                            pathLength: 1,
                            opacity: edge.isActive ? [0.3, 1, 0.3] : 0.3
                          }}
                          transition={{ 
                            pathLength: { duration: 1 },
                            opacity: edge.isActive ? { 
                              duration: 2, 
                              repeat: Infinity,
                              ease: "easeInOut"
                            } : { duration: 0 }
                          }}
                          filter={edge.isActive ? 'url(#glow)' : undefined}
                        />
                        
                        {/* Edge label */}
                        {edge.label && (
                          <text
                            x={(fromNode.x + toNode.x) / 2 + 50}
                            y={(fromNode.y + toNode.y) / 2 + 20}
                            fill="white"
                            fontSize="11"
                            opacity={0.6}
                            textAnchor="middle"
                          >
                            {edge.label}
                          </text>
                        )}

                        {/* Animated traffic packets */}
                        <AnimatePresence>
                          {trafficPackets
                            .filter(p => p.from === edge.from && p.to === edge.to)
                            .map(packet => (
                              <motion.circle
                                key={packet.id}
                                r="4"
                                fill="#22c55e"
                                filter="url(#glow)"
                                initial={{ 
                                  offsetDistance: '0%',
                                  scale: 0
                                }}
                                animate={{ 
                                  offsetDistance: '100%',
                                  scale: [0, 1.5, 1, 0]
                                }}
                                exit={{ scale: 0 }}
                                transition={{ duration: 2, ease: "linear" }}
                                style={{
                                  offsetPath: `path('${getEdgePath(fromNode, toNode)}')`,
                                }}
                              />
                            ))}
                        </AnimatePresence>
                      </g>
                    );
                  })}
                </g>

                {/* Nodes */}
                <g className="nodes">
                  {nodes.map((node) => (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      onMouseEnter={() => setHoveredNode(node.id)}
                      onMouseLeave={() => setHoveredNode(null)}
                      onClick={() => onNodeClick?.(node.id)}
                      className="cursor-pointer"
                    >
                      {/* Node glow on hover/active */}
                      {(node.isActive || hoveredNode === node.id) && (
                        <motion.circle
                          cx="50"
                          cy="50"
                          r="45"
                          fill={getNodeColor(node)}
                          opacity={0.2}
                          initial={{ scale: 0.8 }}
                          animate={{ scale: [0.8, 1.2, 0.8] }}
                          transition={{ duration: 2, repeat: Infinity }}
                        />
                      )}

                      {/* Node background */}
                      <motion.rect
                        x="0"
                        y="0"
                        width="100"
                        height="100"
                        rx="12"
                        fill="#101214"
                        stroke={getNodeColor(node)}
                        strokeWidth={node.isActive ? 3 : 2}
                        whileHover={{ scale: 1.05 }}
                        transition={{ type: "spring", stiffness: 300 }}
                      />

                      {/* Compromise indicator */}
                      {node.isCompromised && node.type !== 'attacker' && (
                        <motion.circle
                          cx="90"
                          cy="10"
                          r="8"
                          fill="#ef4444"
                          initial={{ scale: 0 }}
                          animate={{ scale: [0, 1.2, 1] }}
                          transition={{ duration: 0.5 }}
                        />
                      )}

                      {/* Node icon */}
                      <foreignObject x="30" y="15" width="40" height="40">
                        {getNodeIcon(node.type, node.isCompromised || false)}
                      </foreignObject>

                      {/* Node label */}
                      <text
                        x="50"
                        y="70"
                        fill="white"
                        fontSize="12"
                        fontWeight="600"
                        textAnchor="middle"
                      >
                        {node.label}
                      </text>

                      {/* Node IP */}
                      <text
                        x="50"
                        y="85"
                        fill="white"
                        fontSize="9"
                        opacity={0.6}
                        textAnchor="middle"
                      >
                        {node.ip}
                      </text>

                      {/* Hover tooltip */}
                      {hoveredNode === node.id && (
                        <g>
                          <rect
                            x="110"
                            y="0"
                            width="180"
                            height="auto"
                            rx="6"
                            fill="#1a1b1e"
                            stroke="#2D9CDB"
                            strokeWidth="1"
                          />
                          <text x="120" y="20" fill="white" fontSize="11" fontWeight="600">
                            {node.label}
                          </text>
                          <text x="120" y="35" fill="white" fontSize="9" opacity={0.7}>
                            OS: {node.os}
                          </text>
                          <text x="120" y="50" fill="white" fontSize="9" opacity={0.7}>
                            Services: {node.services?.join(', ')}
                          </text>
                          {node.isCompromised && (
                            <text x="120" y="65" fill="#ef4444" fontSize="9" fontWeight="600">
                              ⚠️ COMPROMISED
                            </text>
                          )}
                        </g>
                      )}
                    </g>
                  ))}
                </g>
              </svg>
            </TransformComponent>
          </>
        )}
      </TransformWrapper>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 bg-[#101214]/90 backdrop-blur-sm p-3 rounded-md border border-white/5 text-xs space-y-2">
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-cyan-400"></div>
          <span className="text-white/60">Attacker Machine</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-blue-400"></div>
          <span className="text-white/60">Target Server</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500"></div>
          <span className="text-white/60">Compromised</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-green-500"></div>
          <span className="text-white/60">Active Connection</span>
        </div>
      </div>
    </div>
  );
}
