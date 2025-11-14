import { useState, useEffect, useCallback } from 'react';
import { TransformWrapper, TransformComponent } from 'react-zoom-pan-pinch';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  Server, 
  Monitor, 
  Shield, 
  Skull, 
  Database,
  Wifi,
  Zap,
  Lock,
  Unlock,
  AlertTriangle,
  Eye,
  Activity,
  Network,
  HardDrive,
  Globe
} from 'lucide-react';

interface Node {
  id: string;
  label: string;
  type: 'attacker' | 'workstation' | 'server' | 'dc' | 'router' | 'firewall';
  x: number;
  y: number;
  ip: string;
  os?: string;
  services?: string[];
  isCompromised?: boolean;
  isActive?: boolean;
  securityLevel?: 'high' | 'medium' | 'low';
}

interface Edge {
  from: string;
  to: string;
  label?: string;
  isActive?: boolean;
  trafficType?: 'attack' | 'response' | 'lateral';
}

interface NetworkPacket {
  id: string;
  from: string;
  to: string;
  progress: number;
  type: 'attack' | 'response' | 'lateral';
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
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [packets, setPackets] = useState<NetworkPacket[]>([]);
  const [showGrid, setShowGrid] = useState(true);
  const [animationSpeed, setAnimationSpeed] = useState(1);

  // Enhanced node configuration with better positioning
  const nodes: Node[] = [
    {
      id: 'attacker',
      label: network.attacker.hostname,
      type: 'attacker',
      x: 50,
      y: 200,
      ip: network.attacker.ip,
      os: 'Kali Linux 2024.3',
      services: ['SSH', 'HTTP', 'Metasploit'],
      isCompromised: true,
      isActive: highlightedMachine === 'attacker',
      securityLevel: 'low'
    },
    {
      id: 'router',
      label: 'Network Gateway',
      type: 'router',
      x: 250,
      y: 200,
      ip: '10.0.0.1',
      os: 'pfSense',
      services: ['NAT', 'Firewall'],
      isCompromised: false,
      isActive: false,
      securityLevel: 'high'
    },
    {
      id: 'target',
      label: network.target.hostname,
      type: 'server',
      x: 450,
      y: 200,
      ip: network.target.ip,
      os: 'Windows Server 2019',
      services: ['RDP', 'SMB', 'WinRM', 'HTTP'],
      isCompromised: compromisedNodes.includes('target'),
      isActive: highlightedMachine === 'target',
      securityLevel: 'medium'
    },
    {
      id: 'dc',
      label: network.dc?.hostname || 'DC01',
      type: 'dc',
      x: 650,
      y: 200,
      ip: network.dc?.ip || '10.0.1.10',
      os: 'Windows Server 2019',
      services: ['LDAP', 'Kerberos', 'DNS', 'SMB', 'NTDS'],
      isCompromised: compromisedNodes.includes('dc'),
      isActive: highlightedMachine === 'dc',
      securityLevel: 'high'
    },
    {
      id: 'workstation',
      label: 'ADMIN-PC',
      type: 'workstation',
      x: 450,
      y: 50,
      ip: '10.0.1.25',
      os: 'Windows 11 Pro',
      services: ['RDP', 'SMB'],
      isCompromised: compromisedNodes.includes('workstation'),
      isActive: highlightedMachine === 'workstation',
      securityLevel: 'medium'
    }
  ];

  const edges: Edge[] = [
    {
      from: 'attacker',
      to: 'router',
      label: 'External',
      isActive: highlightedArrow === 'attacker-to-router',
      trafficType: 'attack'
    },
    {
      from: 'router',
      to: 'target',
      label: 'DMZ',
      isActive: highlightedArrow === 'router-to-target' || highlightedArrow === 'attacker-to-target',
      trafficType: 'attack'
    },
    {
      from: 'target',
      to: 'dc',
      label: 'Internal',
      isActive: highlightedArrow === 'target-to-dc',
      trafficType: 'lateral'
    },
    {
      from: 'target',
      to: 'workstation',
      label: 'Lateral',
      isActive: highlightedArrow === 'target-to-workstation',
      trafficType: 'lateral'
    },
    {
      from: 'dc',
      to: 'workstation',
      label: 'Domain',
      isActive: highlightedArrow === 'dc-to-workstation',
      trafficType: 'response'
    }
  ];

  // Packet animation system
  useEffect(() => {
    if (!showTraffic) return;

    const activeEdge = edges.find(e => e.isActive);
    if (!activeEdge) return;

    const interval = setInterval(() => {
      const newPacket: NetworkPacket = {
        id: `pkt-${Date.now()}-${Math.random()}`,
        from: activeEdge.from,
        to: activeEdge.to,
        progress: 0,
        type: activeEdge.trafficType || 'attack'
      };

      setPackets(prev => [...prev, newPacket]);

      // Animate packet
      const duration = 2000 / animationSpeed;
      const startTime = Date.now();

      const animate = () => {
        const elapsed = Date.now() - startTime;
        const progress = Math.min(elapsed / duration, 1);

        setPackets(prev => 
          prev.map(p => 
            p.id === newPacket.id ? { ...p, progress } : p
          )
        );

        if (progress < 1) {
          requestAnimationFrame(animate);
        } else {
          setPackets(prev => prev.filter(p => p.id !== newPacket.id));
        }
      };

      requestAnimationFrame(animate);
    }, 500 / animationSpeed);

    return () => clearInterval(interval);
  }, [edges, showTraffic, animationSpeed]);

  const getNodeIcon = (type: Node['type'], isCompromised: boolean) => {
    if (isCompromised && type !== 'attacker') {
      return <Skull className="w-10 h-10 text-red-500" />;
    }
    
    switch (type) {
      case 'attacker':
        return <Monitor className="w-10 h-10 text-cyan-400" />;
      case 'dc':
        return <Database className="w-10 h-10 text-purple-400" />;
      case 'server':
        return <Server className="w-10 h-10 text-blue-400" />;
      case 'workstation':
        return <Monitor className="w-10 h-10 text-green-400" />;
      case 'router':
        return <Network className="w-10 h-10 text-orange-400" />;
      case 'firewall':
        return <Shield className="w-10 h-10 text-yellow-400" />;
      default:
        return <HardDrive className="w-10 h-10 text-gray-400" />;
    }
  };

  const getNodeColor = (node: Node) => {
    if (node.type === 'attacker') return '#22d3ee'; // cyan
    if (node.isCompromised) return '#ef4444'; // red
    if (node.isActive) return '#22c55e'; // green
    if (selectedNode === node.id) return '#2D9CDB'; // blue
    return '#6b7280'; // gray
  };

  const getSecurityLevelColor = (level?: string) => {
    switch (level) {
      case 'high': return '#22c55e';
      case 'medium': return '#eab308';
      case 'low': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getEdgePath = (from: Node, to: Node): string => {
    const fromX = from.x + 60;
    const fromY = from.y + 60;
    const toX = to.x + 60;
    const toY = to.y + 60;
    
    const midX = (fromX + toX) / 2;
    const midY = (fromY + toY) / 2;
    const offset = 20;
    
    return `M ${fromX} ${fromY} Q ${midX} ${midY - offset} ${toX} ${toY}`;
  };

  const getPacketPosition = (packet: NetworkPacket) => {
    const fromNode = nodes.find(n => n.id === packet.from);
    const toNode = nodes.find(n => n.id === packet.to);
    if (!fromNode || !toNode) return { x: 0, y: 0 };

    const fromX = fromNode.x + 60;
    const fromY = fromNode.y + 60;
    const toX = toNode.x + 60;
    const toY = toNode.y + 60;

    const midX = (fromX + toX) / 2;
    const midY = (fromY + toY) / 2;
    const offset = 20;

    // Quadratic Bezier curve interpolation
    const t = packet.progress;
    const x = (1 - t) * (1 - t) * fromX + 2 * (1 - t) * t * midX + t * t * toX;
    const y = (1 - t) * (1 - t) * fromY + 2 * (1 - t) * t * (midY - offset) + t * t * toY;

    return { x, y };
  };

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNode(nodeId);
    onNodeClick?.(nodeId);
  }, [onNodeClick]);

  return (
    <div className="relative w-full h-full bg-[#0a0b0d] rounded-lg border border-white/10 overflow-hidden">
      {/* Top Controls Bar */}
      <div className="absolute top-0 left-0 right-0 z-20 bg-gradient-to-b from-[#0a0b0d] to-transparent p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="bg-[#101214]/90 backdrop-blur-sm px-3 py-2 rounded-lg border border-white/10 flex items-center gap-2">
            <Globe className="w-4 h-4 text-[#2D9CDB]" />
            <span className="text-sm font-semibold text-white">{network.domain}</span>
          </div>
          <div className="bg-[#101214]/90 backdrop-blur-sm px-3 py-2 rounded-lg border border-white/10 flex items-center gap-2">
            <Activity className="w-4 h-4 text-green-400" />
            <span className="text-xs text-white/60">Step {currentStep}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Grid Toggle */}
          <button
            onClick={() => setShowGrid(!showGrid)}
            className={`bg-[#101214]/90 backdrop-blur-sm p-2 rounded-lg border transition-all ${
              showGrid 
                ? 'border-[#2D9CDB] text-[#2D9CDB]' 
                : 'border-white/10 text-white/40 hover:text-white/60'
            }`}
            title="Toggle Grid"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM14 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zM14 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
            </svg>
          </button>

          {/* Traffic Toggle */}
          <button
            onClick={() => setShowGrid(!showTraffic)}
            className={`bg-[#101214]/90 backdrop-blur-sm p-2 rounded-lg border transition-all ${
              showTraffic 
                ? 'border-[#2D9CDB] text-[#2D9CDB]' 
                : 'border-white/10 text-white/40 hover:text-white/60'
            }`}
            title="Toggle Traffic Animation"
          >
            <Zap className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Canvas */}
      <TransformWrapper
        initialScale={1}
        minScale={0.5}
        maxScale={2.5}
        centerOnInit={true}
        wheel={{ smoothStep: 0.005 }}
        limitToBounds={false}
      >
        {({ zoomIn, zoomOut, resetTransform }) => (
          <>
            {/* Zoom Controls */}
            <div className="absolute bottom-4 right-4 z-20 flex flex-col gap-2">
              <button
                onClick={() => zoomIn()}
                className="bg-[#101214]/95 backdrop-blur-sm p-3 rounded-lg text-white/80 hover:text-white border border-white/10 hover:border-[#2D9CDB] transition-all shadow-lg hover:shadow-[#2D9CDB]/20"
                title="Zoom In"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                </svg>
              </button>
              <button
                onClick={() => zoomOut()}
                className="bg-[#101214]/95 backdrop-blur-sm p-3 rounded-lg text-white/80 hover:text-white border border-white/10 hover:border-[#2D9CDB] transition-all shadow-lg hover:shadow-[#2D9CDB]/20"
                title="Zoom Out"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
                </svg>
              </button>
              <button
                onClick={() => resetTransform()}
                className="bg-[#101214]/95 backdrop-blur-sm p-3 rounded-lg text-white/80 hover:text-white border border-white/10 hover:border-[#2D9CDB] transition-all shadow-lg hover:shadow-[#2D9CDB]/20"
                title="Reset View"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
              </button>
            </div>

            <TransformComponent
              wrapperClass="!w-full !h-full"
              contentClass="!w-full !h-full flex items-center justify-center"
            >
              <svg 
                width="800" 
                height="400" 
                viewBox="0 0 800 400"
                className="w-full h-full"
                style={{ minHeight: '400px' }}
              >
                <defs>
                  {/* Enhanced Glow Filter */}
                  <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                    <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>

                  {/* Strong Glow for Active Elements */}
                  <filter id="strongGlow" x="-100%" y="-100%" width="300%" height="300%">
                    <feGaussianBlur stdDeviation="6" result="coloredBlur"/>
                    <feMerge>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="coloredBlur"/>
                      <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                  </filter>

                  {/* Arrow Markers */}
                  <marker
                    id="arrowhead"
                    markerWidth="10"
                    markerHeight="10"
                    refX="9"
                    refY="3"
                    orient="auto"
                    markerUnits="strokeWidth"
                  >
                    <polygon points="0 0, 10 3, 0 6" fill="#2D9CDB" opacity="0.6" />
                  </marker>

                  <marker
                    id="arrowhead-active"
                    markerWidth="12"
                    markerHeight="12"
                    refX="10"
                    refY="3"
                    orient="auto"
                    markerUnits="strokeWidth"
                  >
                    <polygon points="0 0, 10 3, 0 6" fill="#22c55e" filter="url(#glow)" />
                  </marker>

                  <marker
                    id="arrowhead-compromised"
                    markerWidth="12"
                    markerHeight="12"
                    refX="10"
                    refY="3"
                    orient="auto"
                    markerUnits="strokeWidth"
                  >
                    <polygon points="0 0, 10 3, 0 6" fill="#ef4444" filter="url(#glow)" />
                  </marker>

                  {/* Grid Pattern */}
                  <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                    <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="1"/>
                  </pattern>
                </defs>

                {/* Background Grid */}
                {showGrid && (
                  <rect width="800" height="400" fill="url(#grid)" />
                )}

                {/* Edges Layer */}
                <g className="edges">
                  {edges.map((edge, idx) => {
                    const fromNode = nodes.find(n => n.id === edge.from);
                    const toNode = nodes.find(n => n.id === edge.to);
                    if (!fromNode || !toNode) return null;

                    const isCompromisedPath = fromNode.isCompromised && toNode.isCompromised;

                    return (
                      <g key={`edge-${idx}`}>
                        {/* Shadow/Backdrop */}
                        <motion.path
                          d={getEdgePath(fromNode, toNode)}
                          stroke="#000"
                          strokeWidth={edge.isActive ? 5 : 3}
                          fill="none"
                          opacity={0.3}
                        />
                        
                        {/* Main Path */}
                        <motion.path
                          d={getEdgePath(fromNode, toNode)}
                          stroke={
                            edge.isActive 
                              ? '#22c55e' 
                              : isCompromisedPath 
                                ? '#ef4444' 
                                : '#2D9CDB'
                          }
                          strokeWidth={edge.isActive ? 3 : 2}
                          fill="none"
                          markerEnd={
                            edge.isActive 
                              ? 'url(#arrowhead-active)' 
                              : isCompromisedPath
                                ? 'url(#arrowhead-compromised)'
                                : 'url(#arrowhead)'
                          }
                          opacity={edge.isActive ? 1 : 0.4}
                          strokeDasharray={edge.isActive ? "0" : "5,5"}
                          initial={{ pathLength: 0, opacity: 0 }}
                          animate={{ 
                            pathLength: 1,
                            opacity: edge.isActive ? 1 : 0.4,
                            strokeDashoffset: edge.isActive ? [0, -10] : 0
                          }}
                          transition={{ 
                            pathLength: { duration: 0.8 },
                            strokeDashoffset: edge.isActive ? {
                              duration: 1,
                              repeat: Infinity,
                              ease: "linear"
                            } : { duration: 0 }
                          }}
                          filter={edge.isActive ? 'url(#strongGlow)' : undefined}
                        />
                        
                        {/* Edge Label */}
                        {edge.label && (
                          <text
                            x={(fromNode.x + toNode.x) / 2 + 60}
                            y={(fromNode.y + toNode.y) / 2 + 50}
                            fill="white"
                            fontSize="10"
                            fontWeight="600"
                            opacity={edge.isActive ? 0.9 : 0.5}
                            textAnchor="middle"
                            className="pointer-events-none select-none"
                          >
                            {edge.label}
                          </text>
                        )}
                      </g>
                    );
                  })}
                </g>

                {/* Traffic Packets Layer */}
                <g className="packets">
                  {packets.map(packet => {
                    const pos = getPacketPosition(packet);
                    const color = packet.type === 'attack' ? '#ef4444' : packet.type === 'lateral' ? '#eab308' : '#22c55e';
                    
                    return (
                      <g key={packet.id}>
                        <circle
                          cx={pos.x}
                          cy={pos.y}
                          r="6"
                          fill={color}
                          filter="url(#strongGlow)"
                          opacity={0.9}
                        />
                        <circle
                          cx={pos.x}
                          cy={pos.y}
                          r="3"
                          fill="white"
                          opacity={0.8}
                        />
                      </g>
                    );
                  })}
                </g>

                {/* Nodes Layer */}
                <g className="nodes">
                  {nodes.map((node) => (
                    <g
                      key={node.id}
                      transform={`translate(${node.x}, ${node.y})`}
                      onMouseEnter={() => setHoveredNode(node.id)}
                      onMouseLeave={() => setHoveredNode(null)}
                      onClick={() => handleNodeClick(node.id)}
                      className="cursor-pointer"
                      style={{ transition: 'all 0.3s ease' }}
                    >
                      {/* Active Pulse Ring */}
                      {(node.isActive || hoveredNode === node.id) && (
                        <>
                          <motion.circle
                            cx="60"
                            cy="60"
                            r="55"
                            fill="none"
                            stroke={getNodeColor(node)}
                            strokeWidth="2"
                            opacity={0.4}
                            initial={{ scale: 0.9, opacity: 0.6 }}
                            animate={{ 
                              scale: [0.9, 1.2, 0.9],
                              opacity: [0.6, 0.2, 0.6]
                            }}
                            transition={{ 
                              duration: 2,
                              repeat: Infinity,
                              ease: "easeInOut"
                            }}
                          />
                          <motion.circle
                            cx="60"
                            cy="60"
                            r="50"
                            fill={getNodeColor(node)}
                            opacity={0.15}
                            initial={{ scale: 0.8 }}
                            animate={{ scale: [0.8, 1.1, 0.8] }}
                            transition={{ duration: 2, repeat: Infinity }}
                          />
                        </>
                      )}

                      {/* Node Background Card */}
                      <motion.rect
                        x="0"
                        y="0"
                        width="120"
                        height="120"
                        rx="16"
                        fill="#101214"
                        stroke={getNodeColor(node)}
                        strokeWidth={node.isActive || hoveredNode === node.id ? 3 : 2}
                        filter={node.isActive ? "url(#glow)" : undefined}
                        whileHover={{ scale: 1.05 }}
                        transition={{ type: "spring", stiffness: 400, damping: 17 }}
                      />

                      {/* Security Level Indicator */}
                      <circle
                        cx="105"
                        cy="15"
                        r="6"
                        fill={getSecurityLevelColor(node.securityLevel)}
                        stroke="#101214"
                        strokeWidth="2"
                      />

                      {/* Compromise Badge */}
                      {node.isCompromised && node.type !== 'attacker' && (
                        <g>
                          <motion.circle
                            cx="105"
                            cy="105"
                            r="12"
                            fill="#ef4444"
                            filter="url(#glow)"
                            initial={{ scale: 0 }}
                            animate={{ scale: [0, 1.2, 1] }}
                            transition={{ duration: 0.5 }}
                          />
                          <text
                            x="105"
                            y="110"
                            fill="white"
                            fontSize="14"
                            fontWeight="bold"
                            textAnchor="middle"
                          >
                            ☠
                          </text>
                        </g>
                      )}

                      {/* Selected Indicator */}
                      {selectedNode === node.id && (
                        <motion.rect
                          x="-2"
                          y="-2"
                          width="124"
                          height="124"
                          rx="18"
                          fill="none"
                          stroke="#2D9CDB"
                          strokeWidth="3"
                          strokeDasharray="8,4"
                          initial={{ strokeDashoffset: 0 }}
                          animate={{ strokeDashoffset: -24 }}
                          transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                        />
                      )}

                      {/* Node Icon */}
                      <foreignObject x="35" y="20" width="50" height="50">
                        <div className="flex items-center justify-center w-full h-full">
                          {getNodeIcon(node.type, node.isCompromised || false)}
                        </div>
                      </foreignObject>

                      {/* Node Label */}
                      <text
                        x="60"
                        y="82"
                        fill="white"
                        fontSize="13"
                        fontWeight="700"
                        textAnchor="middle"
                        className="select-none"
                      >
                        {node.label}
                      </text>

                      {/* Node IP */}
                      <text
                        x="60"
                        y="97"
                        fill="white"
                        fontSize="10"
                        opacity={0.6}
                        textAnchor="middle"
                        fontFamily="monospace"
                        className="select-none"
                      >
                        {node.ip}
                      </text>

                      {/* Status Text */}
                      {node.isCompromised && node.type !== 'attacker' && (
                        <text
                          x="60"
                          y="110"
                          fill="#ef4444"
                          fontSize="9"
                          fontWeight="600"
                          textAnchor="middle"
                          className="select-none"
                        >
                          PWNED
                        </text>
                      )}

                      {/* Hover Tooltip */}
                      {hoveredNode === node.id && (
                        <g>
                          <rect
                            x="130"
                            y="0"
                            width="200"
                            height="auto"
                            minHeight="100"
                            rx="8"
                            fill="#1a1b1e"
                            stroke="#2D9CDB"
                            strokeWidth="2"
                            filter="url(#glow)"
                          />
                          <text x="140" y="22" fill="white" fontSize="12" fontWeight="700">
                            {node.label}
                          </text>
                          <text x="140" y="40" fill="#2D9CDB" fontSize="10" fontWeight="600">
                            {node.ip}
                          </text>
                          <text x="140" y="56" fill="white" fontSize="9" opacity={0.7}>
                            OS: {node.os}
                          </text>
                          <text x="140" y="72" fill="white" fontSize="9" opacity={0.7} fontWeight="600">
                            Services:
                          </text>
                          {node.services?.slice(0, 4).map((service, i) => (
                            <text 
                              key={i}
                              x="140" 
                              y={86 + i * 14} 
                              fill="white" 
                              fontSize="9" 
                              opacity={0.6}
                            >
                              • {service}
                            </text>
                          ))}
                          {node.isCompromised && (
                            <text x="140" y={86 + (node.services?.length || 0) * 14 + 14} fill="#ef4444" fontSize="10" fontWeight="700">
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

      {/* Enhanced Legend */}
      <div className="absolute bottom-4 left-4 bg-[#101214]/95 backdrop-blur-md p-4 rounded-xl border border-white/10 shadow-2xl space-y-3 max-w-[220px]">
        <div className="flex items-center justify-between mb-2">
          <h4 className="text-xs font-bold text-white/90 uppercase tracking-wider">Network Legend</h4>
          <Eye className="w-3 h-3 text-[#2D9CDB]" />
        </div>
        
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Monitor className="w-4 h-4 text-cyan-400" />
            <span className="text-xs text-white/70">Attacker Machine</span>
          </div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-blue-400" />
            <span className="text-xs text-white/70">Target Server</span>
          </div>
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-purple-400" />
            <span className="text-xs text-white/70">Domain Controller</span>
          </div>
          <div className="flex items-center gap-2">
            <Network className="w-4 h-4 text-orange-400" />
            <span className="text-xs text-white/70">Network Gateway</span>
          </div>
        </div>

        <div className="border-t border-white/5 pt-2 space-y-2">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-green-500"></div>
            <span className="text-xs text-white/60">Active Connection</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500"></div>
            <span className="text-xs text-white/60">Compromised</span>
          </div>
          <div className="flex items-center gap-2">
            <Lock className="w-3 h-3 text-green-500" />
            <span className="text-xs text-white/60">High Security</span>
          </div>
          <div className="flex items-center gap-2">
            <Unlock className="w-3 h-3 text-red-500" />
            <span className="text-xs text-white/60">Vulnerable</span>
          </div>
        </div>

        {showTraffic && (
          <div className="border-t border-white/5 pt-2">
            <div className="flex items-center gap-2">
              <Zap className="w-3 h-3 text-yellow-400 animate-pulse" />
              <span className="text-xs text-white/60">Live Traffic</span>
            </div>
          </div>
        )}
      </div>

      {/* Attack Stats Overlay */}
      {currentStep > 0 && (
        <div className="absolute top-16 right-4 bg-[#101214]/95 backdrop-blur-md p-3 rounded-xl border border-white/10 shadow-2xl min-w-[180px]">
          <div className="flex items-center gap-2 mb-3">
            <Activity className="w-4 h-4 text-[#2D9CDB]" />
            <h4 className="text-xs font-bold text-white/90 uppercase tracking-wider">Attack Status</h4>
          </div>
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <span className="text-xs text-white/50">Compromised:</span>
              <span className="text-xs font-bold text-red-400">{compromisedNodes.length}/{nodes.length}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-white/50">Active Step:</span>
              <span className="text-xs font-bold text-[#2D9CDB]">{currentStep}</span>
            </div>
            {highlightedMachine && (
              <div className="mt-2 pt-2 border-t border-white/5">
                <span className="text-xs text-white/50">Targeting:</span>
                <div className="text-xs font-bold text-green-400 mt-1">{highlightedMachine.toUpperCase()}</div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
