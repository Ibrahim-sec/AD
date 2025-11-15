// client/src/components/diagrams/NetworkDiagram.jsx

import { useCallback, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  Panel,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { nodeTypes } from './CustomNodes';
import { Info, Maximize2, Minimize2 } from 'lucide-react';

export default function NetworkDiagram({ 
  diagramData, 
  onNodeClick,
  showMiniMap = true,
  showControls = true,
  interactive = true,
  height = '600px'
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState(diagramData.nodes || []);
  const [edges, setEdges, onEdgesChange] = useEdgesState(diagramData.edges || []);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);

  const handleNodeClick = useCallback((event, node) => {
    setSelectedNode(node);
    if (onNodeClick) {
      onNodeClick(node);
    }
  }, [onNodeClick]);

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  return (
    <div className={`network-diagram-container ${isFullscreen ? 'fullscreen' : ''}`}>
      {/* Diagram Title & Info */}
      {diagramData.title && (
        <div className="diagram-header">
          <h3 className="diagram-title">{diagramData.title}</h3>
          {diagramData.description && (
            <p className="diagram-description">{diagramData.description}</p>
          )}
        </div>
      )}

      {/* React Flow Canvas */}
      <div style={{ height: isFullscreen ? '100vh' : height, width: '100%' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={interactive ? onNodesChange : undefined}
          onEdgesChange={interactive ? onEdgesChange : undefined}
          onNodeClick={handleNodeClick}
          nodeTypes={nodeTypes}
          fitView
          attributionPosition="bottom-left"
        >
          {/* Background Grid */}
          <Background 
            variant="dots" 
            gap={16} 
            size={1} 
            color="#333"
          />

          {/* Controls (zoom, fit view, etc.) */}
          {showControls && <Controls />}

          {/* Mini Map */}
          {showMiniMap && (
            <MiniMap
              nodeColor={(node) => {
                if (node.data?.compromised) return '#ef4444';
                if (node.data?.highlighted) return '#f59e0b';
                return '#3b82f6';
              }}
              maskColor="rgba(0, 0, 0, 0.6)"
            />
          )}

          {/* Custom Panel - Legend & Controls */}
          <Panel position="top-right" className="diagram-panel">
            <button 
              onClick={toggleFullscreen}
              className="panel-button"
              title={isFullscreen ? 'Exit Fullscreen' : 'Fullscreen'}
            >
              {isFullscreen ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
            </button>
          </Panel>

          {/* Legend */}
          {diagramData.legend && (
            <Panel position="bottom-right" className="diagram-legend">
              <div className="legend-title">
                <Info size={16} />
                Legend
              </div>
              <div className="legend-items">
                {diagramData.legend.map((item, idx) => (
                  <div key={idx} className="legend-item">
                    <div 
                      className="legend-color" 
                      style={{ backgroundColor: item.color }}
                    />
                    <span>{item.label}</span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </ReactFlow>
      </div>

      {/* Selected Node Info Panel */}
      {selectedNode && (
        <div className="node-info-panel">
          <h4>{selectedNode.data.label}</h4>
          <button onClick={() => setSelectedNode(null)}>Close</button>
          {/* Add more node details here */}
        </div>
      )}
    </div>
  );
}
