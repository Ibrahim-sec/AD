// client/src/components/diagrams/CustomNodes.jsx

import { Handle, Position } from 'reactflow';
import { Server, Monitor, Shield, Wifi, User, Database, Key } from 'lucide-react';

const iconMap = {
  dc: Server,
  workstation: Monitor,
  server: Database,
  attacker: User,
  firewall: Shield,
  network: Wifi,
  kdc: Key,
};

export function MachineNode({ data }) {
  const Icon = iconMap[data.type] || Server;
  
  return (
    <div className={`custom-node machine-node ${data.compromised ? 'compromised' : ''} ${data.highlighted ? 'highlighted' : ''}`}>
      <Handle type="target" position={Position.Top} />
      
      <div className="node-header">
        <Icon className="node-icon" size={20} />
        <span className="node-role">{data.role}</span>
      </div>
      
      <div className="node-content">
        <div className="node-name">{data.label}</div>
        {data.ip && <div className="node-ip">{data.ip}</div>}
        {data.os && <div className="node-os">{data.os}</div>}
      </div>
      
      {data.compromised && (
        <div className="node-badge compromised-badge">
          Compromised
        </div>
      )}
      
      <Handle type="source" position={Position.Bottom} />
    </div>
  );
}

export function AttackStepNode({ data }) {
  return (
    <div className={`custom-node attack-step-node step-${data.stepNumber}`}>
      <Handle type="target" position={Position.Left} />
      
      <div className="step-number">{data.stepNumber}</div>
      <div className="step-content">
        <div className="step-title">{data.title}</div>
        <div className="step-description">{data.description}</div>
      </div>
      
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

export function ConceptNode({ data }) {
  return (
    <div className="custom-node concept-node">
      <div className="concept-icon">{data.icon}</div>
      <div className="concept-label">{data.label}</div>
      {data.description && (
        <div className="concept-description">{data.description}</div>
      )}
    </div>
  );
}

// Export all node types
export const nodeTypes = {
  machine: MachineNode,
  attackStep: AttackStepNode,
  concept: ConceptNode,
};
