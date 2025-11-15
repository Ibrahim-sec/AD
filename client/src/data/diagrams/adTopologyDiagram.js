// client/src/data/diagrams/adTopologyDiagram.js

export const adTopologyDiagram = {
  title: 'Active Directory Network Topology',
  description: 'Enterprise AD environment with trust relationships',
  
  nodes: [
    {
      id: 'root-dc',
      type: 'machine',
      position: { x: 300, y: 50 },
      data: {
        type: 'dc',
        role: 'Root DC',
        label: 'ROOTDC.corp.local',
        ip: '10.0.1.10'
      }
    },
    {
      id: 'child-dc1',
      type: 'machine',
      position: { x: 100, y: 200 },
      data: {
        type: 'dc',
        role: 'Child DC',
        label: 'DC01.us.corp.local',
        ip: '10.1.1.10'
      }
    },
    {
      id: 'child-dc2',
      type: 'machine',
      position: { x: 500, y: 200 },
      data: {
        type: 'dc',
        role: 'Child DC',
        label: 'DC02.eu.corp.local',
        ip: '10.2.1.10'
      }
    },
    {
      id: 'ws1',
      type: 'machine',
      position: { x: 50, y: 350 },
      data: {
        type: 'workstation',
        role: 'Workstation',
        label: 'WS01',
        ip: '10.1.1.20'
      }
    },
    {
      id: 'ws2',
      type: 'machine',
      position: { x: 150, y: 350 },
      data: {
        type: 'workstation',
        role: 'Workstation',
        label: 'WS02',
        ip: '10.1.1.21'
      }
    },
    {
      id: 'srv1',
      type: 'machine',
      position: { x: 450, y: 350 },
      data: {
        type: 'server',
        role: 'File Server',
        label: 'FILE01',
        ip: '10.2.1.20'
      }
    },
    {
      id: 'srv2',
      type: 'machine',
      position: { x: 550, y: 350 },
      data: {
        type: 'server',
        role: 'SQL Server',
        label: 'SQL01',
        ip: '10.2.1.21'
      }
    },
  ],

  edges: [
    // Trust relationships
    {
      id: 'trust1',
      source: 'root-dc',
      target: 'child-dc1',
      label: 'Parent-Child Trust',
      type: 'smoothstep',
      style: { stroke: '#8b5cf6', strokeWidth: 2 }
    },
    {
      id: 'trust2',
      source: 'root-dc',
      target: 'child-dc2',
      label: 'Parent-Child Trust',
      type: 'smoothstep',
      style: { stroke: '#8b5cf6', strokeWidth: 2 }
    },
    // Machine connections
    {
      id: 'conn1',
      source: 'child-dc1',
      target: 'ws1'
    },
    {
      id: 'conn2',
      source: 'child-dc1',
      target: 'ws2'
    },
    {
      id: 'conn3',
      source: 'child-dc2',
      target: 'srv1'
    },
    {
      id: 'conn4',
      source: 'child-dc2',
      target: 'srv2'
    },
  ],

  legend: [
    { color: '#3b82f6', label: 'Domain Controller' },
    { color: '#10b981', label: 'Workstation' },
    { color: '#f59e0b', label: 'Server' },
    { color: '#8b5cf6', label: 'Trust Relationship' },
  ]
};
