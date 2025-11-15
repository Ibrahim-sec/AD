// client/src/data/diagrams/kerberoastingDiagram.js

export const kerberoastingDiagram = {
  title: 'Kerberoasting Attack Flow',
  description: 'Visual representation of how Kerberoasting exploits service account tickets',
  
  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 50, y: 200 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '10.0.0.5',
        os: 'Kali Linux'
      }
    },
    {
      id: 'dc',
      type: 'machine',
      position: { x: 400, y: 100 },
      data: {
        type: 'dc',
        role: 'Domain Controller',
        label: 'DC01.corp.local',
        ip: '10.0.1.10',
        os: 'Windows Server 2019'
      }
    },
    {
      id: 'service',
      type: 'machine',
      position: { x: 400, y: 300 },
      data: {
        type: 'server',
        role: 'Service Account',
        label: 'SQL Server',
        ip: '10.0.1.20',
        os: 'Windows Server 2016'
      }
    },
    {
      id: 'step1',
      type: 'attackStep',
      position: { x: 750, y: 50 },
      data: {
        stepNumber: 1,
        title: 'Request TGS',
        description: 'Request service ticket for SPN'
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 750, y: 150 },
      data: {
        stepNumber: 2,
        title: 'Receive Encrypted Ticket',
        description: 'KDC returns ticket encrypted with service account hash'
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 750, y: 250 },
      data: {
        stepNumber: 3,
        title: 'Extract Hash',
        description: 'Extract service account hash from ticket'
      }
    },
    {
      id: 'step4',
      type: 'attackStep',
      position: { x: 750, y: 350 },
      data: {
        stepNumber: 4,
        title: 'Crack Offline',
        description: 'Brute-force hash offline with hashcat'
      }
    },
  ],

  edges: [
    {
      id: 'e1',
      source: 'attacker',
      target: 'dc',
      label: 'TGS-REQ (SPN)',
      animated: true,
      style: { stroke: '#3b82f6' }
    },
    {
      id: 'e2',
      source: 'dc',
      target: 'attacker',
      label: 'TGS-REP (Encrypted)',
      animated: true,
      style: { stroke: '#f59e0b' }
    },
    {
      id: 'e3',
      source: 'dc',
      target: 'step1',
      style: { strokeDasharray: '5 5', stroke: '#666' }
    },
    {
      id: 'e4',
      source: 'step1',
      target: 'step2',
      animated: false,
      style: { stroke: '#10b981' }
    },
    {
      id: 'e5',
      source: 'step2',
      target: 'step3',
      animated: false,
      style: { stroke: '#10b981' }
    },
    {
      id: 'e6',
      source: 'step3',
      target: 'step4',
      animated: false,
      style: { stroke: '#10b981' }
    },
  ],

  legend: [
    { color: '#3b82f6', label: 'Request' },
    { color: '#f59e0b', label: 'Response' },
    { color: '#10b981', label: 'Attack Steps' },
    { color: '#ef4444', label: 'Compromised' },
  ]
};
