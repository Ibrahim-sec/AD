// client/src/data/diagrams/asrepRoastingDiagram.js

export const asrepRoastingDiagram = {
  title: 'AS-REP Roasting Attack Flow',
  description: 'Exploiting accounts with "Do not require Kerberos preauthentication"',
  
  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 50, y: 200 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '10.0.0.5'
      }
    },
    {
      id: 'dc',
      type: 'machine',
      position: { x: 400, y: 200 },
      data: {
        type: 'kdc',
        role: 'KDC',
        label: 'Domain Controller',
        ip: '10.0.1.10'
      }
    },
    {
      id: 'step1',
      type: 'attackStep',
      position: { x: 700, y: 100 },
      data: {
        stepNumber: 1,
        title: 'Enumerate Vulnerable Accounts',
        description: 'Find users with pre-auth disabled'
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 700, y: 200 },
      data: {
        stepNumber: 2,
        title: 'Request AS-REP',
        description: 'Request authentication without pre-auth'
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 700, y: 300 },
      data: {
        stepNumber: 3,
        title: 'Crack Hash',
        description: 'Brute-force extracted hash'
      }
    },
  ],

  edges: [
    {
      id: 'e1',
      source: 'attacker',
      target: 'dc',
      label: 'AS-REQ (No Pre-Auth)',
      animated: true
    },
    {
      id: 'e2',
      source: 'dc',
      target: 'attacker',
      label: 'AS-REP (Hash)',
      animated: true,
      style: { stroke: '#ef4444' }
    },
    {
      id: 'e3',
      source: 'attacker',
      target: 'step1',
      style: { strokeDasharray: '5 5' }
    },
    {
      id: 'e4',
      source: 'step1',
      target: 'step2',
      style: { stroke: '#10b981' }
    },
    {
      id: 'e5',
      source: 'step2',
      target: 'step3',
      style: { stroke: '#10b981' }
    },
  ],

  legend: [
    { color: '#3b82f6', label: 'Network Traffic' },
    { color: '#ef4444', label: 'Vulnerable Response' },
    { color: '#10b981', label: 'Attack Progression' },
  ]
};
