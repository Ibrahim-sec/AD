export const printNightmareDiagram = {
  title: 'PrintNightmare Vulnerability Flow',
  description: 'Exploit Windows Print Spooler for remote code execution',

  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 60, y: 160 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '10.0.0.80',
        os: 'Linux'
      },
    },
    {
      id: 'victim-server',
      type: 'machine',
      position: { x: 350, y: 160 },
      data: {
        type: 'server',
        role: 'Windows Server',
        label: 'File Server',
        ip: '10.0.1.20',
        os: 'Windows Server 2019'
      },
    },
    {
      id: 'step1',
      type: 'attackStep',
      position: { x: 180, y: 80 },
      data: {
        stepNumber: 1,
        title: 'Identify Print Spooler',
        description: 'Scan and find machines running vulnerable Print Spooler service'
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 420, y: 80 },
      data: {
        stepNumber: 2,
        title: 'Deliver Malicious Print Job',
        description: 'Send exploit payload via crafted print job'
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 550, y: 160 },
      data: {
        stepNumber: 3,
        title: 'Gain SYSTEM Privileges',
        description: 'Execute arbitrary code as SYSTEM user'
      }
    }
  ],

  edges: [
    { id: 'e1', source: 'attacker', target: 'step1', animated: true, style: { stroke: '#3b82f6' } },
    { id: 'e2', source: 'step1', target: 'step2', animated: false, style: { stroke: '#10b981' } },
    { id: 'e3', source: 'step2', target: 'victim-server', animated: true, label: 'Exploit Payload', style: { stroke: '#f59e0b' } },
    { id: 'e4', source: 'victim-server', target: 'step3', animated: false, style: { stroke: '#10b981' } },
  ],

  legend: [
    { color: '#3b82f6', label: 'Recon/Scan' },
    { color: '#10b981', label: 'Exploit Steps' },
    { color: '#f59e0b', label: 'Payload Delivery' }
  ]
};
