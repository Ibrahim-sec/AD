export const ntlmRelayDiagram = {
  title: 'NTLM Relay Attack Flow',
  description: 'Illustrates how NTLM authentication is intercepted and relayed to impersonate users',

  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 50, y: 150 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '192.168.1.100',
        os: 'Kali Linux'
      },
    },
    {
      id: 'victim',
      type: 'machine',
      position: { x: 250, y: 150 },
      data: {
        type: 'workstation',
        role: 'Victim Workstation',
        label: 'WORKSTATION-01',
        ip: '192.168.1.150',
        os: 'Windows 10'
      },
    },
    {
      id: 'target',
      type: 'machine',
      position: { x: 450, y: 150 },
      data: {
        type: 'server',
        role: 'Target Server',
        label: 'FILE-SERVER-01',
        ip: '192.168.1.200',
        os: 'Windows Server 2019'
      },
    },
    {
      id: 'step1',
      type: 'attackStep',
      position: { x: 300, y: 50 },
      data: {
        stepNumber: 1,
        title: 'Intercept NTLM Auth',
        description: 'Capture victim\'s NTLM authentication request',
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 500, y: 50 },
      data: {
        stepNumber: 2,
        title: 'Relay Auth',
        description: 'Forward credentials to target server',
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 650, y: 150 },
      data: {
        stepNumber: 3,
        title: 'Gain Access',
        description: 'Impersonate victim to access resources',
      }
    }
  ],

  edges: [
    { id: 'e1', source: 'victim', target: 'attacker', label: 'NTLM Auth Request', animated: true, style: { stroke: '#3b82f6' } },
    { id: 'e2', source: 'attacker', target: 'step1', animated: false, style: { strokeDasharray: '5 5', stroke: '#10b981' } },
    { id: 'e3', source: 'step1', target: 'step2', animated: false, style: { stroke: '#10b981' } },
    { id: 'e4', source: 'step2', target: 'target', label: 'Relayed Credentials', animated: true, style: { stroke: '#f59e0b' } },
    { id: 'e5', source: 'target', target: 'step3', animated: false, style: { stroke: '#10b981' } },
  ],

  legend: [
    { color: '#3b82f6', label: 'Original Auth Request' },
    { color: '#10b981', label: 'Attack Process Flow' },
    { color: '#f59e0b', label: 'Relayed Credentials' }
  ]
};
