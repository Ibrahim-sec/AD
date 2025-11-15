export const gppPasswordsDiagram = {
  title: 'GPP Passwords Attack Flow',
  description: 'Shows how attackers extract and decrypt legacy GPP XML passwords from SYSVOL',

  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 50, y: 200 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '10.0.0.15',
        os: 'Kali Linux'
      }
    },
    {
      id: 'dc',
      type: 'machine',
      position: { x: 300, y: 100 },
      data: {
        type: 'dc',
        role: 'Domain Controller',
        label: 'DC01.corp.local',
        ip: '10.0.1.10',
        os: 'Windows Server 2019'
      }
    },
    {
      id: 'sysvol',
      type: 'machine',
      position: { x: 300, y: 300 },
      data: {
        type: 'server',
        role: 'SYSVOL Share',
        label: 'SYSVOL',
        ip: '10.0.1.10',
        os: 'Windows Server 2019'
      }
    },
    {
      id: 'step1',
      type: 'attackStep',
      position: { x: 600, y: 50 },
      data: {
        stepNumber: 1,
        title: 'Download GPP XML Files',
        description: 'Retrieve password-containing XML files from SYSVOL share'
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 600, y: 150 },
      data: {
        stepNumber: 2,
        title: 'Decrypt Passwords',
        description: 'Use publicly known AES keys to decrypt stored passwords'
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 600, y: 250 },
      data: {
        stepNumber: 3,
        title: 'Use Credentials',
        description: 'Leverage extracted credentials for lateral movement'
      }
    }
  ],

  edges: [
    { id: 'e1', source: 'attacker', target: 'dc', label: 'Connect to DC', animated: true, style: { stroke: '#3b82f6' } },
    { id: 'e2', source: 'dc', target: 'sysvol', label: 'Access SYSVOL Share', animated: false, style: { strokeDasharray: '5 5', stroke: '#10b981' } },
    { id: 'e3', source: 'attacker', target: 'step1', animated: false, style: { stroke: '#10b981' } },
    { id: 'e4', source: 'step1', target: 'step2', animated: false, style: { stroke: '#f59e0b' } },
    { id: 'e5', source: 'step2', target: 'step3', animated: false, style: { stroke: '#10b981' } },
  ],

  legend: [
    { color: '#3b82f6', label: 'Network Connection' },
    { color: '#10b981', label: 'Attack Steps' },
    { color: '#f59e0b', label: 'Decryption Phase' }
  ]
};
