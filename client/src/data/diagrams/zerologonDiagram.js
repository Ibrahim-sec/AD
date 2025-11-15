export const zerologonDiagram = {
  title: 'Zerologon Attack Flow',
  description: 'Exploits cryptographic flaw in Netlogon protocol to reset DC password',

  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 50, y: 150 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '10.0.0.55',
        os: 'Kali Linux'
      },
    },
    {
      id: 'dc',
      type: 'machine',
      position: { x: 350, y: 150 },
      data: {
        type: 'dc',
        role: 'Domain Controller',
        label: 'DC01.corp.local',
        ip: '10.0.1.10',
        os: 'Windows Server 2019'
      },
    },
    {
      id: 'step1',
      type: 'attackStep',
      position: { x: 200, y: 50 },
      data: {
        stepNumber: 1,
        title: 'Establish Connection',
        description: 'Connect to DC Netlogon service'
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 450, y: 50 },
      data: {
        stepNumber: 2,
        title: 'Exploit Cryptographic Flaw',
        description: 'Send manipulated Netlogon requests to reset DC password'
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 600, y: 150 },
      data: {
        stepNumber: 3,
        title: 'Gain Full Control',
        description: 'Reset machine account password to compromise DC'
      }
    }
  ],

  edges: [
    { id: 'e1', source: 'attacker', target: 'step1', animated: true, style: { stroke: '#3b82f6' } },
    { id: 'e2', source: 'step1', target: 'step2', animated: false, style: { stroke: '#10b981' } },
    { id: 'e3', source: 'step2', target: 'dc', label: 'Password Reset Request', animated: true, style: { stroke: '#f59e0b' } },
    { id: 'e4', source: 'dc', target: 'step3', animated: false, style: { stroke: '#10b981' } },
  ],

  legend: [
    { color: '#3b82f6', label: 'Attacker Connection' },
    { color: '#10b981', label: 'Attack Sequence' },
    { color: '#f59e0b', label: 'Exploit Payload' }
  ]
};
