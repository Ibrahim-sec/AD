export const skeletonKeyDiagram = {
  title: 'Skeleton Key Attack Flow',
  description: 'How attackers implant a master password backdoor in Domain Controllers',

  nodes: [
    {
      id: 'attacker',
      type: 'machine',
      position: { x: 50, y: 200 },
      data: {
        type: 'attacker',
        role: 'Attacker',
        label: 'Attacker Machine',
        ip: '10.0.0.10',
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
        title: 'Compromise Domain Controller',
        description: 'Gain privileged code execution on DC'
      }
    },
    {
      id: 'step2',
      type: 'attackStep',
      position: { x: 450, y: 50 },
      data: {
        stepNumber: 2,
        title: 'Inject Skeleton Key',
        description: 'Patch LSASS memory with master password backdoor'
      }
    },
    {
      id: 'step3',
      type: 'attackStep',
      position: { x: 600, y: 150 },
      data: {
        stepNumber: 3,
        title: 'Authenticate with Master Password',
        description: 'Bypass normal authentication for all users'
      }
    }
  ],

  edges: [
    { id: 'e1', source: 'attacker', target: 'step1', animated: true, style: { stroke: '#3b82f6' } },
    { id: 'e2', source: 'step1', target: 'step2', animated: false, style: { stroke: '#10b981' } },
    { id: 'e3', source: 'step2', target: 'dc', label: 'Backdoor Injected', animated: true, style: { stroke: '#f59e0b' } },
    { id: 'e4', source: 'dc', target: 'step3', animated: false, style: { stroke: '#10b981' } }
  ],

  legend: [
    { color: '#3b82f6', label: 'Attacker Actions' },
    { color: '#10b981', label: 'Attack Process' },
    { color: '#f59e0b', label: 'Backdoor Installation' }
  ]
};
