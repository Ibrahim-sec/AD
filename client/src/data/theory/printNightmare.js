export const printNightmareTheory = {
  id: 'printnightmare',
  title: 'PrintNightmare Vulnerability',
  subtitle: 'Critical Print Spooler Privilege Escalation',
  estimatedTime: '12 minutes',
  difficulty: 'Advanced',
  xpReward: 180,

  sections: [
    {
      id: 'intro',
      title: '🎯 What is PrintNightmare?',
      type: 'intro',
      duration: '2 min',
      content: `PrintNightmare is a zero-day vulnerability in the Windows Print Spooler service that allows remote code execution and privilege escalation.

**Impact:** Attackers can execute arbitrary code as SYSTEM.`,
      keyPoints: [
        'Exploits the Windows Print Spooler service',
        'Allows remote code execution widely',
        'Used in ransomware and APT campaigns',
        'Requires network access and specific permissions'
      ]
    },
    {
      id: 'attack',
      title: '⚔️ PrintNightmare Attack Flow',
      type: 'steps',
      duration: '4 min',
      content: 'How attackers exploit PrintNightmare step-by-step:',
      steps: [
        {
          number: 1,
          title: 'Identify Print Spooler Service',
          description: 'Find target machines running Print Spooler',
          commands: [
            'Get-Service -Name Spooler',
            'sc query Spooler'
          ]
        },
        {
          number: 2,
          title: 'Exploit Remote Code Execution',
          description: 'Deliver malware via crafted print request',
          commands: [
            'Invoke-PrintNightmare.ps1 -Target 10.0.1.10'
          ]
        },
        {
          number: 3,
          title: 'Elevate Privileges',
          description: 'Gain SYSTEM privileges via Print Spooler service',
          commands: []
        }
      ]
    },
    {
      id: 'defense',
      title: '🛡️ Defense & Mitigation',
      type: 'defensive',
      duration: '3 min',
      content: 'Apply patches and monitor event logs.',
      prevention: [
        {
          title: 'Apply Microsoft Patches',
          description: 'Keep all systems updated with latest PrintNightmare fixes',
          example: 'Microsoft Security Updates June 2021 and later'
        },
        {
          title: 'Restrict Print Spooler Access',
          description: 'Disable Print Spooler service where not required',
          example: 'Group Policy and Service Configuration'
        },
        {
          title: 'Monitor Logs',
          description: 'Audit event IDs related to Print Spooler and spooler remote attacks',
          example: 'Event ID 307, 805'
        }
      ]
    }
  ],

  quiz: [
    {
      question: 'PrintNightmare exploits a vulnerability in which Windows service?',
      options: [
        'Windows Update',
        'Print Spooler',
        'Task Scheduler',
        'File Explorer'
      ],
      correct: 1,
      explanation: 'PrintNightmare exploits a critical flaw in the Windows Print Spooler service.'
    }
  ],

  resources: [
    {
      title: 'Microsoft Security Advisory',
      url: 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527',
      type: 'reference'
    }
  ]
};
