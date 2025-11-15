export const zerologonTheory = {
  id: 'zerologon',
  title: 'Zerologon Vulnerability',
  subtitle: 'Critical Netlogon elevation of privilege flaw',
  estimatedTime: '10 minutes',
  difficulty: 'Expert',
  xpReward: 220,

  sections: [
    {
      id: 'intro',
      title: '🎯 What is Zerologon?',
      type: 'intro',
      duration: '2 min',
      content: `Zerologon is a critical vulnerability in Netlogon protocol allowing attackers to spoof a domain controller and change machine account passwords, gaining full domain control.

**Impact:** Easy privilege escalation, lateral movement, and domain dominance.`,
      keyPoints: [
        'Exploits weak cryptography in Netlogon',
        'Allows full control of domain controller accounts',
        'Requires network access to domain controller',
        'Patched since August 2020 but often unpatched'
      ]
    },
    {
      id: 'attack',
      title: '⚔️ Zerologon Attack Flow',
      type: 'steps',
      duration: '4 min',
      content: 'Step-by-step Zerologon attack:',
      steps: [
        {
          number: 1,
          title: 'Establish Connection',
          description: 'Connect to domain controller Netlogon service',
          commands: ['net use \\\\DC01 /user:DOMAIN\\administrator']
        },
        {
          number: 2,
          title: 'Exploit Cryptographic Flaw',
          description: 'Send specially crafted Netlogon requests to reset password',
          commands: ['Invoke-Zerologon.ps1 -Target DC01']
        },
        {
          number: 3,
          title: 'Gain Control',
          description: 'Reset machine account password and gain access',
          commands: []
        }
      ]
    },
    {
      id: 'defense',
      title: '🛡️ Defense & Mitigation',
      type: 'defensive',
      duration: '3 min',
      content: 'Patch all domain controllers and monitor for exploitation attempts.',
      prevention: [
        {
          title: 'Apply Security Patches',
          description: 'Install latest Windows updates addressing Zerologon',
          example: 'Microsoft KB4569509 or newer'
        },
        {
          title: 'Monitor DC Logs',
          description: 'Audit unusual Netlogon password reset events',
          example: 'Event ID 5805, 5827'
        },
        {
          title: 'Limit Network Access',
          description: 'Restrict access to Netlogon service',
          example: 'Firewall rules limiting DC accessible IPs'
        }
      ]
    }
  ],

  quiz: [
    {
      question: 'What protocol does Zerologon exploit?',
      options: [
        'SMB',
        'Netlogon',
        'LDAP',
        'Kerberos'
      ],
      correct: 1,
      explanation: 'Zerologon exploits a cryptographic flaw in the Netlogon protocol.'
    }
  ],

  resources: [
    {
      title: 'Microsoft Security Advisory',
      url: 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1472',
      type: 'reference'
    },
    {
      title: 'Zerologon Proof of Concept',
      url: 'https://github.com/SecuraBV/CVE-2020-1472',
      type: 'tool'
    }
  ]
};
