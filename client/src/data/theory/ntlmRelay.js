import { ntlmRelayDiagram } from '@/data/diagrams';

export const ntlmRelayTheory = {
  id: 'ntlm-relay',
  title: 'NTLM Relay Attack',
  subtitle: 'Intercept and relay NTLM authentication',
  estimatedTime: '10 minutes',
  difficulty: 'Advanced',
  xpReward: 140,
  
  diagram: ntlmRelayDiagram,  // Add this line
  sections: [
    {
      id: 'intro',
      title: '🎯 What is NTLM Relay?',
      type: 'intro',
      duration: '2 min',
      content: `NTLM Relay is an attack where the attacker captures NTLM authentication requests and relays them to another service to impersonate the user.

**Why it matters:** It allows privileged access without cracking passwords or hashes.`,
      keyPoints: [
        'Intercepts NTLM authentication requests',
        'Relays to other machines/services',
        'Bypasses authentication controls',
        'Works in misconfigured environments'
      ]
    },
    {
      id: 'attack',
      title: '⚔️ How NTLM Relay Works',
      type: 'concept',
      duration: '3 min',
      content: `The attacker listens for NTLM authentication traffic, captures the challenge-response, then forwards it to a target server or service to authenticate as that user.`,
      example: {
        title: 'NTLM Relay Example',
        code: `# Intercept authentication from victim
# Relay to target server and gain access`
      }
    },
    {
      id: 'defense',
      title: '🛡️ Defenses',
      type: 'defensive',
      duration: '3 min',
      content: `Protect your network against NTLM Relay by enabling SMB signing, enforcing extended protection, and disabling NTLM where possible.`,
      prevention: [
        {
          title: 'Enable SMB Signing',
          description: 'Protect against NTLM relay attacks',
          example: 'Group Policy > Network Security: Configure SMB signing'
        },
        {
          title: 'Disable NTLM',
          description: 'Use Kerberos authentication only',
          example: 'Restrict NTLM authentication via Group Policy'
        },
        {
          title: 'Network Segmentation',
          description: 'Limit relay opportunities',
          example: 'Remove unnecessary SMB access'
        }
      ]
    }
  ],
  
  quiz: [
    {
      question: 'How does NTLM Relay allow attackers to impersonate users?',
      options: [
        'By cracking passwords offline',
        'By forwarding NTLM traffic to target servers',
        'By scanning for vulnerabilities',
        'By brute force'
      ],
      correct: 1,
      explanation: 'NTLM Relay forwards intercepted NTLM authentication requests to impersonate users.'
    }
  ],
  
  resources: [
    {
      title: 'Microsoft Docs on NTLM Relay',
      url: 'https://docs.microsoft.com/en-us/archive/blogs/securityfreaks/ntlm-relay-attack-explained',
      type: 'reference'
    },
    {
      title: 'Resecurity Blog on NTLM Relay',
      url: 'https://resecurity.com/2018/05/stealing-ntlm-hashes-through-ntlm-relay-attacks/',
      type: 'reference'
    }
  ]
};
