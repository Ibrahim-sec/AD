javascript
import { skeletonKeyDiagram } from '@/data/diagrams';

export const skeletonKeyTheory = {
  id: 'skeleton-key',
  title: 'Skeleton Key Attack',
  subtitle: 'Backdoor the Active Directory authentication',
  estimatedTime: '10 minutes',
  difficulty: 'Expert',
  xpReward: 200,
  
  sections: [
    {
      id: 'intro',
      title: '🎯 What is Skeleton Key?',
      type: 'intro',
      duration: '2 min',
      content: `Skeleton Key attack installs a master password backdoor into Domain Controllers, letting attackers authenticate as any user without knowing their passwords.

**Impact:** Provides stealth persistence and easy domain dominance.`,
      
      keyPoints: [
        'Modifies LSASS process on DC',
        'Backdoor allows any password to be valid',
        'Hard to detect via traditional methods',
        'Used by advanced APT groups'
      ]
    },
    
    {
      id: 'attack-flow',
      title: '⚔️ Attack Flow',
      type: 'steps',
      duration: '3 min',
      content: 'How attackers implant Skeleton Key and use it:',
      steps: [
        {
          number: 1,
          title: 'Compromise Domain Controller',
          description: 'Gain privileged code execution on a DC',
          commands: []
        },
        {
          number: 2,
          title: 'Inject Skeleton Key',
          description: 'Patch LSASS in memory to accept master password',
          commands: []
        },
        {
          number: 3,
          title: 'Authenticate',
          description: 'Use any password to log in',
          commands: []
        }
      ]
    },
    
    {
      id: 'defense',
      title: '🛡️ Defense & Mitigation',
      type: 'defensive',
      duration: '3 min',
      content: 'Monitor for unauthorized memory modifications and regularly patch your DCs.',
      prevention: [
        {
          title: 'Monitor LSASS',
          description: 'Deploy advanced endpoint protection',
          example: 'Use EDR with memory tampering detection'
        },
        {
          title: 'Patch Promptly',
          description: 'Keep DCs up to date with security patches',
          example: 'Apply monthly security updates'
        }
      ]
    }
  ],
  
  quiz: [
    {
      question: 'What does Skeleton Key attack modify?',
      options: [
        'Active Directory database',
        'LSASS process memory',
        'KDC configuration',
        'Firewall rules'
      ],
      correct: 1,
      explanation: 'Skeleton Key attack patches the LSASS process memory on the Domain Controller.'
    }
  ],
  
  resources: [
    {
      title: 'Research paper on Skeleton Key',
      url: 'https://www.blackhat.com/docs/us-15/materials/us-15-Marlin-Skeleton-Key-Backdoor-Bypassing-Windows-Authentication-wp.pdf',
      type: 'reference'
    }
  ]
};
