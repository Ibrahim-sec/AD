import { asrepRoastingDiagram } from '@/data/diagrams';

export const asrepRoastingTheory = {
  id: 'asrep-roasting',
  title: 'AS-REP Roasting Attack',
  subtitle: 'Exploit accounts with pre-authentication disabled',
  estimatedTime: '12 minutes',
  difficulty: 'Intermediate',
  xpReward: 130,
  diagram: asrepRoastingDiagram,
  
  sections: [
    {
      id: 'intro',
      title: '🎯 What is AS-REP Roasting?',
      type: 'intro',
      duration: '2 min',
      content: `AS-REP Roasting targets user accounts that have "Do not require Kerberos preauthentication" enabled. This misconfiguration allows attackers to request authentication without proving their identity first.

**Why it's dangerous:** Any user can request an AS-REP for these accounts, receiving encrypted material that can be cracked offline.

**Common targets:** Service accounts, legacy accounts, or improperly configured user accounts.`,
      
      keyPoints: [
        'Targets accounts with pre-auth disabled (DONT_REQ_PREAUTH)',
        'No credentials needed to request AS-REP',
        'Response contains encrypted material using user password',
        'Can be cracked offline like Kerberoasting'
      ]
    },
    
    {
      id: 'preauth-explained',
      title: '🔐 Kerberos Pre-Authentication',
      type: 'concept',
      duration: '3 min',
      content: `Pre-authentication is a security mechanism in Kerberos that requires users to prove their identity BEFORE receiving an AS-REP (Authentication Service Response).

**Normal Flow (Pre-auth enabled):**
1. User encrypts timestamp with their password hash
2. KDC verifies the encrypted timestamp
3. Only then does KDC issue AS-REP with TGT

**Vulnerable Flow (Pre-auth disabled):**
1. User requests AS-REP without proof
2. KDC immediately returns AS-REP encrypted with user's password
3. Attacker can crack this offline`,
      
      example: {
        title: 'Pre-Auth vs No Pre-Auth',
        code: `# With Pre-Auth (Secure):
User → KDC: "I'm Alice" + Encrypted Timestamp
KDC verifies → Sends TGT

# Without Pre-Auth (Vulnerable):
Attacker → KDC: "I'm Alice"
KDC → "Here's encrypted AS-REP" (no verification!)
Attacker cracks offline`
      }
    },
    
    {
      id: 'attack-steps',
      title: '⚔️ Attack Execution',
      type: 'steps',
      duration: '4 min',
      content: 'Step-by-step AS-REP Roasting attack:',
      
      steps: [
        {
          number: 1,
          title: 'Enumerate Vulnerable Accounts',
          description: 'Find users with DONT_REQ_PREAUTH flag set',
          commands: [
            'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth',
            'GetNPUsers.py contoso.local/ -dc-ip 10.0.1.10 -usersfile users.txt'
          ]
        },
        {
          number: 2,
          title: 'Request AS-REP',
          description: 'Request authentication without pre-auth',
          commands: [
            'Rubeus.exe asreproast /format:hashcat /outfile:hashes.txt',
            'GetNPUsers.py contoso.local/ -dc-ip 10.0.1.10 -request'
          ]
        },
        {
          number: 3,
          title: 'Crack Hash Offline',
          description: 'Brute-force the encrypted AS-REP',
          commands: [
            'hashcat -m 18200 hashes.txt rockyou.txt',
            'john --format=krb5asrep hashes.txt --wordlist=rockyou.txt'
          ]
        }
      ]
    },
    
    {
      id: 'defense',
      title: '🛡️ Detection & Prevention',
      type: 'defensive',
      duration: '3 min',
      content: 'Protecting against AS-REP Roasting.',
      
      detection: {
        logs: [
          'Event ID 4768: Kerberos authentication ticket (TGT) requested',
          'Look for requests without pre-authentication data',
          'Monitor for unusual AS-REQ patterns'
        ],
        indicators: [
          'Multiple AS-REQ from single source',
          'Requests for accounts with pre-auth disabled',
          'Unusual timing or frequency of requests'
        ]
      },
      
      prevention: [
        {
          title: 'Enable Pre-Authentication',
          description: 'Require Kerberos pre-auth for ALL accounts',
          example: 'Set-ADAccountControl -Identity user -DoesNotRequirePreAuth $false'
        },
        {
          title: 'Strong Passwords',
          description: 'Enforce complex passwords (25+ characters)',
          example: 'Password policy with high complexity requirements'
        },
        {
          title: 'Regular Audits',
          description: 'Scan for accounts with pre-auth disabled',
          example: 'Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}'
        },
        {
          title: 'Protected Users Group',
          description: 'Add sensitive accounts to Protected Users',
          example: 'Forces AES encryption and disables legacy protocols'
        }
      ]
    }
  ],
  
  quiz: [
    {
      question: 'What user account attribute makes AS-REP Roasting possible?',
      options: [
        'DONT_REQ_PREAUTH enabled',
        'Password never expires',
        'Account is locked',
        'SPN is registered'
      ],
      correct: 0,
      explanation: 'The DONT_REQ_PREAUTH flag allows authentication requests without pre-authentication, enabling AS-REP Roasting.'
    },
    {
      question: 'What is encrypted in the AS-REP response?',
      options: [
        'The domain admin password',
        'Material encrypted with the user\'s password hash',
        'The krbtgt hash',
        'The TGS ticket'
      ],
      correct: 1,
      explanation: 'AS-REP contains session key material encrypted with the user\'s password hash, which can be cracked offline.'
    },
    {
      question: 'Which is the BEST defense against AS-REP Roasting?',
      options: [
        'Disable Kerberos entirely',
        'Enable pre-authentication for all accounts',
        'Change domain name',
        'Block port 88'
      ],
      correct: 1,
      explanation: 'Enabling Kerberos pre-authentication prevents attackers from requesting AS-REP without proving identity.'
    }
  ],
  
  resources: [
    {
      title: 'MITRE ATT&CK - AS-REP Roasting',
      url: 'https://attack.mitre.org/techniques/T1558/004/',
      type: 'reference'
    },
    {
      title: 'Rubeus Tool',
      url: 'https://github.com/GhostPack/Rubeus',
      type: 'tool'
    }
  ]
};
