export const dcsyncTheory = {
  id: 'dcsync',
  title: 'DCSync Attack Deep Dive',
  subtitle: 'Extract domain credentials like a Domain Controller',
  estimatedTime: '12 minutes',
  difficulty: 'Advanced',
  xpReward: 200,

  sections: [
    {
      id: 'intro',
      title: '🎯 What is DCSync?',
      type: 'intro',
      duration: '2 min',
      content: `DCSync is a powerful attack that allows an attacker to impersonate a Domain Controller and request password hashes for any user through the Directory Replication Service Remote Protocol (MS-DRSR).

**Critical Impact:** With DCSync, you can extract the krbtgt hash and create Golden Tickets for persistent domain admin access.`,
      keyPoints: [
        'Abuses legitimate AD replication protocol',
        'Extracts password hashes without touching LSASS',
        'Requires specific replication permissions',
        'Can extract krbtgt hash for Golden Ticket attacks'
      ]
    },

    {
      id: 'replication',
      title: '🔄 Active Directory Replication',
      type: 'concept',
      duration: '3 min',
      content: `Active Directory uses multi-master replication between Domain Controllers. DCSync exploits this legitimate mechanism.

**Normal Replication:** DCs replicate changes using the Directory Replication Service (DRS), including password hashes.

**The Attack:** An attacker with replication permissions can pretend to be a DC and request any object's data.`,
      example: {
        title: 'Required Permissions',
        code: `DS-Replication-Get-Changes (GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2)
DS-Replication-Get-Changes-All (GUID: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2)

Default holders:
- Domain Admins
- Enterprise Admins
- Administrators
- Domain Controllers`
      }
    },

    {
      id: 'attack-steps',
      title: '⚔️ Executing DCSync',
      type: 'steps',
      duration: '4 min',
      content: 'Steps to perform a DCSync attack:',
      steps: [
        {
          number: 1,
          title: 'Verify Permissions',
          description: 'Check if compromised account has replication rights',
          commands: [
            'Get-DomainObjectAcl -SearchBase "DC=contoso,DC=local" -ResolveGUIDs'
          ]
        },
        {
          number: 2,
          title: 'Execute DCSync',
          description: 'Use Mimikatz or Impacket to perform replication',
          commands: [
            'mimikatz # lsadump::dcsync /domain:contoso.local /user:Administrator',
            'secretsdump.py contoso.local/user:password@dc01.contoso.local'
          ]
        },
        {
          number: 3,
          title: 'Extract Hashes',
          description: 'Receive NTLM and Kerberos hashes',
          commands: [
            'Use hashes for Pass-the-Hash attacks',
            'Create Golden Tickets with krbtgt hash'
          ]
        }
      ]
    },

    {
      id: 'defense',
      title: '🛡️ Detection & Mitigation',
      type: 'defensive',
      duration: '3 min',
      content: 'Detecting and preventing DCSync attacks.',
      detection: {
        logs: [
          'Event ID 4662: An operation was performed on an object',
          'Directory Service Access auditing must be enabled',
          'Monitor replication requests from non-DC computers'
        ],
        indicators: [
          'Event 4662 with Replication-Get-Changes GUIDs',
          'Replication requests from workstations',
          'Unusual accounts performing replication'
        ]
      },
      prevention: [
        {
          title: 'Limit Replication Permissions',
          description: 'Regularly audit who has replication rights',
          example: 'Remove unnecessary accounts from privileged groups'
        },
        {
          title: 'Protected Users Group',
          description: 'Add high-value accounts to Protected Users',
          example: 'Prevents NTLM hash replication for these users'
        },
        {
          title: 'Enable Advanced Auditing',
          description: 'Configure Directory Service Access auditing',
          example: 'auditpol /set /subcategory:"Directory Service Access" /success:enable'
        }
      ]
    }
  ],

  quiz: [
    {
      question: 'What protocol does DCSync abuse?',
      options: [
        'LDAP',
        'MS-DRSR (Directory Replication Service)',
        'SMB',
        'RPC'
      ],
      correct: 1,
      explanation: 'DCSync abuses the MS-DRSR protocol used for legitimate replication between Domain Controllers.'
    },
    {
      question: 'Which permission is NOT required for DCSync?',
      options: [
        'DS-Replication-Get-Changes',
        'DS-Replication-Get-Changes-All',
        'GenericAll on domain object',
        'Local Administrator on the DC'
      ],
      correct: 3,
      explanation: 'DCSync does not require local admin access to the DC, only the replication permissions.'
    }
  ],

  resources: [
    {
      title: 'MITRE ATT&CK - DCSync',
      url: 'https://attack.mitre.org/techniques/T1003/006/',
      type: 'reference'
    }
  ]
};
