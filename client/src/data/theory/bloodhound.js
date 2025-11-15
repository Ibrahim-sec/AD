export const bloodhoundTheory = {
  id: 'bloodhound',
  title: 'BloodHound: AD Attack Path Analysis',
  subtitle: 'Map and exploit Active Directory relationships',
  estimatedTime: '18 minutes',
  difficulty: 'Advanced',
  xpReward: 180,
  // No specific diagram yet, but can add one later
  
  sections: [
    {
      id: 'intro',
      title: '🎯 What is BloodHound?',
      type: 'intro',
      duration: '3 min',
      content: `BloodHound is a powerful reconnaissance tool that uses graph theory to reveal hidden and often unintended relationships within Active Directory. It visualizes attack paths from your current position to high-value targets like Domain Admins.

**Why it's revolutionary:** It automates attack path discovery that would take hours or days to find manually.

**Real-world impact:** Used in 90%+ of professional AD pentests and real-world breaches.`,
      
      keyPoints: [
        'Automated attack path discovery',
        'Graph database visualization (Neo4j)',
        'Identifies shortest path to Domain Admin',
        'Maps ACL relationships, group memberships, and session data',
        'Open-source and actively maintained'
      ]
    },
    
    {
      id: 'how-it-works',
      title: '🔍 How BloodHound Works',
      type: 'concept',
      duration: '4 min',
      content: `BloodHound consists of two main components:

**1. Collectors (SharpHound):**
- Gather data from Active Directory
- Enumerate users, groups, computers, ACLs, sessions
- Export to JSON format

**2. BloodHound GUI:**
- Imports JSON into Neo4j graph database
- Visualizes relationships and attack paths
- Provides pre-built queries for common attack scenarios`,
      
      example: {
        title: 'BloodHound Data Collection',
        code: `# SharpHound (Windows)
SharpHound.exe -c All -d contoso.local

# BloodHound.py (Linux)
bloodhound-python -d contoso.local -u user -p password -gc dc01.contoso.local -c all

# Output: JSON files containing AD data`
      }
    },
    
    {
      id: 'attack-paths',
      title: '🛤️ Common Attack Paths',
      type: 'concept',
      duration: '5 min',
      content: 'BloodHound reveals various paths to privilege escalation:',
      
      keyPoints: [
        'GenericAll/GenericWrite on users → Reset password or add to group',
        'WriteDacl on objects → Modify permissions (DCSync)',
        'ForceChangePassword → Change user password without knowing current one',
        'AddMembers to privileged groups → Gain elevated access',
        'Session enumeration → Find where admins are logged in for credential theft',
        'GPO abuse → Modify GPOs affecting privileged users'
      ]
    },
    
    {
      id: 'using-bloodhound',
      title: '⚔️ Using BloodHound',
      type: 'steps',
      duration: '4 min',
      
      steps: [
        {
          number: 1,
          title: 'Collect Data',
          description: 'Run SharpHound to gather AD information',
          commands: [
            'SharpHound.exe -c All',
            'bloodhound-python -d domain.local -u user -p pass -c all'
          ]
        },
        {
          number: 2,
          title: 'Start Neo4j & BloodHound',
          description: 'Launch the graph database and GUI',
          commands: [
            'neo4j console',
            'bloodhound'
          ]
        },
        {
          number: 3,
          title: 'Import Data',
          description: 'Upload collected JSON files',
          commands: [
            'Drag-and-drop ZIP files into BloodHound GUI'
          ]
        },
        {
          number: 4,
          title: 'Analyze Attack Paths',
          description: 'Run pre-built queries to find paths',
          commands: [
            'Queries: "Shortest Path to Domain Admins"',
            '"Find Computers where Domain Users can RDP"',
            '"Find Principals with DCSync Rights"'
          ]
        }
      ]
    },
    
    {
      id: 'defense',
      title: '🛡️ Detection & Hardening',
      type: 'defensive',
      duration: '2 min',
      
      detection: {
        logs: [
          'Event ID 4662: Operation performed on AD object (ACL enumeration)',
          'Event ID 4624: Successful logon (session enumeration)',
          'High volume of LDAP queries from single source'
        ],
        indicators: [
          'Unusual LDAP search patterns',
          'Enumeration of all users/groups/computers',
          'Multiple failed authentication attempts'
        ]
      },
      
      prevention: [
        {
          title: 'Principle of Least Privilege',
          description: 'Remove unnecessary permissions and group memberships',
          example: 'Regular access reviews and permission audits'
        },
        {
          title: 'Tiered Administration',
          description: 'Separate admin accounts for different privilege levels',
          example: 'Tier 0 (DC), Tier 1 (Servers), Tier 2 (Workstations)'
        },
        {
          title: 'Monitor LDAP Queries',
          description: 'Alert on excessive or unusual LDAP enumeration',
          example: 'SIEM rules for high-volume LDAP queries'
        },
        {
          title: 'Use BloodHound Yourself',
          description: 'Run BloodHound to identify and fix attack paths',
          example: 'Proactive security assessment with BloodHound'
        }
      ]
    }
  ],
  
  quiz: [
    {
      question: 'What database does BloodHound use to store and visualize AD data?',
      options: [
        'MySQL',
        'Neo4j',
        'MongoDB',
        'PostgreSQL'
      ],
      correct: 1,
      explanation: 'BloodHound uses Neo4j, a graph database, to store and visualize Active Directory relationships.'
    },
    {
      question: 'What is the data collector for BloodHound called?',
      options: [
        'BloodHound.exe',
        'SharpHound',
        'ADExplorer',
        'Mimikatz'
      ],
      correct: 1,
      explanation: 'SharpHound is the data collector that enumerates Active Directory and exports data for BloodHound.'
    },
    {
      question: 'Which permission allows an attacker to perform DCSync?',
      options: [
        'GenericAll on Domain',
        'DS-Replication-Get-Changes + DS-Replication-Get-Changes-All',
        'ForceChangePassword',
        'WriteDacl'
      ],
      correct: 1,
      explanation: 'DCSync requires both DS-Replication-Get-Changes permissions, which BloodHound can identify.'
    }
  ],
  
  resources: [
    {
      title: 'BloodHound GitHub',
      url: 'https://github.com/BloodHoundAD/BloodHound',
      type: 'tool'
    },
    {
      title: 'BloodHound Documentation',
      url: 'https://bloodhound.readthedocs.io/',
      type: 'reference'
    }
  ]
};
