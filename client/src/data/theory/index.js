// client/src/data/theory/index.js

/**
 * Theory modules for each attack technique
 * Provides educational content before scenarios
 */

export const theoryModules = {
  'kerberoasting': {
    id: 'kerberoasting',
    title: 'Understanding Kerberoasting',
    estimatedTime: '10 minutes',
    difficulty: 'Intermediate',
    prerequisites: ['Active Directory Basics', 'Kerberos Authentication'],
    
    sections: [
      {
        id: 'what-is-kerberoasting',
        title: 'What is Kerberoasting?',
        type: 'text',
        content: `Kerberoasting is an attack technique that exploits how Kerberos handles service authentication in Active Directory environments. When a user requests access to a service, the Domain Controller issues a service ticket (TGS) encrypted with the service account's password hash.

**Key Concept**: These service tickets can be requested by any authenticated domain user, and the encryption can be cracked offline to reveal the service account's password.`,
        keyPoints: [
          'Targets service accounts with SPNs (Service Principal Names)',
          'TGS tickets are encrypted with service account password',
          'Offline brute-force attack on encrypted tickets',
          'No special privileges required to request tickets'
        ]
      },
      {
        id: 'kerberos-overview',
        title: 'Kerberos Authentication Flow',
        type: 'diagram',
        content: `Understanding the Kerberos authentication process is crucial to comprehending how Kerberoasting works.`,
        diagram: {
          type: 'flow',
          steps: [
            { id: 1, label: 'User Authentication', description: 'User authenticates to KDC (Key Distribution Center)' },
            { id: 2, label: 'TGT Issued', description: 'KDC issues Ticket Granting Ticket (TGT)' },
            { id: 3, label: 'Service Request', description: 'User requests service ticket (TGS) using TGT' },
            { id: 4, label: 'TGS Issued', description: 'KDC issues service ticket encrypted with service password' },
            { id: 5, label: 'Access Service', description: 'User presents TGS to service for authentication' }
          ]
        }
      },
      {
        id: 'spn-explanation',
        title: 'Service Principal Names (SPNs)',
        type: 'text',
        content: `Service Principal Names are unique identifiers for service instances in Active Directory. They link a service to a specific service account.`,
        example: {
          title: 'SPN Format Examples',
          code: `# HTTP service running under 'svc_web' account
setspn -L svc_web
  MSSQLSvc/SQL01.contoso.local:1433
  HTTP/web.contoso.local

# SQL service
MSSQLSvc/SQL01.contoso.local:1433

# Format: ServiceClass/Host:Port/ServiceName`
        },
        keyPoints: [
          'Format: ServiceClass/Host:Port',
          'Registered in Active Directory',
          'One account can have multiple SPNs',
          'Required for Kerberos authentication to services'
        ]
      },
      {
        id: 'attack-process',
        title: 'Kerberoasting Attack Process',
        type: 'steps',
        content: 'The Kerberoasting attack follows these sequential steps:',
        steps: [
          {
            number: 1,
            title: 'Enumerate SPNs',
            description: 'Identify all service accounts with registered SPNs in the domain',
            commands: ['Get-DomainUser -SPN', 'setspn -Q */*']
          },
          {
            number: 2,
            title: 'Request Service Tickets',
            description: 'Request TGS tickets for each discovered SPN',
            commands: ['Add-Type -AssemblyName System.IdentityModel', 'New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken']
          },
          {
            number: 3,
            title: 'Export Tickets',
            description: 'Extract the encrypted service tickets from memory',
            commands: ['Invoke-Mimikatz -Command "kerberos::list /export"', 'Rubeus.exe kerberoast /format:hashcat']
          },
          {
            number: 4,
            title: 'Crack Offline',
            description: 'Use password cracking tools to recover the plaintext password',
            commands: ['hashcat -m 13100 tickets.txt wordlist.txt', 'john --format=krb5tgs tickets.txt']
          }
        ]
      },
      {
        id: 'why-it-works',
        title: 'Why This Attack Works',
        type: 'text',
        content: `Kerberoasting is successful due to several design characteristics of Kerberos:`,
        reasons: [
          {
            title: 'Weak Service Account Passwords',
            description: 'Many organizations use weak passwords for service accounts (e.g., "Summer2023!")',
            impact: 'Easy to crack offline'
          },
          {
            title: 'RC4 Encryption',
            description: 'Older encryption (RC4_HMAC_MD5) is still widely supported for backward compatibility',
            impact: 'Faster to brute-force than AES'
          },
          {
            title: 'No Rate Limiting',
            description: 'Ticket requests are not rate-limited or logged as suspicious',
            impact: 'Attackers can request hundreds of tickets'
          },
          {
            title: 'Offline Attack',
            description: 'Once tickets are exported, cracking happens offline',
            impact: 'No network traffic to detect'
          }
        ]
      },
      {
        id: 'detection',
        title: 'Detection & Defense',
        type: 'defense',
        content: 'Understanding how to detect and prevent Kerberoasting is crucial for defenders.',
        detection: {
          logs: [
            'Event ID 4769: Kerberos service ticket requested',
            'Event ID 4770: Kerberos service ticket renewed',
            'Look for RC4 encryption in ticket requests'
          ],
          indicators: [
            'Multiple 4769 events from single user in short time',
            'Service ticket requests for high-value SPNs',
            'RC4 encryption usage (should be rare in modern environments)'
          ]
        },
        prevention: [
          {
            title: 'Strong Passwords',
            description: 'Use passwords >25 characters for service accounts',
            example: 'Use password managers to generate complex passwords'
          },
          {
            title: 'Managed Service Accounts',
            description: 'Use Group Managed Service Accounts (gMSA) with 128-character auto-rotating passwords',
            example: 'New-ADServiceAccount -Name gMSA_SQL01'
          },
          {
            title: 'Disable RC4',
            description: 'Force AES encryption only in Group Policy',
            example: 'Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options'
          },
          {
            title: 'Least Privilege',
            description: 'Avoid giving service accounts Domain Admin rights',
            example: 'Grant only necessary permissions to specific resources'
          }
        ]
      },
      {
        id: 'real-world',
        title: 'Real-World Context',
        type: 'case-study',
        content: 'Kerberoasting has been used in numerous real-world breaches:',
        examples: [
          {
            title: 'Common Attack Pattern',
            scenario: 'Attacker gains initial access through phishing, then performs Kerberoasting to escalate privileges',
            outcome: 'Service account compromised, leading to database access and data exfiltration'
          },
          {
            title: 'Ransomware Operations',
            scenario: 'Ransomware groups use Kerberoasting to find high-privilege accounts for lateral movement',
            outcome: 'Domain-wide compromise and encryption'
          }
        ],
        statistics: {
          prevalence: '~35% of AD environments have weak service account passwords',
          successRate: '~60-70% of Kerberoasting attempts succeed',
          averageTime: 'Weak passwords cracked in <1 hour'
        }
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
        explanation: 'Service tickets (TGS) are encrypted with the hash of the service account\'s password, which is why we can crack them offline.'
      },
      {
        question: 'Which of these is the BEST defense against Kerberoasting?',
        options: [
          'Disable Kerberos authentication',
          'Use Group Managed Service Accounts (gMSA)',
          'Remove all SPNs from Active Directory',
          'Block port 88'
        ],
        correct: 1,
        explanation: 'gMSAs use 128-character auto-rotating passwords that are virtually impossible to crack, making Kerberoasting ineffective.'
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
        explanation: 'Any authenticated domain user can request service tickets, which is why Kerberoasting is so dangerous - no special privileges needed!'
      }
    ],
    
    resources: [
      {
        title: 'MITRE ATT&CK',
        url: 'https://attack.mitre.org/techniques/T1558/003/',
        type: 'reference'
      },
      {
        title: 'adsecurity.org - Kerberoasting',
        url: 'https://adsecurity.org/?p=2293',
        type: 'article'
      },
      {
        title: 'Rubeus Tool Documentation',
        url: 'https://github.com/GhostPack/Rubeus',
        type: 'tool'
      }
    ]
  },

  'dcsync': {
    id: 'dcsync',
    title: 'Understanding DCSync Attack',
    estimatedTime: '12 minutes',
    difficulty: 'Advanced',
    prerequisites: ['Active Directory Replication', 'Domain Controller Architecture'],
    
    sections: [
      {
        id: 'what-is-dcsync',
        title: 'What is DCSync?',
        type: 'text',
        content: `DCSync is a powerful attack that allows an attacker to impersonate a Domain Controller and request password hashes for any user in the domain through the Directory Replication Service Remote Protocol (MS-DRSR).

**Critical Impact**: With DCSync, an attacker can extract the krbtgt hash and create Golden Tickets for persistent, undetectable domain admin access.`,
        keyPoints: [
          'Abuses legitimate AD replication protocol',
          'Extracts password hashes without touching LSASS',
          'Requires specific replication permissions',
          'Can extract krbtgt hash for Golden Ticket attacks'
        ]
      },
      {
        id: 'replication-overview',
        title: 'Active Directory Replication',
        type: 'text',
        content: `Active Directory uses multi-master replication to keep all Domain Controllers synchronized. The DCSync attack exploits this legitimate replication mechanism.

**Normal Replication**: Domain Controllers replicate changes using the Directory Replication Service (DRS). This includes password hashes, group memberships, and all AD object attributes.

**The Attack**: An attacker with appropriate permissions can pretend to be a Domain Controller and request replication of any object, including password hashes.`,
        diagram: {
          type: 'flow',
          steps: [
            { id: 1, label: 'Attacker', description: 'Compromised account with replication rights' },
            { id: 2, label: 'Replication Request', description: 'Pretends to be a DC using MS-DRSR protocol' },
            { id: 3, label: 'Domain Controller', description: 'Validates permissions' },
            { id: 4, label: 'Data Transfer', description: 'Sends requested password hashes' },
            { id: 5, label: 'Hash Extraction', description: 'Attacker receives NTLM/Kerberos hashes' }
          ]
        }
      },
      {
        id: 'required-permissions',
        title: 'Required Permissions for DCSync',
        type: 'text',
        content: 'DCSync requires specific extended rights on the domain object:',
        permissions: [
          {
            name: 'DS-Replication-Get-Changes',
            guid: '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
            description: 'Allows reading all objects in the directory'
          },
          {
            name: 'DS-Replication-Get-Changes-All',
            guid: '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2',
            description: 'Allows reading secret domain data (password hashes)'
          },
          {
            name: 'DS-Replication-Get-Changes-In-Filtered-Set',
            guid: '89e95b76-444d-4c62-991a-0facbeda640c',
            description: 'Optional - allows replication of confidential attributes'
          }
        ],
        defaultHolders: [
          'Domain Admins',
          'Enterprise Admins',
          'Administrators',
          'Domain Controllers'
        ]
      },
      {
        id: 'attack-process',
        title: 'DCSync Attack Process',
        type: 'steps',
        steps: [
          {
            number: 1,
            title: 'Verify Permissions',
            description: 'Check if compromised account has replication rights',
            commands: ['Get-DomainObjectAcl -SearchBase "DC=contoso,DC=local" -ResolveGUIDs']
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
            description: 'Receive NTLM and Kerberos key material',
            output: 'Administrator NTLM hash, krbtgt hash, AES keys'
          },
          {
            number: 4,
            title: 'Use Credentials',
            description: 'Perform Pass-the-Hash or create Golden Tickets',
            commands: ['Use hashes for authentication or ticket creation']
          }
        ]
      },
      {
        id: 'why-so-dangerous',
        title: 'Why DCSync is Extremely Dangerous',
        type: 'text',
        content: 'DCSync is considered one of the most critical AD attacks:',
        dangers: [
          {
            title: 'Stealth',
            description: 'Appears as legitimate replication traffic',
            impact: 'Very difficult to detect without proper monitoring'
          },
          {
            title: 'No LSASS Access Needed',
            description: 'Doesn\'t require dumping memory or accessing the DC directly',
            impact: 'Bypasses many endpoint protection solutions'
          },
          {
            title: 'Complete Domain Compromise',
            description: 'Can extract every user hash including krbtgt',
            impact: 'Leads to Golden Ticket attacks and persistent access'
          },
          {
            title: 'Works Remotely',
            description: 'Can be executed from any domain-joined machine',
            impact: 'Attacker doesn\'t need to be on the DC'
          }
        ]
      },
      {
        id: 'detection',
        title: 'Detecting DCSync Attacks',
        type: 'defense',
        detection: {
          logs: [
            'Event ID 4662: An operation was performed on an object',
            'Directory Service Access auditing must be enabled',
            'Look for replication requests from non-DC computers'
          ],
          indicators: [
            'Event 4662 with Replication-Get-Changes GUIDs',
            'Replication requests from workstations',
            'Unusual accounts performing replication',
            'Multiple replication requests in short time'
          ],
          tools: [
            'Windows Event Logs with proper SACL configuration',
            'Azure AD Connect Health',
            'SIEM rules for DCSync detection',
            'Bloodhound for permission auditing'
          ]
        },
        prevention: [
          {
            title: 'Limit Replication Permissions',
            description: 'Regularly audit who has replication rights',
            example: 'Remove unnecessary accounts from groups with these permissions'
          },
          {
            title: 'Protected Users Group',
            description: 'Add high-value accounts to Protected Users group',
            example: 'Prevents NTLM hash replication for these users'
          },
          {
            title: 'Enable Advanced Auditing',
            description: 'Configure Directory Service Access auditing',
            example: 'auditpol /set /subcategory:"Directory Service Access" /success:enable'
          },
          {
            title: 'Network Segmentation',
            description: 'Restrict which systems can communicate with DCs on replication ports',
            example: 'Only allow DC-to-DC traffic on TCP 135, 389, 636, 3268, 3269'
          }
        ]
      },
      {
        id: 'real-world',
        title: 'Real-World Impact',
        type: 'case-study',
        examples: [
          {
            title: 'NotPetya Ransomware (2017)',
            scenario: 'Used DCSync to spread laterally and extract credentials',
            outcome: '$10 billion in damages worldwide'
          },
          {
            title: 'APT29 (Cozy Bear)',
            scenario: 'Russian APT group used DCSync for persistent access in government networks',
            outcome: 'Multi-year persistence with Golden Tickets'
          }
        ],
        statistics: {
          prevalence: 'Used in ~40% of advanced AD compromises',
          detectionRate: 'Only ~25% of organizations have proper DCSync detection',
          averageDetectionTime: '~200 days before discovery'
        }
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
        explanation: 'DCSync abuses the MS-DRSR protocol, which is used for legitimate replication between Domain Controllers.'
      },
      {
        question: 'Which permission is NOT required for DCSync?',
        options: [
          'DS-Replication-Get-Changes',
          'DS-Replication-Get-Changes-All',
          'GenericAll on the domain object',
          'Local Administrator on the DC'
        ],
        correct: 3,
        explanation: 'DCSync does not require local admin access to the DC. It only requires the replication permissions on the domain object.'
      },
      {
        question: 'What makes DCSync particularly dangerous?',
        options: [
          'It requires Domain Admin privileges',
          'It can only be executed from a Domain Controller',
          'It appears as legitimate replication traffic',
          'It permanently damages Active Directory'
        ],
        correct: 2,
        explanation: 'DCSync is dangerous because it mimics legitimate DC replication traffic, making it very difficult to detect without proper auditing.'
      }
    ],
    
    resources: [
      {
        title: 'MITRE ATT&CK - DCSync',
        url: 'https://attack.mitre.org/techniques/T1003/006/',
        type: 'reference'
      },
      {
        title: 'Mimikatz DCSync',
        url: 'https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump',
        type: 'tool'
      }
    ]
  },

  // Add more theory modules for other scenarios...
};

// Helper function to get theory module by scenario ID
export const getTheoryModule = (scenarioId) => {
  return theoryModules[scenarioId] || null;
};

// Check if scenario has theory module
export const hasTheoryModule = (scenarioId) => {
  return scenarioId in theoryModules;
};
