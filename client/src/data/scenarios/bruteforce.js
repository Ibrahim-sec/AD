/**
 * Mission 1D: Brute-Force (Account Lockout)
 *
 * This scenario simulates a "noisy" brute-force attack to
 * demonstrate account lockout policies.
 */

export const bruteforceScenario = {
  id: 'bruteforce-lockout',
  title: 'Brute-Force: Account Lockout',
  description: 'Learn why password spraying is used by testing a "noisy" brute-force attack that triggers account lockouts.',
  difficulty: 'Beginner',

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
    overview: `**Brute-Force** (as opposed to Password Spraying) is a "noisy" attack where an attacker tries many different passwords against a *single* known username.

**Attack Flow:**
1.  Identify a valid username (e.g., 'svc_backup' from our recon).
2.  Use a tool like 'kerbrute' to try a password list against that one user.
3.  Observe the result.

**Why This Matters:**
Most secure domains have an **Account Lockout Policy** (e.g., "lock account after 5 failed attempts"). This attack will fail and be very loud, which teaches you *why* attackers prefer stealthy methods like Password Spraying.`,
    steps: [
      {
        number: 1,
        title: 'Run Brute-Force Attack',
        description:
          'You know "svc_backup" is a valid user. Use "kerbrute" with a password list to try and guess its password.',
        command: 'kerbrute bruteforce -d contoso.local password_list.txt svc_backup',
        tip:
          'This will try all passwords in the list against the "svc_backup" account.'
      },
      {
        number: 2,
        title: 'Attack Detected & Failed',
        description:
          'The attack failed and the account is now locked. This is what a "noisy" attack looks like.',
        command: null,
        tip:
          'This is why attackers prefer Password Spraying (1 password vs. all users) to avoid triggering this exact policy.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommands: [
        'kerbrute bruteforce -d contoso.local password_list.txt svc_backup',
        'kerbrute bruteforce -d contoso.local password_list.txt contoso.local/svc_backup'
      ],
      attackerOutput: [
        '[*] Starting brute-force on domain: contoso.local for user: svc_backup',
        '[*] Loaded 100 passwords.',
        '[*] Trying "Password123"... (FAIL)',
        '[*] Trying "Password!"... (FAIL)',
        '[*] Trying "admin"... (FAIL)',
        '[*] Trying "123456"... (FAIL)',
        '[*] Trying "Summer2025"... (FAIL)',
        '[!] 2025/11/14 21:50:01 ACCOUNT LOCKED: CONTOSO\\svc_backup',
        '[*] Brute-force complete. Account is locked.'
      ],
      serverOutput: [
        '[AUTH] Failed logon for CONTOSO\\svc_backup from 10.0.0.5',
        '[AUTH] Failed logon for CONTOSO\\svc_backup from 10.0.0.5',
        '[AUTH] Failed logon for CONTOSO\\svc_backup from 10.0.0.5',
        '[AUTH] Failed logon for CONTOSO\\svc_backup from 10.0.0.5',
        '[AUTH] Failed logon for CONTOSO\\svc_backup from 10.0.0.5',
        '[ALERT] Account lockout policy triggered for "svc_backup".',
        '[AUDIT] Account "svc_backup" has been locked due to 5 failed logon attempts.'
      ],
      delay: 500,
      // This attack grants no loot, it's a "failure" scenario
      lootToGrant: {}
    },
    {
      id: 2,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] Brute-Force Attack Summary',
        '[+] ============================================',
        '[+] Credentials Found: 0',
        '[+] Accounts Locked: 1 (svc_backup)',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. This attack vector failed and was noisy.',
        '[*] 2. Try a stealthier method like Password Spraying.',
        '',
        '[+] Attack Failed! (But you learned a valuable lesson) 🎯'
      ],
      serverOutput: [
        '[INFO] Blue Team SOC has been alerted to the account lockout.',
      ],
      delay: 400
    }
  ]
};

export default bruteforceScenario;