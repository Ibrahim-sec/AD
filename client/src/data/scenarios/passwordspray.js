/**
 * Mission 1B: Password Spraying
 *
 * This scenario simulates a password spraying attack to find
 * a valid set of credentials using a common, weak password.
 */

export const passwordSprayScenario = {
  id: 'password-spraying',
  title: 'Password Spraying: Finding Weak Credentials',
  description: 'Learn how attackers use a single password against many accounts to find a valid login without causing lockouts.',
  difficulty: 'Beginner', // Added difficulty

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
    overview: `**Password Spraying** is an attack that tries a small number of common passwords (like 'Spring2025!') against a large list of usernames.

**Attack Flow:**
1.  Obtain a list of valid usernames (we'll assume this from recon).
2.  Use a tool like 'kerbrute' to "spray" one password against all users.
3.  Analyze the results to find a successful login.

**Why This Matters:**
This method avoids locking out accounts (which trying many passwords against one user would do). It's highly effective at finding the "low-hanging fruit" in a network.`,
    steps: [
      {
        number: 1,
        title: 'Enumerate Usernames',
        description:
          'First, get a list of users. We can use a pre-built list for this simulation. Our goal is to test a password.',
        command: 'cat userlist.txt | head -n 3',
        tip: 'This just shows you the userlist we are about to use.'
      },
      {
        number: 2,
        title: 'Perform Password Spray',
        description:
          'Use "kerbrute" to try the password "Spring2025!" against every user in our list.',
        command:
          'kerbrute passwordspray -d contoso.local userlist.txt "Spring2025!"',
        tip: 'Kerbrute uses Kerberos (Port 88) to validate credentials without locking accounts.'
      },
      {
        number: 3,
        title: 'Analyze Results',
        description:
          'The spray is complete. We found a valid account!',
        command: null,
        tip:
          'The "svc_sharepoint" account has a weak password. We can use this for our next steps.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'cat userlist.txt | head -n 3',
      attackerOutput: [
        'admin',
        'guest',
        'svc_backup',
        '(...242 more users)'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (local file read).'
      ],
      delay: 200
    },
    {
      id: 2,
      expectedCommands: [
        'kerbrute passwordspray -d contoso.local userlist.txt "Spring2025!"',
        'kerbrute passwordspray -d contoso.local userlist.txt Spring2025!' // Allow without quotes
      ],
      attackerOutput: [
        '[*] Starting password spray on domain: contoso.local',
        '[*] Using password: "Spring2025!"',
        '[*] Loaded 245 usernames.',
        '[*] Spraying users (1 thread)...',
        '[*] 50/245 users sprayed',
        '[*] 100/245 users sprayed',
        '[*] 150/245 users sprayed',
        '[+] SUCCESS: CONTOSO\\svc_sharepoint:Spring2025!',
        '[*] 200/245 users sprayed',
        '[*] 245/245 users sprayed.',
        '[*] Spray complete! Found 1 valid credential.'
      ],
      serverOutput: [
        '[KERBEROS] AS-REQ from 10.0.0.5 for "admin"',
        '[KERBEROS] AS-REQ from 10.0.0.5 for "guest"',
        '[KERBEROS] AS-REQ from 10.0.0.5 for "svc_backup"',
        '[...]',
        '[KERBEROS] AS-REQ from 10.0.0.5 for "svc_sharepoint"',
        '[KERBEROS] Valid credentials provided. Issuing TGT.',
        '[...]',
        '[AUDIT] High volume of Kerberos AS-REQs from 10.0.0.5.',
        '[ALERT] Potential Password Spraying attack detected.'
      ],
      delay: 50
    },
    {
      id: 3,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] Password Spraying Complete',
        '[+] ============================================',
        '[+] Credentials Found: 1',
        '[+] User: svc_sharepoint',
        '[+] Pass: Spring2025!',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use these credentials to enumerate the network.',
        '[*] 2. Check this user\'s privileges with BloodHound.',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '[INFO] Attacker 10.0.0.5 now has a valid user session.',
      ],
      delay: 400
    }
  ]
};

export default passwordSprayScenario;