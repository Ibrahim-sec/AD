/**
 * Pass-the-Hash Quiz
 * 
 * Post-scenario quiz to reinforce learning about lateral movement attacks
 */

const pthQuiz = {
  scenarioId: 'pass-the-hash',
  title: 'Pass-the-Hash: Lateral Movement Without Passwords',
  questions: [
    {
      id: 1,
      question: 'What is the main advantage of Pass-the-Hash attacks?',
      options: [
        'They work even if the user has changed their password',
        'They allow attackers to move laterally without knowing the plaintext password',
        'They bypass Windows Defender',
        'They work on all versions of Windows'
      ],
      correctIndex: 1,
      explanation: 'Pass-the-Hash allows attackers to authenticate using only the NTLM hash of a password, without needing to crack or know the plaintext password. This enables lateral movement across the network.'
    },
    {
      id: 2,
      question: 'Which authentication protocol is vulnerable to Pass-the-Hash attacks?',
      options: [
        'Kerberos only',
        'NTLM only',
        'Both NTLM and Kerberos',
        'Neither NTLM nor Kerberos'
      ],
      correctIndex: 1,
      explanation: 'NTLM is vulnerable to Pass-the-Hash attacks because it uses the password hash directly in the authentication process. Kerberos is more resistant because it uses time-based tickets.'
    },
    {
      id: 3,
      question: 'What is a common source of NTLM hashes for Pass-the-Hash attacks?',
      options: [
        'Phishing emails',
        'Credential dumping tools like Mimikatz that extract hashes from memory',
        'Public password databases',
        'Social engineering'
      ],
      correctIndex: 1,
      explanation: 'Tools like Mimikatz can dump NTLM hashes from the Local Security Authority Subsystem Service (LSASS) memory on compromised systems, providing the hashes needed for Pass-the-Hash attacks.'
    },
    {
      id: 4,
      question: 'Which of the following can help defend against Pass-the-Hash attacks?',
      options: [
        'Using longer passwords',
        'Enabling MFA (Multi-Factor Authentication)',
        'Disabling NTLM and enforcing Kerberos',
        'All of the above'
      ],
      correctIndex: 3,
      explanation: 'Multiple defenses are effective: longer passwords make hash cracking harder, MFA prevents authentication even with valid hashes, and disabling NTLM in favor of Kerberos eliminates the vulnerability entirely.'
    }
  ]
};

export default pthQuiz;
