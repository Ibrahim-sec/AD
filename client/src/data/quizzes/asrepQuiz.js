/**
 * AS-REP Roasting Quiz
 * 
 * Post-scenario quiz to reinforce learning about Kerberos pre-auth attacks
 */

const asrepQuiz = {
  scenarioId: 'asrep-roasting',
  title: 'AS-REP Roasting: Pre-Auth Disabled Exploitation',
  questions: [
    {
      id: 1,
      question: 'What does "AS-REP" stand for in Active Directory?',
      options: [
        'Authentication Server Response',
        'Active Server Replication',
        'Automated Security Response',
        'Advanced System Repair'
      ],
      correctIndex: 0,
      explanation: 'AS-REP stands for Authentication Server Response, which is the response from the Kerberos AS (Authentication Server) when a user requests a Ticket Granting Ticket (TGT).'
    },
    {
      id: 2,
      question: 'What is the prerequisite for AS-REP Roasting to work?',
      options: [
        'The user must have a weak password',
        'Kerberos pre-authentication must be disabled for the target account',
        'The user must be logged in',
        'The domain must be running Windows Server 2003'
      ],
      correctIndex: 1,
      explanation: 'AS-REP Roasting requires that Kerberos pre-authentication (PREAUTH) be disabled for the target account. This allows attackers to request a TGT without providing credentials, and the response is encrypted with the user\'s password hash.'
    },
    {
      id: 3,
      question: 'Why might an administrator disable Kerberos pre-authentication?',
      options: [
        'To improve security',
        'To support legacy applications or non-Windows clients that don\'t support pre-authentication',
        'To speed up authentication',
        'To reduce network traffic'
      ],
      correctIndex: 1,
      explanation: 'Pre-authentication is sometimes disabled for compatibility with older systems or applications that don\'t support the Kerberos pre-authentication mechanism, but this creates a security vulnerability.'
    },
    {
      id: 4,
      question: 'What can be cracked offline after obtaining an AS-REP response?',
      options: [
        'The user\'s session token',
        'The user\'s password hash',
        'The domain controller\'s encryption key',
        'The Kerberos service ticket'
      ],
      correctIndex: 1,
      explanation: 'The AS-REP response contains data encrypted with the user\'s password hash. Attackers can perform offline dictionary or brute-force attacks against this hash to recover the plaintext password.'
    }
  ]
};

export default asrepQuiz;
