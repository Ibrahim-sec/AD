/**
 * Kerberoasting Quiz
 * 
 * Post-scenario quiz to reinforce learning about Kerberos attacks
 */

const kerberoastQuiz = {
  scenarioId: 'kerberoasting',
  title: 'Kerberoasting: Service Account Credential Theft',
  questions: [
    {
      id: 1,
      question: 'What is a Service Principal Name (SPN)?',
      options: [
        'A unique identifier for a user account',
        'A unique identifier for a service running on a computer',
        'A network protocol used in Windows',
        'A type of encryption algorithm'
      ],
      correctIndex: 1,
      explanation: 'An SPN uniquely identifies a service instance in Active Directory. Kerberoasting targets accounts with SPNs because they are associated with service accounts that often have weak passwords.'
    },
    {
      id: 2,
      question: 'Why are service account passwords often weaker in Kerberoasting attacks?',
      options: [
        'Service accounts are not protected by Windows security policies',
        'Service accounts are created with default passwords',
        'Administrators often use simple passwords for service accounts to avoid having to manage complex credentials',
        'Service accounts cannot use password hashing'
      ],
      correctIndex: 2,
      explanation: 'Service accounts often have weak passwords because administrators prioritize usability and ease of management over security, making them attractive targets for attackers.'
    },
    {
      id: 3,
      question: 'What does Kerberoasting extract from the domain?',
      options: [
        'Plaintext passwords',
        'Kerberos service tickets (TGS tickets)',
        'User session tokens',
        'NTLM hashes'
      ],
      correctIndex: 1,
      explanation: 'Kerberoasting requests Ticket Granting Service (TGS) tickets for services with SPNs. These tickets are encrypted with the service account\'s password hash, which can then be cracked offline.'
    },
    {
      id: 4,
      question: 'Which tool is commonly used to crack the hashes obtained from Kerberoasting?',
      options: [
        'Mimikatz',
        'Hashcat or John the Ripper',
        'Metasploit',
        'Wireshark'
      ],
      correctIndex: 1,
      explanation: 'Hashcat and John the Ripper are password cracking tools that can perform offline brute-force or dictionary attacks against the service account password hashes extracted via Kerberoasting.'
    }
  ]
};

export default kerberoastQuiz;
