/**
 * BloodHound Quiz
 * 
 * Post-scenario quiz to reinforce learning about AD reconnaissance
 */

const bloodhoundQuiz = {
  scenarioId: 'bloodhound',
  title: 'BloodHound: Active Directory Reconnaissance',
  questions: [
    {
      id: 1,
      question: 'What is the primary purpose of BloodHound in Active Directory attacks?',
      options: [
        'To directly exploit vulnerabilities in Windows',
        'To map AD relationships and identify attack paths',
        'To crack user passwords',
        'To disable antivirus software'
      ],
      correctIndex: 1,
      explanation: 'BloodHound uses graph theory to visualize complex relationships in Active Directory and reveal hidden attack paths that would be difficult to find manually.'
    },
    {
      id: 2,
      question: 'Which database does BloodHound use to store collected AD data?',
      options: [
        'MongoDB',
        'PostgreSQL',
        'Neo4j',
        'MySQL'
      ],
      correctIndex: 2,
      explanation: 'Neo4j is a graph database that excels at storing and querying relationship data, making it ideal for BloodHound\'s attack path analysis.'
    },
    {
      id: 3,
      question: 'What does the "--zip" flag do in bloodhound-python?',
      options: [
        'Compresses the output into a single ZIP file for easy import',
        'Encrypts the collected data',
        'Uploads data to a remote server',
        'Deletes temporary files'
      ],
      correctIndex: 0,
      explanation: 'The --zip flag packages all collected AD data into a single compressed file that can be easily imported into the BloodHound GUI for visualization.'
    },
    {
      id: 4,
      question: 'Which of the following is NOT typically revealed by BloodHound analysis?',
      options: [
        'Shortest path to Domain Admin',
        'Kerberoastable service accounts',
        'User passwords in plaintext',
        'Accounts with DCSync rights'
      ],
      correctIndex: 2,
      explanation: 'BloodHound reveals relationships and permissions, but it does not extract plaintext passwords. Passwords are typically obtained through other attack methods like credential dumping or phishing.'
    }
  ]
};

export default bloodhoundQuiz;
