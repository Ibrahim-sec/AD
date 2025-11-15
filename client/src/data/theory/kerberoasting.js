import { kerberoastingDiagram } from '@/data/diagrams';

export const kerberoastingTheory = {
  id: 'kerberoasting',
  title: 'Kerberoasting Attack Fundamentals',
  subtitle: 'Crack service account passwords via Kerberos TGS tickets',
  difficulty: 'Intermediate',
  estimatedTime: '15 minutes',
  xpReward: 50,
  // Diagram reference as an imported object
  diagram: kerberoastingDiagram,
  sections: [
    {
      title: 'Overview',
      content: `
Kerberoasting is a post-exploitation attack method that targets service accounts in Active Directory. It takes advantage of how Kerberos issues service tickets (TGS) encrypted with the service account's password hash. Attackers can request these tickets and attempt to crack them offline to recover plaintext service account credentials.
      `
    },
    {
      title: 'How It Works (Diagram Below)',
      content: `
1. **Attacker requests TGS for a service SPN**
2. **KDC responds with a TGS encrypted with service account hash**
3. **Attacker extracts the encrypted ticket and cracks it offline**
4. **If successful, attacker obtains the service account's password**
      `
      // Diagram will show right after this section
    },
    {
      title: 'Defenses',
      content: `
- Use long, complex service account passwords
- Rotate service account passwords regularly
- Detect abnormal TGS requests for service SPNs
- Restrict service account permissions
      `
    }
  ],
  quiz: {
    questions: [
      {
        question: "What encryption is used for service tickets in Kerberoasting?",
        options: [
          "The service account's password hash",
          "The domain administrator's password",
          "The user's password hash",
          "A random session key"
        ],
        correctIndex: 0,
        explanation: "Service tickets for SPNs are encrypted with the service account's password hash."
      },
      {
        question: "Which is the BEST defense against Kerberoasting?",
        options: [
          "Disable Kerberos authentication",
          "Enforce strong/random service account passwords",
          "Set user accounts with SPNs",
          "Use single sign-on for all users"
        ],
        correctIndex: 1,
        explanation: "Strong, random passwords for service accounts make hash cracking impractical."
      }
    ]
  }
};
