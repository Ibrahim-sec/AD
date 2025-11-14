/**
 * BloodHound AD Reconnaissance Scenario
 *
 * This scenario simulates using BloodHound to map Active Directory relationships
 * and identify attack paths in a corporate network.
 */

export const bloodhoundScenario = {
  id: 'bloodhound',
  title: 'BloodHound: Active Directory Reconnaissance',
  description: 'Learn how attackers use BloodHound to map AD relationships and find privilege escalation paths.',

  // Network configuration
  network: {
    attacker: {
      ip: '10.0.0.5',
      hostname: 'kali-attacker',
      role: 'Red Team Machine'
    },
    target: {
      ip: '10.0.1.10',
      hostname: 'DC01.contoso.local',
      role: 'Domain Controller'
    },
    domain: 'contoso.local'
  },

  // Guide content
  guide: {
    overview: `**BloodHound** is a powerful Active Directory reconnaissance tool that uses graph theory to reveal hidden relationships and attack paths in AD environments.

**Attack Flow:**
1. Start the Neo4j graph database
2. Run BloodHound's Python collector to gather AD data
3. Analyze the collected data to find privilege escalation paths

**Why This Matters:**
BloodHound can quickly identify complex attack paths that would take hours to find manually.
    
**Note:** This scenario uses the 'sqlservice' credentials compromised in the Kerberoasting mission.`,

    steps: [
      {
        number: 1,
        title: 'Start Neo4j Database',
        description: 'Neo4j is the graph database that stores BloodHound data. Start it before collecting AD information.',
        command: 'neo4j-start',
        tip: 'Neo4j runs on port 7474 (HTTP) and 7687 (Bolt protocol)'
      },
      {
        number: 2,
        title: 'Run BloodHound Python Collector',
        description: 'Use the compromised "sqlservice" credentials to collect AD objects. Find the password in your "Files" tab.',
        command: 'bloodhound-python -d contoso.local -u sqlservice -p [PASSWORD-FROM-FILES-TAB] --zip',
        tip: 'Check the "Files" tab for the credential you harvested in the Kerberoasting scenario.'
      },
      {
        number: 3,
        title: 'Collection Complete',
        description: 'Data has been exported to BH.zip. You can now import this into the BloodHound GUI to visualize attack paths.',
        command: null,
        tip: 'In a real scenario, you would now open the BloodHound GUI and drag-and-drop the ZIP file to analyze the data'
      }
    ]
  },

  // Simulation steps
  steps: [
    {
      id: 1,
      expectedCommand: 'neo4j-start',
      attackerOutput: [
        '[*] Starting Neo4j database...',
        '[*] Neo4j is running at http://localhost:7474',
        '[*] Bolt protocol available at bolt://localhost:7687',
        '[+] Database ready!'
      ],
      serverOutput: [
        '[INFO] Neo4j Graph Database - Version 4.4.0',
        '[INFO] Starting database service...',
        '[INFO] Bolt enabled on 0.0.0.0:7687',
        '[INFO] HTTP enabled on 0.0.0.0:7474',
        '[INFO] Database started successfully'
      ],
      delay: 800 // milliseconds between lines
    },
    {
      id: 2,
      // This now uses the LOOT variable, which your SimulatorPage will resolve
      expectedCommand: 'bloodhound-python -d contoso.local -u sqlservice -p [LOOT:sqlservice] --zip',
      attackerOutput: [
        '[*] Initializing BloodHound Python collector',
        '[*] Connecting to contoso.local...',
        '[*] Authenticating as sqlservice@contoso.local',
        '[+] Authentication successful!',
        '[*] Resolving domain controller: DC01.contoso.local (10.0.1.10)',
        '[*] Querying LDAP for domain objects...',
        '[*] Collecting users... (245 found)',
        '[*] Collecting groups... (89 found)',
        '[*] Collecting computers... (156 found)',
        '[*] Collecting trusts... (2 found)',
        '[*] Collecting GPOs... (12 found)',
        '[*] Processing ACLs and relationships...',
        '[*] Compressing data to BH.zip',
        '[+] Collection complete! Output saved to: BH.zip'
      ],
      serverOutput: [
        '[LDAP] Connection established from 10.0.0.5:49152',
        '[AUTH] NTLM authentication attempt: CONTOSO\\sqlservice',
        '[AUTH] Authentication successful for sqlservice@contoso.local',
        '[LDAP] Query: (&(objectClass=user)(objectCategory=person))',
        '[LDAP] Returned 245 user objects',
        '[LDAP] Query: (objectClass=group)',
        '[LDAP] Returned 89 group objects',
        '[LDAP] Query: (objectClass=computer)',
        '[LDAP] Returned 156 computer objects',
        '[LDAP] Query: (objectClass=trustedDomain)',
        '[LDAP] Returned 2 trust objects',
        '[LDAP] Query: (objectClass=groupPolicyContainer)',
        '[LDAP] Returned 12 GPO objects',
        '[LDAP] Multiple ACL queries detected',
        '[WARN] Extensive enumeration activity from 10.0.0.5',
        '[LDAP] Connection closed by client'
      ],
      delay: 600
    },
    {
      id: 3,
      expectedCommand: null, // Auto-advance
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] BloodHound Collection Summary',
        '[+] ============================================',
        '[+] Domain: contoso.local',
        '[+] Users: 245',
        '[+] Groups: 89',
        '[+] Computers: 156',
        '[+] Trusts: 2',
        '[+] GPOs: 12',
        '[+] Output File: BH.zip (2.3 MB)',
        '[+] ============================================',
        '',
        '[*] Next Steps:',
        '[*] 1. Open BloodHound GUI',
        '[*] 2. Import BH.zip',
        '[*] 3. Run pre-built queries to find attack paths',
        '',
        '[+] Happy hunting! 🎯'
      ],
      serverOutput: [
        '',
        '[INFO] Connection summary for 10.0.0.5:',
        '[INFO] - Duration: 47 seconds',
        '[INFO] - LDAP queries: 1,247',
        '[INFO] - Objects accessed: 502',
        '[INFO] - Authentication: NTLM (sqlservice)',
        '[WARN] Behavior consistent with AD enumeration tools',
        '[ALERT] Recommend investigation of sqlservice account activity'
      ],
      delay: 400
    }
  ]
};

export default bloodhoundScenario;