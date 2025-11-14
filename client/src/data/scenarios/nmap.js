/**
 * Mission 0: Network Reconnaissance
 *
 * This scenario simulates the initial reconnaissance phase
 * using Nmap to discover live hosts and identify the
 * Domain Controller.
 */

export const nmapScenario = {
  id: 'nmap-recon',
  title: 'Nmap: Network Reconnaissance',
  description: 'Learn how to discover live hosts and enumerate services to find high-value targets like Domain Controllers.',

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

  // Guide content for the sidebar
  guide: {
    overview: `**Network Reconnaissance** is the first step of any attack. Before you can exploit a system, you must find it.

**Attack Flow:**
1.  Use Nmap to perform a "ping scan" to find all live hosts on the target subnet.
2.  Analyze the results to identify potential targets.
3.  Perform a detailed "service scan" on a high-value target to confirm its role.

**Why This Matters:**
This phase is critical for mapping out the network and identifying high-value targets like Domain Controllers, file servers, or web servers.`,
    steps: [
      {
        number: 1,
        title: 'Find Live Hosts',
        description:
          'Run an Nmap "ping scan" (-sn) against the entire 10.0.1.0/24 subnet to see which hosts are online.',
        command: 'nmap -sn 10.0.1.0/24',
        tip:
          '-sn tells Nmap to not scan ports, making it much faster.'
      },
      {
        number: 2,
        title: 'Identify Domain Controller',
        description:
          'Host 10.0.1.10 is online. Run a detailed service scan (-sV) against it to identify the services it is running.',
        command:
          'nmap -sV -p- 10.0.1.10',
        tip: '-sV probes open ports to determine service/version info. -p- scans all 65,535 ports.'
      },
      {
        number: 3,
        title: 'Analyze Scan Results',
        description:
          'The scan results confirm this is a Domain Controller. You can now proceed with enumeration.',
        command: null,
        tip:
          'The presence of ports 88 (Kerberos) and 389 (LDAP) are dead giveaways for a DC.'
      }
    ]
  },

  // Simulation steps executed in the terminal
  steps: [
    {
      id: 1,
      expectedCommand: 'nmap -sn 10.0.1.0/24',
      attackerOutput: [
        'Starting Nmap 7.92 ( https://nmap.org ) at 2025-11-14 21:35 +08',
        'Nmap scan report for 10.0.1.1 (Gateway)',
        'Host is up (0.0010s latency).',
        'Nmap scan report for 10.0.1.10',
        'Host is up (0.0020s latency).',
        'Nmap scan report for 10.0.1.20',
        'Host is up (0.0015s latency).',
        'Nmap scan report for 10.0.1.30',
        'Host is up (0.0018s latency).',
        'Nmap done: 256 IP addresses (4 hosts up) scanned in 2.50 seconds'
      ],
      serverOutput: [
        '[NET] ICMP Echo Request from 10.0.0.5 to 10.0.1.1',
        '[NET] ICMP Echo Request from 10.0.0.5 to 10.0.1.10',
        '[NET] ICMP Echo Request from 10.0.0.5 to 10.0.1.20',
        '[NET] ICMP Echo Request from 10.0.0.5 to 10.0.1.30'
      ],
      delay: 400
    },
    {
      id: 2,
      expectedCommands: [
        'nmap -sV -p- 10.0.1.10',
        'nmap -sV 10.0.1.10' // Also allow a simpler scan
      ],
      commonMistakes: [
        {
          pattern: '^nmap -sn',
          message: 'You already did a ping scan. Now you need to scan for services (-sV) on the target (10.0.1.10).'
        }
      ],
      attackerOutput: [
        'Starting Nmap 7.92 ( https://nmap.org ) at 2025-11-14 21:36 +08',
        'Nmap scan report for 10.0.1.10',
        'Host is up (0.0020s latency).',
        'Not shown: 65526 closed tcp ports',
        'PORT      STATE SERVICE         VERSION',
        '53/tcp    open  domain          Simple DNS Plus',
        '88/tcp    open  kerberos-sec    Microsoft Windows Kerberos (server time: 2025-11-14 13:36:10Z)',
        '135/tcp   open  msrpc           Microsoft Windows RPC',
        '139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn',
        '389/tcp   open  ldap            Microsoft Windows Active Directory LDAP (Domain: contoso.local)',
        '445/tcp   open  microsoft-ds    Windows Server 2019 microsoft-ds',
        '464/tcp   open  kpasswd5        Microsoft Windows kpasswd5',
        '593/tcp   open  ncacn_http      Microsoft Windows RPC over HTTP 1.0',
        '636/tcp   open  ldapssl         Microsoft Windows AD LDAP (SSL)',
        'Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows_server_2019',
        'Nmap done: 1 IP address (1 host up) scanned in 12.45 seconds'
      ],
      serverOutput: [
        '[NET] Aggressive port scan detected from 10.0.0.5 against DC01 (10.0.1.10)',
        '[AUDIT] Dozens of connection attempts to closed ports.',
        '[ALERT] Potential Nmap -sV or -A scan in progress.'
      ],
      delay: 100
    },
    {
      id: 3,
      expectedCommand: null,
      attackerOutput: [
        '',
        '[+] ============================================',
        '[+] Reconnaissance Complete',
        '[+] ============================================',
        '[+] Target IP: 10.0.1.10',
        '[+] Hostname: DC01.contoso.local',
        '[+] Role: Domain Controller (Identified by Kerberos/LDAP)',
        '[+] ============================================',
        '[*] Next Steps:',
        '[*] 1. Enumerate domain users and accounts.',
        '[*] 2. Check for common misconfigurations.',
        '',
        '[+] Attack successful! 🎯'
      ],
      serverOutput: [
        '[INFO] Scan from 10.0.0.5 finished.',
      ],
      delay: 400
    }
  ]
};

export default nmapScenario;