// client/src/data/scenarios/nmap-recon.js
// Example scenario demonstrating multiple accepted command variations

export const nmapReconScenario = {
  id: 'nmap-recon',
  title: 'Nmap: Network Reconnaissance',
  description: 'Learn basic network scanning with Nmap',
  difficulty: 'beginner',
  category: 'reconnaissance',
  
  network: {
    attacker: {
      hostname: 'kali-attacker',
      ip: '10.0.0.5'
    },
    target: {
      hostname: 'target-server',
      ip: '10.0.1.10'
    },
    dc: {
      hostname: 'DC01',
      ip: '10.0.1.1'
    },
    domain: 'contoso.local'
  },
  
  steps: [
    {
      id: 0,
      description: 'Perform a ping scan to discover live hosts on the network. Use nmap with the -sn flag to scan the 10.0.1.0/24 subnet.',
      
      // NEW: Multiple accepted commands (all variations work!)
      expectedCommands: [
        'nmap -sn 10.0.1.0/24',           // Standard format
        'nmap 10.0.1.0/24 -sn',           // Flag at end
        'nmap -sn 10.0.1.1-255',          // Range format
        'nmap -sn 10.0.1.*',              // Wildcard format
        'nmap -sn 10.0.1.0/255.255.255.0' // Netmask format
      ],
      
      hintShort: 'Use nmap with -sn flag to perform a ping scan',
      hintFull: 'Try: nmap -sn 10.0.1.0/24',
      
      attackerOutput: [
        '[*] Starting Nmap ping scan...',
        '[*] Scanning 10.0.1.0/24 subnet',
        '',
        '[+] Host is up: 10.0.1.1 (0.001s latency)',
        '[+] Host is up: 10.0.1.10 (0.002s latency)',
        '[+] Host is up: 10.0.1.25 (0.003s latency)',
        '',
        '[*] Nmap done: 3 hosts up'
      ],
      
      serverOutput: [
        '[SYSTEM] ICMP echo request received from 10.0.0.5',
        '[SYSTEM] Responding to ping request'
      ],
      
      commonMistakes: [
        { message: 'Forgot the -sn flag for ping scan' },
        { message: 'Used wrong subnet notation' }
      ]
    },
    
    {
      id: 1,
      description: 'Scan the target server for open ports. Use nmap to scan common ports on 10.0.1.10.',
      
      expectedCommands: [
        'nmap 10.0.1.10',
        'nmap -sT 10.0.1.10',
        'nmap -p- 10.0.1.10',
        'nmap -p 1-65535 10.0.1.10'
      ],
      
      hintShort: 'Use nmap followed by the target IP',
      hintFull: 'Try: nmap 10.0.1.10',
      
      attackerOutput: [
        '[*] Starting Nmap port scan on 10.0.1.10...',
        '',
        'PORT     STATE SERVICE',
        '22/tcp   open  ssh',
        '80/tcp   open  http',
        '135/tcp  open  msrpc',
        '139/tcp  open  netbios-ssn',
        '445/tcp  open  microsoft-ds',
        '3389/tcp open  ms-wbt-server',
        '',
        '[*] Nmap done: 6 ports open'
      ],
      
      serverOutput: [
        '[SECURITY] Port scan detected from 10.0.0.5',
        '[SECURITY] Multiple connection attempts logged'
      ]
    },
    
    {
      id: 2,
      description: 'Perform service version detection on the target. Use nmap with the -sV flag.',
      
      expectedCommands: [
        'nmap -sV 10.0.1.10',
        'nmap 10.0.1.10 -sV',
        'nmap -sV -p- 10.0.1.10',
        'nmap -sV --version-all 10.0.1.10'
      ],
      
      hintShort: 'Add the -sV flag for version detection',
      hintFull: 'Try: nmap -sV 10.0.1.10',
      
      attackerOutput: [
        '[*] Starting Nmap version scan...',
        '',
        'PORT     STATE SERVICE       VERSION',
        '22/tcp   open  ssh           OpenSSH 8.2',
        '80/tcp   open  http          Microsoft IIS 10.0',
        '445/tcp  open  microsoft-ds  Windows Server 2019',
        '3389/tcp open  ms-wbt-server Microsoft Terminal Services',
        '',
        '[*] Service detection complete'
      ],
      
      serverOutput: [
        '[SECURITY] Aggressive service probing detected',
        '[SECURITY] Version enumeration attempt from 10.0.0.5'
      ],
      
      lootToGrant: {
        creds: [],
        files: {
          'scan_results.txt': {
            content: 'Target: 10.0.1.10\nOS: Windows Server 2019\nOpen Ports: 22, 80, 445, 3389'
          }
        }
      }
    }
  ]
};
