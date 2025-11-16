// client/src/data/campaigns/index.js

export const campaigns = {
  'initial-foothold': {
    id: 'initial-foothold',
    title: 'Initial Compromise: From Zero to Domain User',
    description: 'Gain initial access to the Contoso domain through reconnaissance and credential attacks',
    difficulty: 'Beginner',
    estimatedTime: '45 minutes',
    xpReward: 500,
    badge: '🎯',
    
    story: {
      intro: `**Mission Briefing**\n\nYou've been hired to perform a penetration test on Contoso Corporation's Active Directory environment. Your objective: demonstrate the security posture by compromising domain credentials.\n\nIntelligence suggests:\n- Weak authentication controls\n- Legacy service accounts\n- Minimal security monitoring\n\nStarting from an external Kali Linux machine, find a way in.`,
      
      transitions: {
        'nmap-recon': {
          before: 'Begin with reconnaissance to map the network.',
          after: 'Excellent! Port 88 (Kerberos) and 389 (LDAP) confirm Active Directory is running.\n\nThe next step is to identify authentication weaknesses. Look for accounts with pre-authentication disabled.'
        },
        'asrep-roasting': {
          before: 'Check for accounts with Kerberos pre-authentication disabled - a common misconfiguration.',
          after: 'Success! You now have valid domain credentials for svc_backup.\n\nWith these credentials, you can enumerate the domain for service accounts and attempt Kerberoasting.'
        },
        'kerberoasting': {
          before: 'Use your compromised credentials to request service tickets and extract password hashes.',
          after: 'Outstanding! You\'ve compromised multiple service accounts including sqlservice.\n\nYou now have multiple entry points into the domain.'
        }
      },
      
      conclusion: `**Mission Complete!**\n\nYou successfully compromised Contoso Corporation's initial defenses:\n\n**Achievements:**\n- Mapped network topology\n- Exploited pre-authentication disabled accounts\n- Extracted and cracked service account passwords\n- Obtained multiple domain credentials\n\n**Impact:**\nWith these credentials, an attacker could:\n- Access sensitive file shares\n- Enumerate additional targets\n- Move laterally to other systems\n- Escalate privileges\n\n**Next Campaign:** Use these credentials for lateral movement and privilege escalation.`
    },
    
    scenarios: [
      {
        id: 'nmap-recon',
        required: true,
        description: 'Map the network and identify AD services'
      },
      {
        id: 'asrep-roasting',
        required: true,
        description: 'Exploit pre-authentication disabled accounts'
      },
      {
        id: 'kerberoasting',
        required: true,
        description: 'Extract and crack service account passwords'
      }
    ],
    
    prerequisites: [],
    
    rewards: {
      xp: 500,
      achievements: ['first-blood', 'domain-recon-master', 'credential-harvester'],
      unlocks: ['privilege-escalation-chain']
    }
  },
  
  'privilege-escalation-chain': {
    id: 'privilege-escalation-chain',
    title: 'Privilege Escalation: From User to Enterprise Admin',
    description: 'Escalate from domain user to Enterprise Admin through lateral movement and delegation attacks',
    difficulty: 'Intermediate',
    estimatedTime: '90 minutes',
    xpReward: 1000,
    badge: '⚡',
    
    story: {
      intro: `**Mission Briefing**\n\nWith domain user credentials in hand, it's time to escalate privileges.\n\nYour objectives:\n1. Map attack paths using BloodHound\n2. Move laterally to high-value targets\n3. Extract domain admin credentials\n4. Achieve Enterprise Admin access\n\n**Warning:** Blue team monitoring has increased. Stealth is essential.`,
      
      transitions: {
        'bloodhound': {
          before: 'Use BloodHound to map Active Directory relationships and find privilege escalation paths.',
          after: 'BloodHound reveals critical paths to Domain Admin.\n\nYou\'ve identified that sqlservice has GenericWrite permissions on a high-value account.'
        },
        'pass-the-hash': {
          before: 'Use compromised NTLM hashes to authenticate without knowing plaintext passwords.',
          after: 'Successful lateral movement! You now have access to additional systems.\n\nTime to extract Domain Controller credentials.'
        },
        'dcsync': {
          before: 'Use DCSync to extract the KRBTGT account hash from the Domain Controller.',
          after: 'Critical success! You\'ve extracted the KRBTGT hash.\n\nWith this, you can create Golden Tickets for persistent access.'
        },
        'golden-ticket': {
          before: 'Forge a Golden Ticket using the KRBTGT hash for persistent domain admin access.',
          after: 'Domain compromised! You have persistent Enterprise Admin access.\n\nThe entire Active Directory forest is now under your control.'
        }
      },
      
      conclusion: `**Mission Complete!**\n\nYou achieved complete domain dominance:\n\n**Attack Chain:**\n1. Mapped AD with BloodHound\n2. Lateral movement via Pass-the-Hash\n3. DCSync to extract KRBTGT\n4. Golden Ticket for persistence\n\n**Impact:**\nFull Enterprise Admin access means:\n- Access to ALL domain resources\n- Ability to create new domain admins\n- Persistent backdoor access\n- Complete forest compromise\n\n**Next Campaign:** Abuse trust relationships to compromise partner forests.`
    },
    
    scenarios: [
      {
        id: 'bloodhound',
        required: true,
        description: 'Map Active Directory attack paths'
      },
      {
        id: 'pass-the-hash',
        required: true,
        description: 'Lateral movement using NTLM hashes'
      },
      {
        id: 'dcsync',
        required: true,
        description: 'Extract KRBTGT hash via DCSync'
      },
      {
        id: 'golden-ticket',
        required: true,
        description: 'Create Golden Ticket for persistence'
      }
    ],
    
    prerequisites: ['initial-foothold'],
    
    rewards: {
      xp: 1000,
      achievements: ['privilege-escalation-master', 'lateral-movement-expert', 'golden-ticket-holder'],
      unlocks: ['forest-domination']
    }
  },
  
  'forest-domination': {
    id: 'forest-domination',
    title: 'Forest Domination: Cross-Domain Exploitation',
    description: 'Abuse trust relationships to compromise multiple forests and achieve complete enterprise control',
    difficulty: 'Advanced',
    estimatedTime: '120 minutes',
    xpReward: 1500,
    badge: '👑',
    
    story: {
      intro: `**Mission Briefing**\n\nContoso has trust relationships with partner forests. Your final objective: complete enterprise compromise.\n\nTargets:\n- Child domains\n- Trusted partner forests\n- Enterprise-wide persistence\n\n**Challenge Level:** Advanced\n**Detection Risk:** Critical`,
      
      transitions: {
        'gpo-abuse': {
          before: 'Abuse Group Policy Objects to establish persistence and deploy backdoors.',
          after: 'GPO backdoor deployed. Every computer that applies this policy will execute your code.'
        },
        'adcs-esc1': {
          before: 'Exploit AD Certificate Services misconfiguration to obtain certificates for privileged accounts.',
          after: 'Certificate obtained for Enterprise Admin! This provides authentication without knowing passwords.'
        },
        'rbcd-attack': {
          before: 'Abuse Resource-Based Constrained Delegation to impersonate privileged accounts.',
          after: 'Delegation abuse successful! You can now impersonate any user to any service.'
        },
        'trust-abuse': {
          before: 'Exploit trust relationships to pivot into partner forests.',
          after: 'Forest trust compromised! You now control multiple Active Directory forests.'
        }
      },
      
      conclusion: `**MISSION COMPLETE - ENTERPRISE COMPROMISED**\n\nYou achieved complete enterprise domination:\n\n**Full Attack Chain:**\n- Initial reconnaissance and credential theft\n- Privilege escalation to Domain Admin\n- Persistent backdoors via GPO\n- Certificate-based authentication\n- Cross-forest trust exploitation\n\n**Final Impact:**\n🚨 CRITICAL: Complete compromise of:\n- Primary Contoso forest\n- All child domains\n- Partner forest environments\n- Enterprise-wide persistence\n\n**Recommendations for Blue Team:**\nThis assessment revealed critical security gaps requiring immediate remediation.\n\n**Congratulations, Elite Hacker!**`
    },
    
    scenarios: [
      {
        id: 'gpo-abuse',
        required: true,
        description: 'Deploy backdoors via Group Policy'
      },
      {
        id: 'adcs-esc1',
        required: true,
        description: 'Exploit certificate services for auth'
      },
      {
        id: 'rbcd-attack',
        required: false,
        description: 'Resource-Based Constrained Delegation'
      },
      {
        id: 'trust-abuse',
        required: true,
        description: 'Compromise partner forests via trusts'
      }
    ],
    
    prerequisites: ['privilege-escalation-chain'],
    
    rewards: {
      xp: 1500,
      achievements: ['forest-master', 'enterprise-pwned', 'elite-hacker'],
      unlocks: []
    }
  }
};

export const getCampaignById = (campaignId) => {
  return campaigns[campaignId] || null;
};

export const getAvailableCampaigns = (progress) => {
  return Object.values(campaigns).filter(campaign => {
    if (campaign.prerequisites.length === 0) return true;
    
    return campaign.prerequisites.every(prereqId =>
      progress.completedCampaigns?.includes(prereqId)
    );
  });
};

export const isCampaignUnlocked = (campaignId, progress) => {
  const campaign = campaigns[campaignId];
  if (!campaign) return false;
  
  if (campaign.prerequisites.length === 0) return true;
  
  return campaign.prerequisites.every(prereqId =>
    progress.completedCampaigns?.includes(prereqId)
  );
};
