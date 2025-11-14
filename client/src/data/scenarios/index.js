// Central scenario registry
//
// This file imports each defined attack scenario and then exports them
// in a list and an ID-based map. When adding new scenarios, import the
// scenario module here and add it to both the `scenarios` array and the
// `scenarioMap` object. The keys in scenarioMap should match each
// scenario's `id` property.

// ============================================================================
// EXISTING SCENARIOS (12)
// ============================================================================

// Mission 0 - Initial Reconnaissance
import nmapScenario from './nmap.js';

// Mission 1 - Initial Access
import asrepScenario from './asrep.js';
import passwordSprayScenario from './passwordspray.js';
import llmnrScenario from './llmnr.js';
import bruteforceScenario from './bruteforce.js';
import ntlmRelayScenario from './ntlmrelay.js';

// Mission 2 - Credential Access
import gppScenario from './gpp.js';
import kerberoastScenario from './kerberoast.js';

// Mission 3 - Discovery & Collection
import bloodhoundScenario from './bloodhound.js';

// Mission 4 - Lateral Movement
import pthScenario from './pth.js';

// Mission 5 - Domain Dominance
import dcsyncScenario from './dcsync.js';
import goldenTicketScenario from './goldenticket.js';

// ============================================================================
// NEW ADVANCED SCENARIOS (5)
// ============================================================================

// Advanced Attacks - Privilege Escalation & Persistence
import gpoAbuseScenario from './gpoabuse.js';
import adcsEsc1Scenario from './adcs-esc1.js';
import rbcdScenario from './rbcd.js';
import trustAbuseScenario from './trust-abuse.js';
import credentialDumpingScenario from './credential-dumping.js';

// ============================================================================
// SCENARIO ARRAY - Order determines display in UI
// ============================================================================

/**
 * Array of all scenarios in the order they should appear in the UI.
 * Organized by attack phase following the Cyber Kill Chain:
 * 
 * 1. Reconnaissance
 * 2. Initial Access
 * 3. Credential Access
 * 4. Discovery
 * 5. Lateral Movement
 * 6. Privilege Escalation
 * 7. Domain Dominance
 * 8. Advanced Techniques
 */
export const scenarios = [
  // ========== PHASE 1: RECONNAISSANCE ==========
  nmapScenario,                    // Network scanning and service enumeration

  // ========== PHASE 2: INITIAL ACCESS ==========
  asrepScenario,                   // AS-REP Roasting attack
  passwordSprayScenario,           // Password spraying attack
  llmnrScenario,                   // LLMNR/NBT-NS poisoning
  bruteforceScenario,              // SMB brute force attack
  ntlmRelayScenario,              // NTLM relay attack

  // ========== PHASE 3: CREDENTIAL ACCESS ==========
  gppScenario,                     // Group Policy Preferences password extraction
  kerberoastScenario,             // Kerberoasting attack
  credentialDumpingScenario,      // Advanced credential harvesting techniques (NEW)

  // ========== PHASE 4: DISCOVERY ==========
  bloodhoundScenario,             // BloodHound AD enumeration

  // ========== PHASE 5: LATERAL MOVEMENT ==========
  pthScenario,                    // Pass-the-Hash attack

  // ========== PHASE 6: PRIVILEGE ESCALATION ==========
  gpoAbuseScenario,               // Group Policy Object abuse (NEW)
  adcsEsc1Scenario,               // AD Certificate Services ESC1 exploitation (NEW)
  rbcdScenario,                   // Resource-Based Constrained Delegation (NEW)

  // ========== PHASE 7: DOMAIN DOMINANCE ==========
  dcsyncScenario,                 // DCSync attack
  goldenTicketScenario,           // Golden Ticket attack
  trustAbuseScenario,             // Forest/Domain trust exploitation (NEW)
];

// ============================================================================
// SCENARIO MAP - Quick lookup by ID
// ============================================================================

/**
 * Map scenario IDs to scenario objects for quick lookup.
 * Used throughout the application for scenario selection and routing.
 */
export const scenarioMap = {
  // Reconnaissance
  'nmap-recon': nmapScenario,

  // Initial Access
  'asrep-roasting': asrepScenario,
  'password-spraying': passwordSprayScenario,
  'llmnr-poisoning': llmnrScenario,
  'bruteforce-lockout': bruteforceScenario,
  'ntlm-relay': ntlmRelayScenario,

  // Credential Access
  'gpp-passwords': gppScenario,
  'kerberoasting': kerberoastScenario,
  'credential-dumping-advanced': credentialDumpingScenario, // NEW

  // Discovery
  'bloodhound': bloodhoundScenario,

  // Lateral Movement
  'pass-the-hash': pthScenario,

  // Privilege Escalation
  'gpo-abuse': gpoAbuseScenario,                // NEW
  'adcs-esc1': adcsEsc1Scenario,                // NEW
  'rbcd-attack': rbcdScenario,                  // NEW

  // Domain Dominance
  'dcsync': dcsyncScenario,
  'golden-ticket': goldenTicketScenario,
  'trust-abuse': trustAbuseScenario,            // NEW
};

// ============================================================================
// SCENARIO METADATA - For filtering and categorization
// ============================================================================

/**
 * Categorize scenarios by attack phase for easier filtering and navigation
 */
export const scenariosByPhase = {
  reconnaissance: [
    nmapScenario
  ],
  initialAccess: [
    asrepScenario,
    passwordSprayScenario,
    llmnrScenario,
    bruteforceScenario,
    ntlmRelayScenario
  ],
  credentialAccess: [
    gppScenario,
    kerberoastScenario,
    credentialDumpingScenario
  ],
  discovery: [
    bloodhoundScenario
  ],
  lateralMovement: [
    pthScenario
  ],
  privilegeEscalation: [
    gpoAbuseScenario,
    adcsEsc1Scenario,
    rbcdScenario
  ],
  domainDominance: [
    dcsyncScenario,
    goldenTicketScenario,
    trustAbuseScenario
  ]
};

/**
 * Categorize scenarios by difficulty level
 */
export const scenariosByDifficulty = {
  beginner: [
    nmapScenario,
    passwordSprayScenario,
    llmnrScenario,
    bruteforceScenario,
    gppScenario
  ],
  intermediate: [
    asrepScenario,
    ntlmRelayScenario,
    kerberoastScenario,
    bloodhoundScenario,
    pthScenario,
    dcsyncScenario
  ],
  advanced: [
    goldenTicketScenario,
    gpoAbuseScenario,
    adcsEsc1Scenario,
    rbcdScenario,
    credentialDumpingScenario
  ],
  expert: [
    trustAbuseScenario
  ]
};

/**
 * Map MITRE ATT&CK techniques to scenarios
 */
export const scenariosByMitreAttack = {
  'T1595': [nmapScenario],                          // Active Scanning
  'T1558.004': [asrepScenario],                     // AS-REP Roasting
  'T1110.003': [passwordSprayScenario],             // Password Spraying
  'T1557.001': [llmnrScenario],                     // LLMNR/NBT-NS Poisoning
  'T1110.001': [bruteforceScenario],                // Password Guessing
  'T1557.001': [ntlmRelayScenario],                 // Man-in-the-Middle
  'T1552.006': [gppScenario],                       // Group Policy Preferences
  'T1558.003': [kerberoastScenario, rbcdScenario],  // Kerberoasting, Delegation
  'T1003': [credentialDumpingScenario],             // Credential Dumping
  'T1087': [bloodhoundScenario],                    // Account Discovery
  'T1550.002': [pthScenario],                       // Pass the Hash
  'T1484.001': [gpoAbuseScenario],                  // Group Policy Modification
  'T1649': [adcsEsc1Scenario],                      // Steal or Forge Authentication Certificates
  'T1558.002': [goldenTicketScenario],              // Golden Ticket
  'T1003.006': [dcsyncScenario],                    // DCSync
  'T1482': [trustAbuseScenario],                    // Domain Trust Discovery
};

/**
 * Scenario learning paths - Recommended progression for learners
 */
export const learningPaths = {
  beginner: {
    name: 'Red Team Foundations',
    description: 'Start your Active Directory hacking journey',
    scenarios: [
      'nmap-recon',
      'password-spraying',
      'llmnr-poisoning',
      'gpp-passwords',
      'pass-the-hash'
    ]
  },
  intermediate: {
    name: 'Advanced AD Exploitation',
    description: 'Master intermediate Active Directory attacks',
    scenarios: [
      'asrep-roasting',
      'kerberoasting',
      'ntlm-relay',
      'bloodhound',
      'dcsync'
    ]
  },
  advanced: {
    name: 'Elite Red Teaming',
    description: 'Advanced persistence and privilege escalation',
    scenarios: [
      'credential-dumping-advanced',
      'gpo-abuse',
      'adcs-esc1',
      'rbcd-attack',
      'golden-ticket'
    ]
  },
  expert: {
    name: 'Forest Domination',
    description: 'Complete enterprise compromise techniques',
    scenarios: [
      'trust-abuse',
      'golden-ticket',
      'dcsync'
    ]
  },
  oscp: {
    name: 'OSCP Preparation',
    description: 'Scenarios aligned with OSCP certification',
    scenarios: [
      'nmap-recon',
      'password-spraying',
      'kerberoasting',
      'pass-the-hash',
      'credential-dumping-advanced'
    ]
  },
  crto: {
    name: 'CRTO/CRTE Preparation',
    description: 'Advanced Red Team Ops certification prep',
    scenarios: [
      'bloodhound',
      'kerberoasting',
      'dcsync',
      'golden-ticket',
      'gpo-abuse',
      'adcs-esc1',
      'rbcd-attack',
      'trust-abuse'
    ]
  }
};

/**
 * Scenario statistics and metadata
 */
export const scenarioStats = {
  total: scenarios.length,
  byDifficulty: {
    beginner: scenariosByDifficulty.beginner.length,
    intermediate: scenariosByDifficulty.intermediate.length,
    advanced: scenariosByDifficulty.advanced.length,
    expert: scenariosByDifficulty.expert.length
  },
  byPhase: {
    reconnaissance: scenariosByPhase.reconnaissance.length,
    initialAccess: scenariosByPhase.initialAccess.length,
    credentialAccess: scenariosByPhase.credentialAccess.length,
    discovery: scenariosByPhase.discovery.length,
    lateralMovement: scenariosByPhase.lateralMovement.length,
    privilegeEscalation: scenariosByPhase.privilegeEscalation.length,
    domainDominance: scenariosByPhase.domainDominance.length
  },
  newScenarios: [
    'gpo-abuse',
    'adcs-esc1',
    'rbcd-attack',
    'trust-abuse',
    'credential-dumping-advanced'
  ]
};

/**
 * Helper function to get scenario by ID
 */
export function getScenarioById(id) {
  return scenarioMap[id] || null;
}

/**
 * Helper function to get scenarios by difficulty
 */
export function getScenariosByDifficulty(difficulty) {
  return scenariosByDifficulty[difficulty] || [];
}

/**
 * Helper function to get scenarios by phase
 */
export function getScenariosByPhase(phase) {
  return scenariosByPhase[phase] || [];
}

/**
 * Helper function to get learning path scenarios
 */
export function getLearningPath(pathName) {
  const path = learningPaths[pathName];
  if (!path) return null;
  
  return {
    ...path,
    scenarios: path.scenarios.map(id => scenarioMap[id]).filter(Boolean)
  };
}

/**
 * Helper function to get next recommended scenario based on completed ones
 */
export function getNextRecommendedScenario(completedScenarioIds = []) {
  // Find the first incomplete scenario in order
  for (const scenario of scenarios) {
    if (!completedScenarioIds.includes(scenario.id)) {
      return scenario;
    }
  }
  
  // All completed - recommend a random advanced one
  const advanced = scenariosByDifficulty.advanced.concat(scenariosByDifficulty.expert);
  return advanced[Math.floor(Math.random() * advanced.length)];
}

/**
 * Helper function to get scenario prerequisites
 */
export function getScenarioPrerequisites(scenarioId) {
  const prerequisites = {
    'kerberoasting': ['nmap-recon', 'asrep-roasting'],
    'pass-the-hash': ['kerberoasting', 'credential-dumping-advanced'],
    'dcsync': ['pass-the-hash'],
    'golden-ticket': ['dcsync'],
    'gpo-abuse': ['bloodhound'],
    'adcs-esc1': ['bloodhound'],
    'rbcd-attack': ['bloodhound', 'kerberoasting'],
    'trust-abuse': ['golden-ticket', 'dcsync']
  };
  
  return (prerequisites[scenarioId] || []).map(id => scenarioMap[id]).filter(Boolean);
}

/**
 * Helper function to check if scenario is unlocked based on progress
 */
export function isScenarioUnlocked(scenarioId, completedScenarioIds = []) {
  const prerequisites = getScenarioPrerequisites(scenarioId);
  
  // No prerequisites - always unlocked
  if (prerequisites.length === 0) return true;
  
  // Check if all prerequisites are completed
  return prerequisites.every(prereq => completedScenarioIds.includes(prereq.id));
}

/**
 * Helper function to get scenario completion percentage
 */
export function getCompletionPercentage(completedScenarioIds = []) {
  return Math.round((completedScenarioIds.length / scenarios.length) * 100);
}

// Default export
export default scenarios;
