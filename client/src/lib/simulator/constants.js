// client/src/lib/simulator/constants.js

export const COMMAND_HISTORY_KEY = 'ad-simulator-command-history';
export const MAX_COMMAND_HISTORY = 100;
export const SUBSHELL_TIMEOUT = 120000; // 2 minutes

/**
 * Calculate score based on performance
 */
export const calculateScenarioScore = (wrongAttempts, hintsUsed) => {
  if (wrongAttempts === 0 && hintsUsed === 0) {
    return 10;
  } else if (hintsUsed > 0 && hintsUsed <= 2) {
    return 5;
  } else if (wrongAttempts > 0) {
    return Math.max(0, 10 - (wrongAttempts * 2));
  }
  return 0;
};

/**
 * Get defense alert for specific step
 */
export const getDefenseAlertForStep = (stepId, scenarioId) => {
  const alerts = {
    'kerberoasting': {
      1: "[DEFENSE] ALERT: LDAP Query pattern detected (SPN enumeration).",
      4: "[DEFENSE] ALERT: Weak hash identified (Service account compromised)."
    },
    'pass-the-hash': {
      3: "[DEFENSE] ALERT: Unusual NTLM authentication without password detected (PtH)."
    },
    'dcsync': "[DEFENSE] ALERT: DCSync attack detected! Domain replication from unauthorized host!",
    'golden-ticket': "[DEFENSE] ALERT: krbtgt hash compromised! Golden Ticket attack possible!"
  };
  
  const alert = alerts[scenarioId];
  if (typeof alert === 'object') {
    return alert[stepId] || null;
  }
  return alert || null;
};

/**
 * Get sub-shell prompt
 */
export const getSubShellPrompt = (shell) => {
  const prompts = {
    'mimikatz': 'mimikatz # ',
    'powershell': 'PS> ',
    'cmd': 'C:\\> '
  };
  return prompts[shell] || '> ';
};

/**
 * Get expected commands array from step
 */
export const getExpectedCommands = (step) => {
  if (!step) return [];
  
  if (Array.isArray(step.expectedCommands) && step.expectedCommands.length > 0) {
    return step.expectedCommands;
  } else if (step.expectedCommand) {
    return [step.expectedCommand];
  }
  
  return [];
};

/**
 * Get initial history for each panel
 */
export const getInitialHistories = (scenario) => {
  return {
    attacker: [
      { type: 'system', text: `Welcome to ${scenario.network.attacker.hostname}` },
      { type: 'system', text: `IP: ${scenario.network.attacker.ip}` },
      { type: 'system', text: `Target: ${scenario.network.target.hostname} (${scenario.network.target.ip})` },
      { type: 'system', text: '' },
      { type: 'system', text: 'Type the commands from the guide to begin the attack simulation.' },
      { type: 'system', text: '' }
    ],
    server: [
      { type: 'info', text: `[SYSTEM] ${scenario.network.target.hostname} - Windows Server 2019` },
      { type: 'info', text: `[SYSTEM] Domain Controller for ${scenario.network.domain}` },
      { type: 'info', text: `[SYSTEM] IP Address: ${scenario.network.target.ip}` },
      { type: 'info', text: '[SYSTEM] All services running normally' },
      { type: 'info', text: '' }
    ],
    defense: [
      { type: 'info', text: `[DEFENSE] Blue Team Console Online. Monitoring Domain: ${scenario.network.domain}` },
      { type: 'info', text: "[DEFENSE] Active Policy: Strong Password Policy, NTLM Enabled (Legacy Support)" },
      { type: 'info', text: "" }
    ]
  };
};

/**
 * Get compromised nodes based on completed scenarios
 */
export const getCompromisedNodesMap = () => ({
  'pass-the-hash': ['target'],
  'dcsync': ['dc'],
  'golden-ticket': ['dc'],
  'gpo-abuse': ['dc'],
  'adcs-esc1': ['dc'],
  'trust-abuse': ['dc'],
  'credential-dumping-advanced': ['target', 'dc']
});
