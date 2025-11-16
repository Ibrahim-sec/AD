// client/src/lib/scenarioManager.js

import { scenarioMap } from '@/data/scenarios/index.js';

/**
 * Scenario relationship definitions
 */
export const scenarioRelationships = {
  'kerberoasting': {
    hardPrerequisites: ['asrep-roasting'],
    softPrerequisites: ['nmap-recon'],
    requiredLoot: {
      credentials: ['svc_backup']
    },
    unlocks: ['pass-the-hash', 'dcsync']
  },
  
  'pass-the-hash': {
    hardPrerequisites: ['kerberoasting'],
    requiredLoot: {
      credentials: ['sqlservice']
    },
    unlocks: ['dcsync']
  },
  
  'dcsync': {
    hardPrerequisites: ['pass-the-hash'],
    softPrerequisites: ['bloodhound'],
    unlocks: ['golden-ticket']
  },
  
  'golden-ticket': {
    hardPrerequisites: ['dcsync'],
    requiredLoot: {
      credentials: ['krbtgt']
    },
    unlocks: ['trust-abuse']
  },
  
  'gpo-abuse': {
    softPrerequisites: ['bloodhound'],
    unlocks: []
  },
  
  'adcs-esc1': {
    softPrerequisites: ['bloodhound'],
    unlocks: []
  },
  
  'rbcd-attack': {
    softPrerequisites: ['bloodhound', 'kerberoasting'],
    unlocks: []
  },
  
  'trust-abuse': {
    hardPrerequisites: ['golden-ticket'],
    unlocks: []
  }
};

/**
 * Check if scenario is unlocked
 */
export const isScenarioUnlocked = (scenarioId, progress) => {
  const relations = scenarioRelationships[scenarioId];
  
  // No prerequisites = always unlocked
  if (!relations || !relations.hardPrerequisites || relations.hardPrerequisites.length === 0) {
    return { unlocked: true };
  }
  
  // Check hard prerequisites
  const hardPrereqsMet = relations.hardPrerequisites.every(prereqId =>
    progress.scenariosCompleted.includes(prereqId)
  );
  
  if (!hardPrereqsMet) {
    return {
      unlocked: false,
      reason: 'prerequisite',
      missing: relations.hardPrerequisites.filter(id =>
        !progress.scenariosCompleted.includes(id)
      )
    };
  }
  
  // Check required loot
  if (relations.requiredLoot?.credentials) {
    const hasAllCreds = relations.requiredLoot.credentials.every(username =>
      progress.globalInventory?.credentials?.some(cred =>
        cred.username.toLowerCase() === username.toLowerCase()
      )
    );
    
    if (!hasAllCreds) {
      return {
        unlocked: false,
        reason: 'missing-loot',
        missing: relations.requiredLoot.credentials,
        missingType: 'credentials'
      };
    }
  }
  
  return { unlocked: true };
};

/**
 * Get unlockable scenarios after completing a scenario
 */
export const getUnlockableScenarios = (progress, completedScenarioId) => {
  const relations = scenarioRelationships[completedScenarioId];
  
  if (!relations || !relations.unlocks) return [];
  
  // Filter scenarios that are now unlocked
  return relations.unlocks.filter(scenarioId => {
    const status = isScenarioUnlocked(scenarioId, progress);
    return status.unlocked && !progress.scenariosCompleted.includes(scenarioId);
  }).map(id => scenarioMap[id]).filter(Boolean);
};

/**
 * Get scenarios that recommend this one as prerequisite
 */
export const getRecommendedFor = (scenarioId, progress) => {
  const recommended = [];
  
  Object.entries(scenarioRelationships).forEach(([id, relations]) => {
    if (relations.softPrerequisites?.includes(scenarioId)) {
      const status = isScenarioUnlocked(id, progress);
      if (status.unlocked && !progress.scenariosCompleted.includes(id)) {
        recommended.push(scenarioMap[id]);
      }
    }
  });
  
  return recommended.filter(Boolean);
};

/**
 * Get source scenario for required credential
 */
export const getCredentialSourceScenario = (username, progress) => {
  const cred = progress.globalInventory?.credentials?.find(
    c => c.username.toLowerCase() === username.toLowerCase()
  );
  
  return cred?.sourceScenario || null;
};
