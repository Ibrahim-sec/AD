// client/src/data/theory/index.js

import { kerberoastingTheory } from './kerberoasting';
import { asrepRoastingTheory } from './asrepRoasting';
import { dcsyncTheory } from './dcsync';
import { passTheHashTheory } from './passTheHash';
import { bloodhoundTheory } from './bloodhound';
import { goldenTicketTheory } from './goldenTicket';
import { ntlmRelayTheory } from './ntlmRelay';
import { gppPasswordsTheory } from './gppPasswords';
import { zerologonTheory } from './zerologon';
import { printNightmareTheory } from './printNightmare';
import { skeletonKeyTheory } from './skeletonKey';

export const theoryModules = {
  'kerberoasting': kerberoastingTheory,
  'asrep-roasting': asrepRoastingTheory,
  'dcsync': dcsyncTheory,
  'pass-the-hash': passTheHashTheory,
  'bloodhound': bloodhoundTheory,
  'golden-ticket': goldenTicketTheory,
  'ntlm-relay': ntlmRelayTheory,
  'gpp-passwords': gppPasswordsTheory,
  'zerologon': zerologonTheory,
  'printnightmare': printNightmareTheory,
  'skeleton-key': skeletonKeyTheory
};


/**
 * Get theory module by scenario ID
 */
export const getTheoryModule = (scenarioId) => {
  return theoryModules[scenarioId] || null;
};

/**
 * Check if scenario has theory module
 */
export const hasTheoryModule = (scenarioId) => {
  return scenarioId in theoryModules;
};

/**
 * Get all theory modules
 */
export const getAllTheoryModules = () => {
  return Object.values(theoryModules);
};

/**
 * Get theory modules by difficulty
 */
export const getTheoryModulesByDifficulty = (difficulty) => {
  return Object.values(theoryModules).filter(module => module.difficulty === difficulty);
};
