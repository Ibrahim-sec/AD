/**
 * Scenarios Index
 * 
 * Central export point for all attack scenarios
 */

import bloodhoundScenario from './bloodhound.js';
import kerberoastScenario from './kerberoast.js';
import asrepScenario from './asrep.js';
import pthScenario from './pth.js';

export const scenarios = [
  bloodhoundScenario,
  kerberoastScenario,
  asrepScenario,
  pthScenario
];

export const scenarioMap = {
  'bloodhound': bloodhoundScenario,
  'kerberoasting': kerberoastScenario,
  'asrep-roasting': asrepScenario,
  'pass-the-hash': pthScenario
};

export default scenarios;
