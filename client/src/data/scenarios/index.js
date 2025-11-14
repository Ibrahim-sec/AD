// In client/src/data/scenarios/index.js

import nmapScenario from './nmap.js'; // <-- ADD THIS IMPORT
import bloodhoundScenario from './bloodhound.js';
import kerberoastScenario from './kerberoast.js';
import asrepScenario from './asrep.js';
import pthScenario from './pth.js';
import dcsyncScenario from './dcsync.js';

// Array of all scenarios in the order they should appear in the UI
export const scenarios = [
  nmapScenario, // <-- ADD THIS
  asrepScenario,
  kerberoastScenario,
  bloodhoundScenario,
  pthScenario,
  dcsyncScenario
];

// Map scenario IDs to scenario objects for quick lookup
export const scenarioMap = {
  'nmap-recon': nmapScenario, // <-- ADD THIS
  'asrep-roasting': asrepScenario,
  'kerberoasting': kerberoastScenario,
  'bloodhound': bloodhoundScenario,
  'pass-the-hash': pthScenario,
  'dcsync': dcsyncScenario
};

export default scenarios;