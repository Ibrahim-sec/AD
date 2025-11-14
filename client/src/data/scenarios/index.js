// Central scenario registry
//
// This file imports each defined attack scenario and then exports them
// in a list and an ID-based map. When adding new scenarios, import the
// scenario module here and add it to both the `scenarios` array and the
// `scenarioMap` object. The keys in scenarioMap should match each
// scenario's `id` property.

import nmapScenario from './nmap.js'; // Mission 0
import passwordSprayScenario from './passwordspray.js'; // <-- ADD THIS IMPORT
import asrepScenario from './asrep.js'; // Mission 1A
import kerberoastScenario from './kerberoast.js'; // Mission 2
import bloodhoundScenario from './bloodhound.js'; // Mission 3
import pthScenario from './pth.js'; // Mission 4
import dcsyncScenario from './dcsync.js'; // Mission 5

// Array of all scenarios in the order they should appear in the UI
export const scenarios = [
  nmapScenario,
  asrepScenario,
  passwordSprayScenario, // <-- ADD THIS
  kerberoastScenario,
  bloodhoundScenario,
  pthScenario,
  dcsyncScenario
];

// Map scenario IDs to scenario objects for quick lookup
export const scenarioMap = {
  'nmap-recon': nmapScenario,
  'asrep-roasting': asrepScenario,
  'password-spraying': passwordSprayScenario, // <-- ADD THIS
  'kerberoasting': kerberoastScenario,
  'bloodhound': bloodhoundScenario,
  'pass-the-hash': pthScenario,
  'dcsync': dcsyncScenario
};

export default scenarios;