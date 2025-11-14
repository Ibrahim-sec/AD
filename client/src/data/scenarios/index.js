// Central scenario registry
//
// This file imports each defined attack scenario and then exports them
// in a list and an ID-based map. When adding new scenarios, import the
// scenario module here and add it to both the `scenarios` array and the
// `scenarioMap` object. The keys in scenarioMap should match each
// scenario's `id` property.

import bloodhoundScenario from './bloodhound.js';
import kerberoastScenario from './kerberoast.js';
import asrepScenario from './asrep.js';
import pthScenario from './pth.js';
import dcsyncScenario from './dcsync.js';

// Array of all scenarios in the order they should appear in the UI
export const scenarios = [
  bloodhoundScenario,
  kerberoastScenario,
  asrepScenario,
  pthScenario,
  dcsyncScenario
];

// Map scenario IDs to scenario objects for quick lookup
export const scenarioMap = {
  bloodhound: bloodhoundScenario,
  kerberoasting: kerberoastScenario,
  'asrep-roasting': asrepScenario,
  'pass-the-hash': pthScenario,
  dcsync: dcsyncScenario
};

export default scenarios;