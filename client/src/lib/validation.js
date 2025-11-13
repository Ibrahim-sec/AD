/**
 * Validation utilities for scenarios and data structures
 */

/**
 * Validate scenario structure
 * @param {Object} scenario - Scenario to validate
 * @returns {Object} { isValid: boolean, errors: Array<string> }
 */
export function validateScenario(scenario) {
  const errors = [];

  if (!scenario) {
    errors.push('Scenario is null or undefined');
    return { isValid: false, errors };
  }

  // Check required fields
  if (!scenario.name || typeof scenario.name !== 'string' || scenario.name.trim() === '') {
    errors.push('Scenario name is required and must be a non-empty string');
  }

  if (!scenario.mission || typeof scenario.mission !== 'object') {
    errors.push('Scenario must have a mission object');
  } else {
    if (!scenario.mission.target || typeof scenario.mission.target !== 'string') {
      errors.push('Mission target is required');
    }
    if (!scenario.mission.objective || typeof scenario.mission.objective !== 'string') {
      errors.push('Mission objective is required');
    }
  }

  // Check steps
  if (!Array.isArray(scenario.steps) || scenario.steps.length === 0) {
    errors.push('Scenario must have at least one step');
  } else {
    scenario.steps.forEach((step, index) => {
      const stepErrors = validateStep(step, index);
      errors.push(...stepErrors);
    });
  }

  // Check machines if present
  if (scenario.machines && typeof scenario.machines === 'object') {
    const machineErrors = validateMachines(scenario.machines);
    errors.push(...machineErrors);
  }

  return {
    isValid: errors.length === 0,
    errors,
  };
}

/**
 * Validate a single step
 * @param {Object} step - Step to validate
 * @param {number} index - Step index (for error messages)
 * @returns {Array<string>} Array of error messages
 */
export function validateStep(step, index = 0) {
  const errors = [];
  const stepNum = index + 1;

  if (!step || typeof step !== 'object') {
    errors.push(`Step ${stepNum} is invalid (must be an object)`);
    return errors;
  }

  if (!step.description || typeof step.description !== 'string' || step.description.trim() === '') {
    errors.push(`Step ${stepNum}: description is required`);
  }

  if (!step.expectedCommand || typeof step.expectedCommand !== 'string' || step.expectedCommand.trim() === '') {
    errors.push(`Step ${stepNum}: expectedCommand is required`);
  }

  if (!step.attackerOutput || typeof step.attackerOutput !== 'string') {
    errors.push(`Step ${stepNum}: attackerOutput is required`);
  }

  if (!step.serverOutput || typeof step.serverOutput !== 'string') {
    errors.push(`Step ${stepNum}: serverOutput is required`);
  }

  // Optional fields validation
  if (step.hintShort && typeof step.hintShort !== 'string') {
    errors.push(`Step ${stepNum}: hintShort must be a string`);
  }

  if (step.hintFull && typeof step.hintFull !== 'string') {
    errors.push(`Step ${stepNum}: hintFull must be a string`);
  }

  return errors;
}

/**
 * Validate machines configuration
 * @param {Object} machines - Machines object
 * @returns {Array<string>} Array of error messages
 */
export function validateMachines(machines) {
  const errors = [];

  if (!machines.attacker || typeof machines.attacker !== 'object') {
    errors.push('Attacker machine configuration is invalid');
  }

  if (!machines.target || typeof machines.target !== 'object') {
    errors.push('Target machine configuration is invalid');
  }

  return errors;
}

/**
 * Safe JSON parse with error handling
 * @param {string} jsonString - JSON string to parse
 * @returns {Object} { success: boolean, data: any, error: string }
 */
export function safeJsonParse(jsonString) {
  try {
    const data = JSON.parse(jsonString);
    return { success: true, data, error: null };
  } catch (error) {
    return {
      success: false,
      data: null,
      error: `Invalid JSON: ${error.message}`,
    };
  }
}

/**
 * Validate and parse scenario JSON
 * @param {string} jsonString - JSON string containing scenario
 * @returns {Object} { success: boolean, scenario: Object, errors: Array<string> }
 */
export function validateScenarioJson(jsonString) {
  const parseResult = safeJsonParse(jsonString);

  if (!parseResult.success) {
    return {
      success: false,
      scenario: null,
      errors: [parseResult.error],
    };
  }

  const validationResult = validateScenario(parseResult.data);

  return {
    success: validationResult.isValid,
    scenario: validationResult.isValid ? parseResult.data : null,
    errors: validationResult.errors,
  };
}

/**
 * Create a minimal valid scenario with defaults
 * @param {Object} overrides - Fields to override defaults
 * @returns {Object} Valid scenario object
 */
export function createDefaultScenario(overrides = {}) {
  return {
    id: `scenario-${Date.now()}`,
    name: 'Untitled Scenario',
    description: 'A custom attack scenario',
    difficulty: 'intermediate',
    mission: {
      target: 'contoso.local',
      objective: 'Demonstrate an attack technique',
      attackFlow: ['Step 1', 'Step 2', 'Step 3'],
      recommendedTools: ['tool1', 'tool2'],
    },
    machines: {
      attacker: {
        name: 'Attacker',
        ip: '10.0.0.5',
        os: 'Kali Linux',
      },
      target: {
        name: 'Internal Server',
        ip: '10.0.1.10',
        os: 'Windows Server 2019',
      },
      dc: {
        name: 'Domain Controller',
        ip: '10.0.1.10',
        os: 'Windows Server 2019',
      },
    },
    steps: [
      {
        description: 'Initial reconnaissance',
        expectedCommand: 'example-command',
        attackerOutput: 'Output from attacker perspective',
        serverOutput: 'Output from server perspective',
        hintShort: 'Try using the example command',
        hintFull: 'This is the full hint with more details',
      },
    ],
    ...overrides,
  };
}
