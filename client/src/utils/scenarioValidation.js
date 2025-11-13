/**
 * Scenario Validation Utilities
 * 
 * Validates scenario JSON structure and provides detailed error messages
 */

/**
 * Validate a complete scenario object
 * @param {Object} scenario - The scenario to validate
 * @returns {Object} { valid: boolean, errors: Array<string> }
 */
export function validateScenarioStructure(scenario) {
  const errors = [];

  // Check if scenario is an object
  if (!scenario || typeof scenario !== 'object') {
    return { valid: false, errors: ['Scenario must be a valid object'] };
  }

  // Validate required top-level fields
  const requiredFields = ['id', 'name', 'difficulty', 'machines', 'mission', 'steps'];
  for (const field of requiredFields) {
    if (!scenario[field]) {
      errors.push(`Missing required field: ${field}`);
    }
  }

  // Validate ID format
  if (scenario.id && typeof scenario.id !== 'string') {
    errors.push('ID must be a string');
  }

  // Validate name
  if (scenario.name && typeof scenario.name !== 'string') {
    errors.push('Name must be a string');
  }

  // Validate difficulty
  if (scenario.difficulty && !['Beginner', 'Intermediate', 'Advanced'].includes(scenario.difficulty)) {
    errors.push('Difficulty must be one of: Beginner, Intermediate, Advanced');
  }

  // Validate machines object
  if (scenario.machines) {
    if (typeof scenario.machines !== 'object') {
      errors.push('Machines must be an object');
    } else {
      const machineErrors = validateMachines(scenario.machines);
      errors.push(...machineErrors);
    }
  }

  // Validate mission object
  if (scenario.mission) {
    if (typeof scenario.mission !== 'object') {
      errors.push('Mission must be an object');
    } else {
      const missionErrors = validateMission(scenario.mission);
      errors.push(...missionErrors);
    }
  }

  // Validate steps array
  if (scenario.steps) {
    if (!Array.isArray(scenario.steps)) {
      errors.push('Steps must be an array');
    } else if (scenario.steps.length === 0) {
      errors.push('Scenario must have at least one step');
    } else {
      for (let i = 0; i < scenario.steps.length; i++) {
        const stepErrors = validateStep(scenario.steps[i], i);
        errors.push(...stepErrors);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Validate machines configuration
 * @param {Object} machines - The machines object
 * @returns {Array<string>} Array of error messages
 */
function validateMachines(machines) {
  const errors = [];

  // Check required machines
  const requiredMachines = ['attacker', 'internal', 'dc'];
  for (const machine of requiredMachines) {
    if (!machines[machine]) {
      errors.push(`Missing required machine: ${machine}`);
    } else if (typeof machines[machine] !== 'object') {
      errors.push(`Machine '${machine}' must be an object`);
    } else {
      // Validate machine properties
      if (!machines[machine].name) {
        errors.push(`Machine '${machine}' missing name field`);
      }
      if (!machines[machine].ip) {
        errors.push(`Machine '${machine}' missing ip field`);
      }
    }
  }

  return errors;
}

/**
 * Validate mission configuration
 * @param {Object} mission - The mission object
 * @returns {Array<string>} Array of error messages
 */
function validateMission(mission) {
  const errors = [];

  if (!mission.target) {
    errors.push('Mission missing target field');
  }

  if (!mission.objective) {
    errors.push('Mission missing objective field');
  }

  return errors;
}

/**
 * Validate a single step
 * @param {Object} step - The step to validate
 * @param {number} index - The step index (for error messages)
 * @returns {Array<string>} Array of error messages
 */
export function validateStep(step, index = 0) {
  const errors = [];
  const stepNum = index + 1;

  if (!step || typeof step !== 'object') {
    errors.push(`Step ${stepNum} must be a valid object`);
    return errors;
  }

  // Required fields for a step
  const requiredFields = ['description', 'expectedCommand', 'attackerOutput'];
  for (const field of requiredFields) {
    if (!step[field]) {
      errors.push(`Step ${stepNum} missing required field: ${field}`);
    }
  }

  // Validate field types
  if (step.description && typeof step.description !== 'string') {
    errors.push(`Step ${stepNum} description must be a string`);
  }

  if (step.expectedCommand && typeof step.expectedCommand !== 'string') {
    errors.push(`Step ${stepNum} expectedCommand must be a string`);
  }

  if (step.attackerOutput && typeof step.attackerOutput !== 'string') {
    errors.push(`Step ${stepNum} attackerOutput must be a string`);
  }

  if (step.internalOutput && typeof step.internalOutput !== 'string') {
    errors.push(`Step ${stepNum} internalOutput must be a string`);
  }

  if (step.dcOutput && typeof step.dcOutput !== 'string') {
    errors.push(`Step ${stepNum} dcOutput must be a string`);
  }

  // Validate hints
  if (step.hintShort && typeof step.hintShort !== 'string') {
    errors.push(`Step ${stepNum} hintShort must be a string`);
  }

  if (step.hintFull && typeof step.hintFull !== 'string') {
    errors.push(`Step ${stepNum} hintFull must be a string`);
  }

  // Validate score value
  if (step.scoreValue !== undefined && typeof step.scoreValue !== 'number') {
    errors.push(`Step ${stepNum} scoreValue must be a number`);
  }

  return errors;
}

/**
 * Validate JSON string and parse it
 * @param {string} jsonString - The JSON string to validate
 * @returns {Object} { valid: boolean, data: Object|null, errors: Array<string> }
 */
export function validateAndParseJSON(jsonString) {
  try {
    const data = JSON.parse(jsonString);
    const validation = validateScenarioStructure(data);
    return {
      valid: validation.valid,
      data: validation.valid ? data : null,
      errors: validation.errors
    };
  } catch (error) {
    return {
      valid: false,
      data: null,
      errors: [`Invalid JSON: ${error.message}`]
    };
  }
}
