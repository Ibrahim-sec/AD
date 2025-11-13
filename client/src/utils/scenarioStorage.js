/**
 * Scenario Storage Utilities
 * 
 * Manages custom scenarios in localStorage
 * Provides CRUD operations for custom scenario persistence
 */

const STORAGE_KEY = 'adTrainer_customScenarios';

/**
 * Get all custom scenarios from localStorage
 * @returns {Array} Array of custom scenario objects
 */
export function getCustomScenarios() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch (error) {
    console.error('Error loading custom scenarios:', error);
    return [];
  }
}

/**
 * Save a custom scenario to localStorage
 * @param {Object} scenario - The scenario object to save
 * @returns {boolean} True if successful, false otherwise
 */
export function saveCustomScenario(scenario) {
  try {
    const scenarios = getCustomScenarios();
    const existingIndex = scenarios.findIndex(s => s.id === scenario.id);
    
    if (existingIndex >= 0) {
      // Update existing scenario
      scenarios[existingIndex] = scenario;
    } else {
      // Add new scenario
      scenarios.push(scenario);
    }
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(scenarios));
    return true;
  } catch (error) {
    console.error('Error saving custom scenario:', error);
    return false;
  }
}

/**
 * Update an existing custom scenario
 * @param {string} id - The scenario ID
 * @param {Object} updates - The fields to update
 * @returns {boolean} True if successful, false otherwise
 */
export function updateCustomScenario(id, updates) {
  try {
    const scenarios = getCustomScenarios();
    const scenario = scenarios.find(s => s.id === id);
    
    if (!scenario) {
      console.error(`Scenario with ID ${id} not found`);
      return false;
    }
    
    const updated = { ...scenario, ...updates };
    return saveCustomScenario(updated);
  } catch (error) {
    console.error('Error updating custom scenario:', error);
    return false;
  }
}

/**
 * Delete a custom scenario from localStorage
 * @param {string} id - The scenario ID to delete
 * @returns {boolean} True if successful, false otherwise
 */
export function deleteCustomScenario(id) {
  try {
    const scenarios = getCustomScenarios();
    const filtered = scenarios.filter(s => s.id !== id);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
    return true;
  } catch (error) {
    console.error('Error deleting custom scenario:', error);
    return false;
  }
}

/**
 * Get a specific custom scenario by ID
 * @param {string} id - The scenario ID
 * @returns {Object|null} The scenario object or null if not found
 */
export function getCustomScenarioById(id) {
  const scenarios = getCustomScenarios();
  return scenarios.find(s => s.id === id) || null;
}

/**
 * Clear all custom scenarios from localStorage
 * @returns {boolean} True if successful
 */
export function clearAllCustomScenarios() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return true;
  } catch (error) {
    console.error('Error clearing custom scenarios:', error);
    return false;
  }
}
