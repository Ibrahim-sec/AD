/**
 * Scenario Storage Utilities
 * * Manages custom scenarios in localStorage
 * Provides CRUD operations for custom scenario persistence
 */

import { safeGetItem, safeSetItem, safeRemoveItem } from '../lib/safeStorage';

// The key used within the safeStorage namespace ('ad-trainer-' prefix is handled by safeStorage)

const STORAGE_KEY = 'customScenarios';

/**
 * Get all custom scenarios from localStorage
 * @returns {Array} Array of custom scenario objects, defaults to an empty array
 */
export function getCustomScenarios() {
  // Use safeGetItem to automatically handle JSON parsing and errors, defaulting to an empty array
  return safeGetItem(STORAGE_KEY, []);
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
  // Use safeRemoveItem to clear the key
  return safeRemoveItem(STORAGE_KEY);
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
    
    // Use safeSetItem to store the updated list
    return safeSetItem(STORAGE_KEY, scenarios);
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
    const scenarioIndex = scenarios.findIndex(s => s.id === id);
    
    if (scenarioIndex === -1) {
      console.error(`Scenario with ID ${id} not found`);
      return false;
    }
    
    const updated = { ...scenarios[scenarioIndex], ...updates };
    scenarios[scenarioIndex] = updated; // Update in place
    
    // Use safeSetItem to store the updated list
    return safeSetItem(STORAGE_KEY, scenarios);

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
    // Use safeSetItem to store the filtered list
    return safeSetItem(STORAGE_KEY, filtered);
  } catch (error) {
    console.error('Error deleting custom scenario:', error);
    return false;
  }
}

/**
 * Clear all custom scenarios from localStorage
 * @returns {boolean} True if successful
 */
export function clearAllCustomScenarios() {
  // Use safeRemoveItem to clear the key
  return safeRemoveItem(STORAGE_KEY);
}
  // Use safeGetItem to automatically handle JSON parsing and errors, defaulting to an empty array
  return safeGetItem(STORAGE_KEY, []);
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
    
    // Use safeSetItem to store the updated list
    return safeSetItem(STORAGE_KEY, scenarios);
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
    const scenarioIndex = scenarios.findIndex(s => s.id === id);
    
    if (scenarioIndex === -1) {
      console.error(`Scenario with ID ${id} not found`);
      return false;
    }
    
    const updated = { ...scenarios[scenarioIndex], ...updates };
    scenarios[scenarioIndex] = updated; // Update in place
    
    // Use safeSetItem to store the updated list
    return safeSetItem(STORAGE_KEY, scenarios);

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
    // Use safeSetItem to store the filtered list
    return safeSetItem(STORAGE_KEY, filtered);
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
  // Use safeRemoveItem to clear the key
  return safeRemoveItem(STORAGE_KEY);
}

/**
 * Clear all custom scenarios from localStorage
 * @returns {boolean} True if successful
 */
export function clearAllCustomScenarios() {
  // Use safeRemoveItem to clear the key
  return safeRemoveItem(STORAGE_KEY);
}