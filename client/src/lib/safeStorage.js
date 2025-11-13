/**
 * Safe localStorage helpers with error handling and fallbacks
 */

const STORAGE_PREFIX = 'ad-trainer-';

/**
 * Safely get item from localStorage
 * @param {string} key - Storage key
 * @param {*} defaultValue - Default value if key doesn't exist or parsing fails
 * @returns {*} Parsed value or default
 */
export function safeGetItem(key, defaultValue = null) {
  try {
    const fullKey = `${STORAGE_PREFIX}${key}`;
    const item = localStorage.getItem(fullKey);
    
    if (item === null) {
      return defaultValue;
    }
    
    try {
      return JSON.parse(item);
    } catch (parseError) {
      console.warn(`Failed to parse localStorage key "${key}":`, parseError);
      return defaultValue;
    }
  } catch (error) {
    console.warn(`Failed to read from localStorage:`, error);
    return defaultValue;
  }
}

/**
 * Safely set item in localStorage
 * @param {string} key - Storage key
 * @param {*} value - Value to store (will be JSON stringified)
 * @returns {boolean} Success status
 */
export function safeSetItem(key, value) {
  try {
    const fullKey = `${STORAGE_PREFIX}${key}`;
    localStorage.setItem(fullKey, JSON.stringify(value));
    return true;
  } catch (error) {
    console.error(`Failed to write to localStorage key "${key}":`, error);
    return false;
  }
}

/**
 * Safely remove item from localStorage
 * @param {string} key - Storage key
 * @returns {boolean} Success status
 */
export function safeRemoveItem(key) {
  try {
    const fullKey = `${STORAGE_PREFIX}${key}`;
    localStorage.removeItem(fullKey);
    return true;
  } catch (error) {
    console.error(`Failed to remove from localStorage key "${key}":`, error);
    return false;
  }
}

/**
 * Safely clear all app-prefixed items from localStorage
 * @returns {boolean} Success status
 */
export function safeClearAll() {
  try {
    const keysToRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX)) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach(key => localStorage.removeItem(key));
    return true;
  } catch (error) {
    console.error('Failed to clear localStorage:', error);
    return false;
  }
}

/**
 * Get all app-prefixed items from localStorage
 * @returns {Object} All stored items
 */
export function safeGetAll() {
  try {
    const items = {};
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.startsWith(STORAGE_PREFIX)) {
        const cleanKey = key.replace(STORAGE_PREFIX, '');
        items[cleanKey] = safeGetItem(cleanKey);
      }
    }
    return items;
  } catch (error) {
    console.error('Failed to read all items from localStorage:', error);
    return {};
  }
}

/**
 * Migrate old localStorage keys to new prefixed format
 * @param {Array<string>} oldKeys - Old key names to migrate
 */
export function migrateLegacyStorage(oldKeys = []) {
  try {
    oldKeys.forEach(oldKey => {
      try {
        const value = localStorage.getItem(oldKey);
        if (value !== null) {
          safeSetItem(oldKey, JSON.parse(value));
          localStorage.removeItem(oldKey);
        }
      } catch (error) {
        console.warn(`Failed to migrate key "${oldKey}":`, error);
      }
    });
  } catch (error) {
    console.error('Failed to migrate legacy storage:', error);
  }
}
