// client/src/lib/safeStorage.js

/**
 * Safe localStorage wrapper with error handling and quota management
 * Handles all edge cases: disabled storage, quota exceeded, JSON errors
 */

const QUOTA_WARNING_THRESHOLD = 0.8; // Warn at 80% usage

/**
 * Check if localStorage is available
 */
const isStorageAvailable = () => {
  try {
    const test = '__storage_test__';
    localStorage.setItem(test, test);
    localStorage.removeItem(test);
    return true;
  } catch (e) {
    return false;
  }
};

/**
 * Get localStorage usage percentage (0-1)
 */
export const getStorageUsage = () => {
  if (!isStorageAvailable()) return 0;
  
  try {
    let total = 0;
    for (let key in localStorage) {
      if (localStorage.hasOwnProperty(key)) {
        total += localStorage[key].length + key.length;
      }
    }
    
    // Estimate quota (usually 5-10MB, we'll use 5MB as conservative estimate)
    const estimatedQuota = 5 * 1024 * 1024;
    return total / estimatedQuota;
  } catch (e) {
    return 0;
  }
};

/**
 * Check if we're approaching storage quota
 */
export const isApproachingQuota = () => {
  return getStorageUsage() > QUOTA_WARNING_THRESHOLD;
};

/**
 * Safely get item from localStorage
 */
export const safeGetItem = (key, defaultValue = null) => {
  if (!isStorageAvailable()) {
    console.warn('localStorage is not available');
    return defaultValue;
  }
  
  try {
    const item = localStorage.getItem(key);
    
    if (item === null) {
      return defaultValue;
    }
    
    // Try to parse as JSON, fallback to raw string
    try {
      return JSON.parse(item);
    } catch (parseError) {
      // Not JSON, return as string
      return item;
    }
  } catch (error) {
    console.error(`Error reading from localStorage (${key}):`, error);
    return defaultValue;
  }
};

/**
 * Safely set item in localStorage
 */
export const safeSetItem = (key, value) => {
  if (!isStorageAvailable()) {
    console.warn('localStorage is not available');
    return false;
  }
  
  try {
    // Warn if approaching quota
    if (isApproachingQuota()) {
      console.warn('localStorage is approaching quota limit');
    }
    
    // Serialize value if it's an object
    const serialized = typeof value === 'string' ? value : JSON.stringify(value);
    
    localStorage.setItem(key, serialized);
    return true;
  } catch (error) {
    if (error.name === 'QuotaExceededError') {
      console.error('localStorage quota exceeded');
      
      // Try to free up space by removing old data
      const success = cleanupOldData(key);
      
      if (success) {
        try {
          const serialized = typeof value === 'string' ? value : JSON.stringify(value);
          localStorage.setItem(key, serialized);
          return true;
        } catch (retryError) {
          console.error('Failed to save even after cleanup:', retryError);
          return false;
        }
      }
      
      return false;
    }
    
    console.error(`Error writing to localStorage (${key}):`, error);
    return false;
  }
};

/**
 * Safely remove item from localStorage
 */
export const safeRemoveItem = (key) => {
  if (!isStorageAvailable()) {
    return false;
  }
  
  try {
    localStorage.removeItem(key);
    return true;
  } catch (error) {
    console.error(`Error removing from localStorage (${key}):`, error);
    return false;
  }
};

/**
 * Safely clear all localStorage
 */
export const safeClearAll = () => {
  if (!isStorageAvailable()) {
    return false;
  }
  
  try {
    localStorage.clear();
    return true;
  } catch (error) {
    console.error('Error clearing localStorage:', error);
    return false;
  }
};

/**
 * Get all keys in localStorage
 */
export const getAllKeys = () => {
  if (!isStorageAvailable()) {
    return [];
  }
  
  try {
    return Object.keys(localStorage);
  } catch (error) {
    console.error('Error getting localStorage keys:', error);
    return [];
  }
};

/**
 * Get storage size in bytes
 */
export const getStorageSize = () => {
  if (!isStorageAvailable()) {
    return 0;
  }
  
  try {
    let total = 0;
    for (let key in localStorage) {
      if (localStorage.hasOwnProperty(key)) {
        total += localStorage[key].length + key.length;
      }
    }
    return total;
  } catch (error) {
    return 0;
  }
};

/**
 * Cleanup old data to free up space
 */
const cleanupOldData = (priorityKey) => {
  console.log('Attempting to free up localStorage space...');
  
  try {
    // Get all keys except the priority key
    const keys = Object.keys(localStorage).filter(k => k !== priorityKey);
    
    // Remove items with timestamps, starting with oldest
    const itemsWithTimestamps = keys
      .map(key => {
        try {
          const value = JSON.parse(localStorage.getItem(key));
          const timestamp = value?.updatedAt || value?.createdAt || 0;
          return { key, timestamp };
        } catch {
          return { key, timestamp: 0 };
        }
      })
      .sort((a, b) => a.timestamp - b.timestamp);
    
    // Remove oldest 25% of items
    const toRemove = Math.ceil(itemsWithTimestamps.length * 0.25);
    
    for (let i = 0; i < toRemove; i++) {
      localStorage.removeItem(itemsWithTimestamps[i].key);
    }
    
    console.log(`Removed ${toRemove} old items from localStorage`);
    return true;
  } catch (error) {
    console.error('Failed to cleanup localStorage:', error);
    return false;
  }
};

/**
 * Export all localStorage data
 */
export const exportAllData = () => {
  if (!isStorageAvailable()) {
    return null;
  }
  
  try {
    const data = {};
    for (let key in localStorage) {
      if (localStorage.hasOwnProperty(key)) {
        try {
          data[key] = JSON.parse(localStorage[key]);
        } catch {
          data[key] = localStorage[key];
        }
      }
    }
    return data;
  } catch (error) {
    console.error('Error exporting localStorage data:', error);
    return null;
  }
};

/**
 * Import data to localStorage
 */
export const importAllData = (data) => {
  if (!isStorageAvailable() || !data) {
    return false;
  }
  
  try {
    for (let key in data) {
      safeSetItem(key, data[key]);
    }
    return true;
  } catch (error) {
    console.error('Error importing localStorage data:', error);
    return false;
  }
};

/**
 * Check storage health
 */
export const checkStorageHealth = () => {
  const available = isStorageAvailable();
  const usage = getStorageUsage();
  const size = getStorageSize();
  const approaching = isApproachingQuota();
  
  return {
    available,
    usage,
    size,
    approaching,
    sizeFormatted: formatBytes(size),
    status: !available ? 'unavailable' : approaching ? 'warning' : 'healthy'
  };
};

/**
 * Format bytes to human readable
 */
const formatBytes = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
};
