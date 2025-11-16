// client/src/lib/simulator/lootResolver.js

import { addCredentialToInventory, addFileToInventory, saveProgress } from '../progressTracker';

/**
 * Resolve loot variables in command strings
 * Replaces [loot:username] with actual credential values
 */
export const resolveLootVariables = (commandString, credentialInventory, onError) => {
  if (!commandString) return commandString;
  
  const lootRegex = /\[loot:([^\]]+)\]/gi;
  let resolvedCmd = commandString;
  
  const matches = [...commandString.matchAll(lootRegex)];
  if (matches.length === 0) return commandString;
  
  for (const match of matches) {
    const [fullMatch, usernameToFind] = match;
    const normalizedUsername = usernameToFind.toLowerCase().trim();
    
    const foundCred = credentialInventory.find(
      (c) => c.username.toLowerCase().trim() === normalizedUsername
    );
    
    if (foundCred) {
      resolvedCmd = resolvedCmd.replace(fullMatch, foundCred.secret);
    } else {
      if (onError) {
        onError({
          type: 'error',
          username: usernameToFind,
          available: credentialInventory.map(c => c.username)
        });
      }
      return null;
    }
  }
  
  return resolvedCmd;
};

/**
 * Harvest credential and add to inventory
 */
export const harvestCredential = (inventory, type, username, secret) => {
  const newCred = { id: Date.now(), type, username, secret };
  
  // Avoid duplicates
  if (inventory.some(c => c.secret === secret)) {
    return inventory;
  }
  
  return [...inventory, newCred];
};

/**
 * Process loot grant from step
 * Updated to save to both session state AND global inventory
 */
export const processLootGrant = (lootToGrant, setters, progress, setProgress, scenarioId) => {
  if (!lootToGrant) return;
  
  let updatedProgress = { ...progress };
  
  // Grant files to file system (session only)
  if (lootToGrant.files && setters.setSimulatedFileSystem) {
    setters.setSimulatedFileSystem(prev => ({
      ...prev,
      ...lootToGrant.files
    }));
    
    // Also add to global inventory
    if (progress && setProgress && scenarioId) {
      Object.entries(lootToGrant.files).forEach(([name, fileData]) => {
        updatedProgress = addFileToInventory(updatedProgress, {
          name,
          content: fileData.content,
          size: fileData.size
        }, scenarioId);
      });
    }
  }
  
  // Grant credentials to both session and global inventory
  if (lootToGrant.creds && setters.setCredentialInventory) {
    lootToGrant.creds.forEach(cred => {
      // Add to session
      setters.setCredentialInventory(prev =>
        harvestCredential(prev, cred.type, cred.username, cred.secret)
      );
      
      // Add to global inventory
      if (progress && setProgress && scenarioId) {
        updatedProgress = addCredentialToInventory(updatedProgress, cred, scenarioId);
      }
    });
  }
  
  // Grant file downloads
  if (lootToGrant.download && setters.setSimulatedFiles) {
    setters.setSimulatedFiles(prev => [...prev, ...lootToGrant.download]);
    
    // Also add to global inventory
    if (progress && setProgress && scenarioId) {
      lootToGrant.download.forEach(file => {
        updatedProgress = addFileToInventory(updatedProgress, file, scenarioId);
      });
    }
  }
  
  // Save updated progress to localStorage
  if (progress && setProgress && scenarioId && updatedProgress !== progress) {
    setProgress(updatedProgress);
    saveProgress(updatedProgress);
  }
};
