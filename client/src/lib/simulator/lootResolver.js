// client/src/lib/simulator/lootResolver.js

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
 * FIXED: Now uses state setters directly instead of the generic setState
 */
export const processLootGrant = (lootToGrant, setters) => {
  if (!lootToGrant) return;
  
  // Grant files to file system
  if (lootToGrant.files && setters.setSimulatedFileSystem) {
    setters.setSimulatedFileSystem(prev => ({
      ...prev,
      ...lootToGrant.files
    }));
  }
  
  // Grant credentials
  if (lootToGrant.creds && setters.setCredentialInventory) {
    lootToGrant.creds.forEach(cred => {
      setters.setCredentialInventory(prev =>
        harvestCredential(prev, cred.type, cred.username, cred.secret)
      );
    });
  }
  
  // Grant file downloads - THIS WAS THE BUG
  if (lootToGrant.download && setters.setSimulatedFiles) {
    setters.setSimulatedFiles(prev => [...prev, ...lootToGrant.download]);
  }
};
