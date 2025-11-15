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
 */
export const processLootGrant = (lootToGrant, state, setState) => {
  if (!lootToGrant) return;
  
  // Grant files
  if (lootToGrant.files) {
    setState(prev => ({
      ...prev,
      simulatedFileSystem: { ...prev.simulatedFileSystem, ...lootToGrant.files }
    }));
  }
  
  // Grant credentials
  if (lootToGrant.creds) {
    lootToGrant.creds.forEach(cred => {
      setState(prev => ({
        ...prev,
        credentialInventory: harvestCredential(
          prev.credentialInventory,
          cred.type,
          cred.username,
          cred.secret
        )
      }));
    });
  }
  
  // Grant downloads
  if (lootToGrant.download) {
    setState(prev => ({
      ...prev,
      simulatedFiles: [...prev.simulatedFiles, ...lootToGrant.download]
    }));
  }
};
