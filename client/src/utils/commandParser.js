/**
 * Command Parser Utility
 * Parses shell commands into structured components for intelligent matching
 */

/**
 * Parse a shell command into its components
 * @param {string} command - The command string to parse
 * @returns {Object} Parsed command structure
 */
export function parseCommand(command) {
  if (!command || typeof command !== 'string') {
    return { baseCommand: '', flags: [], arguments: [], raw: '' };
  }

  const normalized = command.trim().toLowerCase();
  const parts = normalized.split(/\s+/).filter(Boolean);

  if (parts.length === 0) {
    return { baseCommand: '', flags: [], arguments: [], raw: normalized };
  }

  const baseCommand = parts[0];
  const flags = [];
  const args = [];

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    if (part.startsWith('-')) {
      flags.push(part);
    } else {
      args.push(part);
    }
  }

  return {
    baseCommand,
    flags: flags.sort(), // Sort for consistent comparison
    arguments: args,
    raw: normalized
  };
}

/**
 * Normalize command for comparison
 * @param {string} cmd - Command to normalize
 * @returns {string} Normalized command
 */
export function normalizeCommand(cmd) {
  if (!cmd || typeof cmd !== 'string') return '';
  
  return cmd
    .trim()
    .toLowerCase()
    .replace(/\\/g, '/') // Normalize path separators
    .replace(/\s+/g, ' ') // Normalize whitespace
    .replace(/["'`]/g, '') // Remove quotes
    .replace(/;+$/, '') // Remove trailing semicolons
    .trim();
}

/**
 * Check if two commands are structurally similar
 * @param {Object} parsed1 - First parsed command
 * @param {Object} parsed2 - Second parsed command
 * @returns {boolean} True if structurally similar
 */
export function areCommandsSimilar(parsed1, parsed2) {
  // Base command must match
  if (parsed1.baseCommand !== parsed2.baseCommand) {
    return false;
  }

  // All flags in expected must be present
  const allFlagsPresent = parsed2.flags.every(flag => 
    parsed1.flags.includes(flag)
  );

  if (!allFlagsPresent) {
    return false;
  }

  // Check if arguments are similar (allow some flexibility)
  if (parsed2.arguments.length > 0) {
    const hasAllArgs = parsed2.arguments.every(arg =>
      parsed1.arguments.some(userArg => 
        userArg.includes(arg) || arg.includes(userArg)
      )
    );
    
    return hasAllArgs;
  }

  return true;
}

/**
 * Extract command differences for feedback
 * @param {Object} parsedInput - User's parsed command
 * @param {Object} parsedExpected - Expected parsed command
 * @returns {Object} Differences object
 */
export function getCommandDifferences(parsedInput, parsedExpected) {
  const differences = {
    baseCommandMismatch: parsedInput.baseCommand !== parsedExpected.baseCommand,
    missingFlags: [],
    extraFlags: [],
    missingArguments: [],
    extraArguments: []
  };

  // Find missing and extra flags
  differences.missingFlags = parsedExpected.flags.filter(f => !parsedInput.flags.includes(f));
  differences.extraFlags = parsedInput.flags.filter(f => !parsedExpected.flags.includes(f));

  // Find missing and extra arguments
  differences.missingArguments = parsedExpected.arguments.filter(a => !parsedInput.arguments.includes(a));
  differences.extraArguments = parsedInput.arguments.filter(a => !parsedExpected.arguments.includes(a));

  return differences;
}
