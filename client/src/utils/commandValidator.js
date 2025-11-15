/**
 * Command Validator Utility
 * Input validation and sanitization
 */

const MAX_COMMAND_LENGTH = 1000;

/**
 * Validate command input
 * @param {string} command - Command to validate
 * @returns {Object} Validation result
 */
export function validateCommand(command) {
  if (!command || typeof command !== 'string') {
    return { valid: false, error: 'Invalid command' };
  }
  
  const sanitized = command.trim();
  
  if (sanitized.length === 0) {
    return { valid: false, error: 'Empty command' };
  }
  
  if (sanitized.length > MAX_COMMAND_LENGTH) {
    return { valid: false, error: `Command too long (max ${MAX_COMMAND_LENGTH} characters)` };
  }
  
  // Prevent XSS attempts
  const dangerousPatterns = [
    /<script/i,
    /javascript:/i,
    /onerror=/i,
    /onclick=/i,
    /<iframe/i
  ];
  
  if (dangerousPatterns.some(pattern => pattern.test(sanitized))) {
    return { valid: false, error: 'Invalid command syntax' };
  }
  
  return { valid: true, command: sanitized };
}

/**
 * Check if command is a built-in terminal command
 * @param {string} command - Command to check
 * @returns {boolean} True if built-in
 */
export function isBuiltInCommand(command) {
  const builtIns = ['ls', 'dir', 'cat', 'type', 'pwd', 'whoami', 'clear', 'help', 'exit'];
  const baseCommand = command.trim().split(' ')[0].toLowerCase();
  return builtIns.includes(baseCommand);
}

/**
 * Sanitize command for display
 * @param {string} command - Command to sanitize
 * @returns {string} Sanitized command
 */
export function sanitizeForDisplay(command) {
  if (!command) return '';
  
  return command
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
