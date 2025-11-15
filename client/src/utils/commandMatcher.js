/**
 * Command Matcher Utility
 * Intelligent fuzzy matching with multiple strategies
 */

import { parseCommand, normalizeCommand, areCommandsSimilar } from './commandParser.js';

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

/**
 * Match user input against expected command with fuzzy logic
 * @param {string} userInput - User's command input
 * @param {string} expectedCommand - Expected command
 * @param {boolean} tutorialMode - Whether tutorial mode is enabled
 * @returns {Object} Match result with confidence and suggestions
 */
export function fuzzyMatchCommand(userInput, expectedCommand, tutorialMode = false) {
  const normalizedInput = normalizeCommand(userInput);
  const normalizedExpected = normalizeCommand(expectedCommand);
  
  // Exact match
  if (normalizedInput === normalizedExpected) {
    return { 
      match: true, 
      confidence: 1.0,
      method: 'exact',
      matchedCommand: expectedCommand
    };
  }

  // Parse both commands
  const parsedInput = parseCommand(normalizedInput);
  const parsedExpected = parseCommand(normalizedExpected);

  // Structural match (command + flags + args in any order)
  if (areCommandsSimilar(parsedInput, parsedExpected)) {
    return {
      match: true,
      confidence: 0.95,
      method: 'structural',
      matchedCommand: expectedCommand,
      parsedInput,
      parsedExpected
    };
  }

  // Fuzzy string matching
  const threshold = tutorialMode ? 0.70 : 0.85;
  
  const expectedParts = normalizedExpected
    .split(' ')
    .filter(p => p.length > 2 && !['the', 'and', 'for', 'with'].includes(p));
  
  const inputParts = normalizedInput.split(' ');
  
  const matchedParts = expectedParts.filter(part => 
    inputParts.some(inputPart => 
      inputPart.includes(part) || 
      part.includes(inputPart) ||
      levenshteinDistance(inputPart, part) <= 2
    )
  );
  
  const confidence = expectedParts.length > 0 ? matchedParts.length / expectedParts.length : 0;
  
  return {
    match: confidence >= threshold,
    confidence,
    method: 'fuzzy',
    suggestion: confidence < threshold && confidence > 0.5 ? expectedCommand : null,
    matchedCommand: confidence >= threshold ? expectedCommand : null,
    parsedInput,
    parsedExpected
  };
}

/**
 * Match against multiple expected commands
 * @param {string} userInput - User's command input
 * @param {Array<string>} expectedCommands - Array of valid commands
 * @param {boolean} tutorialMode - Whether tutorial mode is enabled
 * @returns {Object} Best match result
 */
export function matchAgainstMultiple(userInput, expectedCommands, tutorialMode = false) {
  if (!Array.isArray(expectedCommands) || expectedCommands.length === 0) {
    return {
      match: false,
      confidence: 0,
      method: 'none',
      suggestion: null
    };
  }

  let bestMatch = null;
  let bestConfidence = 0;

  for (const expectedCmd of expectedCommands) {
    const result = fuzzyMatchCommand(userInput, expectedCmd, tutorialMode);
    
    // If exact or structural match, return immediately
    if (result.match && (result.method === 'exact' || result.method === 'structural')) {
      return result;
    }
    
    // Track best fuzzy match
    if (result.confidence > bestConfidence) {
      bestConfidence = result.confidence;
      bestMatch = result;
    }
  }

  // Return best match if it passed threshold, otherwise no match
  if (bestMatch && bestMatch.match) {
    return bestMatch;
  }

  // Return best attempt even if not matched (for suggestions)
  return bestMatch || {
    match: false,
    confidence: 0,
    method: 'none',
    suggestion: expectedCommands[0] || null // Suggest first command as fallback
  };
}
