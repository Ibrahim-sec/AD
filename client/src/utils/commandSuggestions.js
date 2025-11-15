/**
 * Command Suggestions Utility
 * Generate helpful error messages and suggestions
 */

import { getCommandDifferences } from './commandParser.js';

/**
 * Generate helpful error message based on match result
 * @param {Object} matchResult - Result from fuzzy matcher
 * @param {string} userInput - User's input
 * @param {boolean} tutorialMode - Tutorial mode status
 * @returns {Array} Array of error message objects
 */
export function generateErrorMessages(matchResult, userInput, tutorialMode) {
  const messages = [];

  if (!matchResult || matchResult.match) {
    return messages;
  }

  const { confidence, suggestion, parsedInput, parsedExpected } = matchResult;

  if (tutorialMode) {
    // Tutorial mode: detailed feedback
    messages.push({
      type: 'error',
      text: `[!] Command not quite right. Let's analyze what you typed:`
    });

    messages.push({
      type: 'info',
      text: `[*] You typed: ${userInput}`
    });

    if (suggestion) {
      messages.push({
        type: 'info',
        text: `[*] Expected: ${suggestion}`
      });
    }

    // Compare structure if both parsed successfully
    if (parsedInput && parsedExpected) {
      const differences = getCommandDifferences(parsedInput, parsedExpected);

      if (differences.baseCommandMismatch) {
        messages.push({
          type: 'warning',
          text: `[⚠] Wrong base command. You used: ${parsedInput.baseCommand}, Expected: ${parsedExpected.baseCommand}`
        });
      } else {
        // Check flags
        if (differences.missingFlags.length > 0) {
          messages.push({
            type: 'warning',
            text: `[⚠] Missing flags: ${differences.missingFlags.join(' ')}`
          });
        }

        if (differences.extraFlags.length > 0) {
          messages.push({
            type: 'info',
            text: `[*] Extra flags (not needed): ${differences.extraFlags.join(' ')}`
          });
        }

        // Check arguments
        if (differences.missingArguments.length > 0) {
          messages.push({
            type: 'warning',
            text: `[⚠] Missing arguments: ${differences.missingArguments.join(' ')}`
          });
        }
      }
    }

    if (confidence > 0.5) {
      messages.push({
        type: 'success',
        text: `[✓] You're close! Confidence: ${Math.round(confidence * 100)}%`
      });
    } else if (confidence > 0.3) {
      messages.push({
        type: 'warning',
        text: `[⚠] Heading in the right direction. Confidence: ${Math.round(confidence * 100)}%`
      });
    } else {
      messages.push({
        type: 'error',
        text: `[!] Command seems quite different from what's expected.`
      });
    }

  } else {
    // Non-tutorial mode: minimal feedback
    messages.push({
      type: 'error',
      text: '[!] Command not recognized or incorrect for this step.'
    });

    if (confidence > 0.6 && suggestion) {
      messages.push({
        type: 'info',
        text: `[*] Hint: Did you mean: ${suggestion}?`
      });
    } else if (confidence > 0.4) {
      messages.push({
        type: 'info',
        text: `[*] You're on the right track. Review the objective and try again.`
      });
    }
  }

  return messages;
}

/**
 * Generate success message
 * @param {Object} matchResult - Match result
 * @returns {Array} Success messages
 */
export function generateSuccessMessages(matchResult) {
  const messages = [];

  if (matchResult.method === 'exact') {
    messages.push({
      type: 'success',
      text: '[✓] Perfect match! Executing command...'
    });
  } else if (matchResult.method === 'structural') {
    messages.push({
      type: 'success',
      text: '[✓] Command accepted! (Flags in different order, but correct)'
    });
  } else if (matchResult.method === 'fuzzy') {
    messages.push({
      type: 'success',
      text: '[✓] Command accepted! (Minor variations, but semantically correct)'
    });
  } else {
    messages.push({
      type: 'success',
      text: '[✓] Command accepted!'
    });
  }

  return messages;
}

/**
 * Get command comparison for display
 * @param {string} userInput - User input
 * @param {string} expected - Expected command
 * @returns {Object} Comparison object
 */
export function getCommandComparison(userInput, expected) {
  return {
    userInput: userInput,
    expected: expected,
    match: userInput.trim().toLowerCase() === expected.trim().toLowerCase()
  };
}
