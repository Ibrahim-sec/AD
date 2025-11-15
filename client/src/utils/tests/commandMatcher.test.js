/**
 * Unit tests for command matching utilities
 * Run with: npm test
 */

import { fuzzyMatchCommand, matchAgainstMultiple } from '../commandMatcher.js';
import { parseCommand, normalizeCommand, areCommandsSimilar } from '../commandParser.js';
import { generateErrorMessages, generateSuccessMessages } from '../commandSuggestions.js';

describe('Command Parser', () => {
  test('should parse basic command correctly', () => {
    const result = parseCommand('nmap -sn 10.0.1.0/24');
    expect(result.baseCommand).toBe('nmap');
    expect(result.flags).toContain('-sn');
    expect(result.arguments).toContain('10.0.1.0/24');
  });

  test('should parse command with multiple flags', () => {
    const result = parseCommand('nmap -sV -sC -p- 10.0.1.10');
    expect(result.baseCommand).toBe('nmap');
    expect(result.flags).toEqual(['-p-', '-sc', '-sv']); // sorted
    expect(result.arguments).toContain('10.0.1.10');
  });

  test('should normalize command whitespace', () => {
    const result = normalizeCommand('  NMAP   -sn  10.0.1.0/24  ');
    expect(result).toBe('nmap -sn 10.0.1.0/24');
  });

  test('should remove quotes from normalized command', () => {
    const result = normalizeCommand('echo "hello world"');
    expect(result).toBe('echo hello world');
  });

  test('should detect similar commands with different flag order', () => {
    const parsed1 = parseCommand('nmap -sn -vv 10.0.1.0/24');
    const parsed2 = parseCommand('nmap -vv -sn 10.0.1.0/24');
    expect(areCommandsSimilar(parsed1, parsed2)).toBe(true);
  });

  test('should reject dissimilar commands', () => {
    const parsed1 = parseCommand('nmap -sn 10.0.1.0/24');
    const parsed2 = parseCommand('masscan -p80 10.0.1.0/24');
    expect(areCommandsSimilar(parsed1, parsed2)).toBe(false);
  });
});

describe('Fuzzy Matcher', () => {
  test('should match exact commands', () => {
    const result = fuzzyMatchCommand(
      'nmap -sn 10.0.1.0/24',
      'nmap -sn 10.0.1.0/24'
    );
    expect(result.match).toBe(true);
    expect(result.method).toBe('exact');
    expect(result.confidence).toBe(1.0);
  });

  test('should match commands with different flag order', () => {
    const result = fuzzyMatchCommand(
      'nmap -vv -sn 10.0.1.0/24',
      'nmap -sn -vv 10.0.1.0/24'
    );
    expect(result.match).toBe(true);
    expect(result.method).toBe('structural');
    expect(result.confidence).toBeGreaterThanOrEqual(0.95);
  });

  test('should match with extra whitespace', () => {
    const result = fuzzyMatchCommand(
      'nmap    -sn   10.0.1.0/24',
      'nmap -sn 10.0.1.0/24'
    );
    expect(result.match).toBe(true);
  });

  test('should match case-insensitive', () => {
    const result = fuzzyMatchCommand(
      'NMAP -SN 10.0.1.0/24',
      'nmap -sn 10.0.1.0/24'
    );
    expect(result.match).toBe(true);
  });

  test('should be more lenient in tutorial mode', () => {
    const result = fuzzyMatchCommand(
      'nmap 10.0.1.0/24',
      'nmap -sn 10.0.1.0/24',
      true // tutorial mode
    );
    // Should have higher confidence but may not match
    expect(result.confidence).toBeGreaterThan(0.5);
  });

  test('should be strict in non-tutorial mode', () => {
    const result = fuzzyMatchCommand(
      'nmap 10.0.1.0/24',
      'nmap -sn 10.0.1.0/24',
      false // non-tutorial mode
    );
    expect(result.match).toBe(false);
  });

  test('should reject completely different commands', () => {
    const result = fuzzyMatchCommand(
      'ls -la',
      'nmap -sn 10.0.1.0/24'
    );
    expect(result.match).toBe(false);
    expect(result.confidence).toBeLessThan(0.3);
  });

  test('should provide suggestions for near-matches', () => {
    const result = fuzzyMatchCommand(
      'nmap -s 10.0.1.0/24',
      'nmap -sn 10.0.1.0/24',
      true
    );
    expect(result.suggestion).toBeTruthy();
  });
});

describe('Multiple Command Matcher', () => {
  test('should match against multiple valid commands', () => {
    const validCommands = [
      'nmap -sn 10.0.1.0/24',
      'nmap 10.0.1.0/24 -sn',
      'nmap -sn 10.0.1.1-255'
    ];
    
    const result = matchAgainstMultiple(
      'nmap -sn 10.0.1.1-255',
      validCommands
    );
    
    expect(result.match).toBe(true);
    expect(result.matchedCommand).toBe('nmap -sn 10.0.1.1-255');
  });

  test('should return best match even if no exact match', () => {
    const validCommands = [
      'nmap -sn 10.0.1.0/24',
      'nmap -sV 10.0.1.0/24'
    ];
    
    const result = matchAgainstMultiple(
      'nmap 10.0.1.0/24',
      validCommands,
      true // tutorial mode
    );
    
    expect(result.suggestion).toBeTruthy();
    expect(result.confidence).toBeGreaterThan(0);
  });

  test('should prioritize exact matches over fuzzy', () => {
    const validCommands = [
      'nmap -sn 10.0.1.0/24',
      'nmap -sV 10.0.1.0/24',
      'nmap -sC 10.0.1.0/24'
    ];
    
    const result = matchAgainstMultiple(
      'nmap -sV 10.0.1.0/24',
      validCommands
    );
    
    expect(result.match).toBe(true);
    expect(result.method).toBe('exact');
    expect(result.matchedCommand).toBe('nmap -sV 10.0.1.0/24');
  });

  test('should handle empty command array', () => {
    const result = matchAgainstMultiple('nmap -sn 10.0.1.0/24', []);
    expect(result.match).toBe(false);
    expect(result.confidence).toBe(0);
  });
});

describe('Error Message Generator', () => {
  test('should generate detailed feedback in tutorial mode', () => {
    const matchResult = {
      match: false,
      confidence: 0.6,
      suggestion: 'nmap -sn 10.0.1.0/24',
      parsedInput: parseCommand('nmap 10.0.1.0/24'),
      parsedExpected: parseCommand('nmap -sn 10.0.1.0/24')
    };

    const messages = generateErrorMessages(matchResult, 'nmap 10.0.1.0/24', true);
    
    expect(messages.length).toBeGreaterThan(2);
    expect(messages.some(m => m.type === 'warning')).toBe(true);
    expect(messages.some(m => m.text.includes('Missing flags'))).toBe(true);
  });

  test('should generate minimal feedback in non-tutorial mode', () => {
    const matchResult = {
      match: false,
      confidence: 0.3,
      suggestion: null
    };

    const messages = generateErrorMessages(matchResult, 'wrong command', false);
    
    expect(messages.length).toBeLessThanOrEqual(2);
    expect(messages[0].type).toBe('error');
  });

  test('should not generate messages for successful match', () => {
    const matchResult = {
      match: true,
      confidence: 1.0
    };

    const messages = generateErrorMessages(matchResult, 'nmap -sn 10.0.1.0/24', true);
    expect(messages.length).toBe(0);
  });
});

describe('Success Message Generator', () => {
  test('should generate appropriate message for exact match', () => {
    const matchResult = {
      match: true,
      method: 'exact',
      confidence: 1.0
    };

    const messages = generateSuccessMessages(matchResult);
    expect(messages.length).toBeGreaterThan(0);
    expect(messages[0].type).toBe('success');
    expect(messages[0].text).toContain('Perfect match');
  });

  test('should generate message for structural match', () => {
    const matchResult = {
      match: true,
      method: 'structural',
      confidence: 0.95
    };

    const messages = generateSuccessMessages(matchResult);
    expect(messages[0].text).toContain('Structural match');
  });

  test('should generate message for fuzzy match', () => {
    const matchResult = {
      match: true,
      method: 'fuzzy',
      confidence: 0.87
    };

    const messages = generateSuccessMessages(matchResult);
    expect(messages[0].text).toContain('accepted');
  });
});

describe('Integration Tests', () => {
  test('should handle complete workflow for valid command', () => {
    const userInput = 'nmap -sn 10.0.1.0/24';
    const expectedCommands = [
      'nmap -sn 10.0.1.0/24',
      'nmap 10.0.1.0/24 -sn'
    ];

    const matchResult = matchAgainstMultiple(userInput, expectedCommands, false);
    expect(matchResult.match).toBe(true);

    const successMessages = generateSuccessMessages(matchResult);
    expect(successMessages.length).toBeGreaterThan(0);
  });

  test('should handle complete workflow for invalid command', () => {
    const userInput = 'wrong command';
    const expectedCommands = ['nmap -sn 10.0.1.0/24'];

    const matchResult = matchAgainstMultiple(userInput, expectedCommands, true);
    expect(matchResult.match).toBe(false);

    const errorMessages = generateErrorMessages(matchResult, userInput, true);
    expect(errorMessages.length).toBeGreaterThan(0);
  });
});

describe('Edge Cases', () => {
  test('should handle null/undefined input gracefully', () => {
    expect(() => parseCommand(null)).not.toThrow();
    expect(() => normalizeCommand(undefined)).not.toThrow();
  });

  test('should handle empty string input', () => {
    const result = parseCommand('');
    expect(result.baseCommand).toBe('');
  });

  test('should handle very long commands', () => {
    const longCmd = 'nmap -sV -sC -O -A -p- ' + '10.0.1.'.repeat(50) + '1';
    expect(() => fuzzyMatchCommand(longCmd, 'nmap -sV 10.0.1.1')).not.toThrow();
  });

  test('should handle special characters', () => {
    const cmd = 'echo "test with $VAR and `backticks`"';
    const result = normalizeCommand(cmd);
    expect(result).toBeTruthy();
  });
});
