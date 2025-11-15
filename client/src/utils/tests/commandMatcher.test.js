/**
 * Unit tests for command matching utilities
 */

import { fuzzyMatchCommand, matchAgainstMultiple } from '../commandMatcher.js';
import { parseCommand, normalizeCommand, areCommandsSimilar } from '../commandParser.js';

describe('Command Parser', () => {
  test('should parse basic command', () => {
    const result = parseCommand('nmap -sn 10.0.1.0/24');
    expect(result.baseCommand).toBe('nmap');
    expect(result.flags).toContain('-sn');
    expect(result.arguments).toContain('10.0.1.0/24');
  });

  test('should normalize command', () => {
    const result = normalizeCommand('  NMAP   -sn  10.0.1.0/24  ');
    expect(result).toBe('nmap -sn 10.0.1.0/24');
  });

  test('should detect similar commands with different flag order', () => {
    const parsed1 = parseCommand('nmap -sn -vv 10.0.1.0/24');
    const parsed2 = parseCommand('nmap -vv -sn 10.0.1.0/24');
    expect(areCommandsSimilar(parsed1, parsed2)).toBe(true);
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
  });

  test('should match with extra whitespace', () => {
    const result = fuzzyMatchCommand(
      'nmap    -sn   10.0.1.0/24',
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
    // Should have higher tolerance
    expect(result.confidence).toBeGreaterThan(0.5);
  });

  test('should reject completely different commands', () => {
    const result = fuzzyMatchCommand(
      'ls -la',
      'nmap -sn 10.0.1.0/24'
    );
    expect(result.match).toBe(false);
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
  });

  test('should return best match suggestion', () => {
    const validCommands = [
      'nmap -sn 10.0.1.0/24',
      'nmap -sV 10.0.1.0/24'
    ];
    
    const result = matchAgainstMultiple(
      'nmap 10.0.1.0/24',
      validCommands
    );
    
    expect(result.suggestion).toBeTruthy();
  });
});
