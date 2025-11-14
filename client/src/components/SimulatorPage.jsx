import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { Redirect, Link } from 'wouter';
import Header from './Header';
import GuidePanel from './GuidePanel';
import AttackerPanel from './AttackerPanel';
import MissionModal from './MissionModal';
import QuizPanel from './QuizPanel';
import AchievementsPanel from './AchievementsPanel';
import SettingsModal from './SettingsModal';
import { quizMap } from '../data/quizzes/index.js';
import { achievements, getUnlockedAchievements } from '../data/achievements.js';
import { 
  saveProgress, 
  addScenarioCompletion,
  addQuizScore,
  unlockAchievement
} from '../lib/progressTracker.js';
import { safeGetItem, safeSetItem } from '../lib/safeStorage.js';
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Activity, AlertTriangle } from 'lucide-react';
import MachineInfoSheet from './MachineInfoSheet';

// ============================================================================
// CONSTANTS
// ============================================================================

const COMMAND_HISTORY_KEY = 'ad-simulator-command-history';
const MAX_COMMAND_HISTORY = 100;
const SUBSHELL_TIMEOUT = 120000; // 2 minutes
const MAX_COMMAND_LENGTH = 1000;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Calculate score based on performance
 */
const calculateScenarioScore = (wrongAttempts, hintsUsed) => {
  if (wrongAttempts === 0 && hintsUsed === 0) {
    return 10;
  } else if (hintsUsed > 0 && hintsUsed <= 2) {
    return 5;
  } else if (wrongAttempts > 0) {
    return Math.max(0, 10 - (wrongAttempts * 2));
  }
  return 0;
};

/**
 * Get defense alert for specific step
 */
const getDefenseAlertForStep = (stepId, scenarioId) => {
  if (scenarioId === 'kerberoasting') {
    if (stepId === 1) return "[DEFENSE] ALERT: LDAP Query pattern detected (SPN enumeration).";
    if (stepId === 4) return "[DEFENSE] ALERT: Weak hash identified (Service account compromised).";
  }
  if (scenarioId === 'pass-the-hash') {
    if (stepId === 3) return "[DEFENSE] ALERT: Unusual NTLM authentication without password detected (PtH).";
  }
  if (scenarioId === 'dcsync') {
    return "[DEFENSE] ALERT: DCSync attack detected! Domain replication from unauthorized host!";
  }
  if (scenarioId === 'golden-ticket') {
    return "[DEFENSE] ALERT: krbtgt hash compromised! Golden Ticket attack possible!";
  }
  return null;
};

/**
 * Get sub-shell prompt
 */
const getSubShellPrompt = (shell) => {
  if (shell === 'mimikatz') return 'mimikatz # ';
  if (shell === 'powershell') return 'PS> ';
  if (shell === 'cmd') return 'C:\\> ';
  return '> ';
};

/**
 * Normalize command for comparison
 */
const normalizeCommand = (cmd) => {
  if (!cmd || typeof cmd !== 'string') return '';
  
  return cmd
    .trim()
    .toLowerCase()
    .replace(/\\/g, '/') // Normalize path separators
    .replace(/\s+/g, ' ') // Normalize whitespace
    .replace(/["'`]/g, '') // Remove quotes
    .replace(/;+$/, '') // Remove trailing semicolons
    .trim();
};

/**
 * Fuzzy match command with confidence score
 */
const fuzzyMatchCommand = (input, expected, threshold = 0.85) => {
  const normalizedInput = normalizeCommand(input);
  const normalizedExpected = normalizeCommand(expected);
  
  // Exact match
  if (normalizedInput === normalizedExpected) {
    return { match: true, confidence: 1.0 };
  }
  
  // Check if input contains all key parts of expected command
  const expectedParts = normalizedExpected
    .split(' ')
    .filter(p => p.length > 2 && !['the', 'and', 'for', 'with'].includes(p));
  
  const inputParts = normalizedInput.split(' ');
  
  const matchedParts = expectedParts.filter(part => 
    inputParts.some(inputPart => 
      inputPart.includes(part) || part.includes(inputPart) ||
      levenshteinDistance(inputPart, part) <= 2
    )
  );
  
  const confidence = expectedParts.length > 0 ? matchedParts.length / expectedParts.length : 0;
  
  return {
    match: confidence >= threshold,
    confidence,
    suggestion: confidence < threshold && confidence > 0.5 ? expected : null
  };
};

/**
 * Calculate Levenshtein distance between two strings
 */
const levenshteinDistance = (str1, str2) => {
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
};

/**
 * Validate command input
 */
const validateCommand = (command) => {
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
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function SimulatorPage({ 
  scenarioId, 
  allScenarios,
  progress,
  setProgress,
  appMode, 
  setAppMode,
}) {
  const currentScenario = allScenarios[scenarioId];

  // ========== STATE MANAGEMENT ==========
  
  // Core simulation state
  const [currentStep, setCurrentStep] = useState(0);
  const [attackerHistory, setAttackerHistory] = useState([]);
  const [serverHistory, setServerHistory] = useState([]);
  const [defenseHistory, setDefenseHistory] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [activeMachine, setActiveMachine] = useState('attacker');
  const [highlightedMachine, setHighlightedMachine] = useState(null);
  const [highlightedArrow, setHighlightedArrow] = useState(null);
  
  // Loot & File System State
  const [credentialInventory, setCredentialInventory] = useState([]);
  const [simulatedFiles, setSimulatedFiles] = useState([]);
  const [simulatedFileSystem, setSimulatedFileSystem] = useState({});
  
  // Sub-shell state
  const [subShell, setSubShell] = useState(null);
  const [subShellTimeout, setSubShellTimeout] = useState(null);
  
  // Settings state
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [customTheme, setCustomTheme] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('terminal_theme')) || {};
    } catch (e) {
      return {};
    }
  });
  
  // Modal & Game State
  const briefingStorageKey = `hasSeenBriefing_${scenarioId}`;
  const [showMissionBriefing, setShowMissionBriefing] = useState(() => {
    const hasSeen = safeGetItem(briefingStorageKey, null);
    return hasSeen !== true;
  });
  
  const [showMissionDebrief, setShowMissionDebrief] = useState(false);
  const [isMissionCompleted, setIsMissionCompleted] = useState(false);
  const [showQuiz, setShowQuiz] = useState(false);
  const [showAchievements, setShowAchievements] = useState(false);
  const [scenarioStats, setScenarioStats] = useState({
    wrongAttempts: 0,
    hintsUsed: 0,
    startTime: Date.now()
  });
  const [newAchievements, setNewAchievements] = useState([]);
  const [tutorialMode, setTutorialMode] = useState(progress.tutorialMode);
  const [hintsShown, setHintsShown] = useState({});
  
  // Machine inspection state
  const [inspectingNode, setInspectingNode] = useState(null);
  
  // Command history state
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  
  // Loading state
  const [isLoadingScenario, setIsLoadingScenario] = useState(false);
  
  // Debug mode
  const [debugMode, setDebugMode] = useState(false);
  
  // Processed steps tracker (prevent re-processing)
  const [processedSteps, setProcessedSteps] = useState(new Set());
  
  // Refs
  const processingRef = useRef(false);
  const mountedRef = useRef(true);
  
  // ========== REDIRECT IF NO SCENARIO ==========
  
  if (!currentScenario) {
    return <Redirect to="/" />;
  }
  
  // ========== LOAD COMMAND HISTORY FROM LOCALSTORAGE ==========
  
  useEffect(() => {
    try {
      const saved = localStorage.getItem(COMMAND_HISTORY_KEY);
      if (saved) {
        setCommandHistory(JSON.parse(saved).slice(-MAX_COMMAND_HISTORY));
      }
    } catch (e) {
      console.error('Failed to load command history:', e);
    }
  }, []);
  
  // ========== SAVE COMMAND HISTORY TO LOCALSTORAGE ==========
  
  useEffect(() => {
    try {
      localStorage.setItem(
        COMMAND_HISTORY_KEY,
        JSON.stringify(commandHistory.slice(-MAX_COMMAND_HISTORY))
      );
    } catch (e) {
      console.error('Failed to save command history:', e);
    }
  }, [commandHistory]);
  
  // ========== DEBUG MODE TOGGLE ==========
  
  useEffect(() => {
    const handleKeyPress = (e) => {
      if (e.ctrlKey && e.shiftKey && e.key === 'D') {
        setDebugMode(prev => !prev);
      }
    };
    
    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, []);
  
  // ========== SUB-SHELL TIMEOUT ==========
  
  useEffect(() => {
    if (subShell) {
      const timeout = setTimeout(() => {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'warning', text: `[!] Sub-shell timeout after 2 minutes. Type "exit" to return.` }
        ]);
      }, SUBSHELL_TIMEOUT);
      
      setSubShellTimeout(timeout);
      
      return () => {
        if (timeout) clearTimeout(timeout);
      };
    }
  }, [subShell]);
  
  // ========== INITIALIZE/RESET SCENARIO ==========
  
  useEffect(() => {
    setIsLoadingScenario(true);
    
    resetScenario();
    setCredentialInventory([]);
    setSimulatedFiles([]);
    setSimulatedFileSystem({});
    setSubShell(null);
    setInspectingNode(null);
    setIsMissionCompleted(false);
    setProcessedSteps(new Set());
    
    const hasSeen = safeGetItem(briefingStorageKey, null);
    setShowMissionBriefing(hasSeen !== true);
    
    setShowMissionDebrief(false);
    setShowQuiz(false);
    setScenarioStats({
      wrongAttempts: 0,
      hintsUsed: 0,
      startTime: Date.now()
    });
    setHintsShown({});
    
    // Smooth loading transition
    setTimeout(() => {
      setIsLoadingScenario(false);
    }, 300);
  }, [scenarioId, briefingStorageKey]);
  
  // ========== AUTO-ADVANCE STEPS WITH NULL EXPECTED COMMAND ==========
  
  useEffect(() => {
    const step = currentScenario?.steps[currentStep];
    const stepKey = `${scenarioId}-${currentStep}`;
    
    if (
      step && 
      step.expectedCommand == null && 
      !processingRef.current && 
      !isProcessing &&
      !subShell &&
      !processedSteps.has(stepKey) &&
      mountedRef.current
    ) {
      setProcessedSteps(prev => new Set(prev).add(stepKey));
      processingRef.current = true;
      setIsProcessing(true);
      processStepOutput(step);
    }
  }, [currentStep, currentScenario?.id, isProcessing, subShell, processedSteps]);
  
  // ========== CLEANUP ON UNMOUNT ==========
  
  useEffect(() => {
    mountedRef.current = true;
    
    return () => {
      mountedRef.current = false;
      if (subShellTimeout) clearTimeout(subShellTimeout);
    };
  }, []);
  
  // ========== HELPER FUNCTIONS ==========
  
  const handleUpdateTheme = (newTheme) => {
    setCustomTheme(newTheme);
    localStorage.setItem('terminal_theme', JSON.stringify(newTheme));
  };
  
  const harvestCredential = (type, username, secret) => {
    setCredentialInventory(prev => {
      const newCred = { id: Date.now(), type, username, secret };
      if (prev.some(c => c.secret === secret)) return prev;
      return [...prev, newCred];
    });
  };
  
  const resetScenario = () => {
    setCurrentStep(0);
    setActiveMachine('attacker');
    setHighlightedMachine(null);
    setHighlightedArrow(null);
    setSubShell(null);
    processingRef.current = false;
    
    setAttackerHistory([
      { type: 'system', text: `Welcome to ${currentScenario.network.attacker.hostname}` },
      { type: 'system', text: `IP: ${currentScenario.network.attacker.ip}` },
      { type: 'system', text: `Target: ${currentScenario.network.target.hostname} (${currentScenario.network.target.ip})` },
      { type: 'system', text: '' },
      { type: 'system', text: 'Type the commands from the guide to begin the attack simulation.' },
      { type: 'system', text: '' }
    ]);
    
    setServerHistory([
      { type: 'info', text: `[SYSTEM] ${currentScenario.network.target.hostname} - Windows Server 2019` },
      { type: 'info', text: `[SYSTEM] Domain Controller for ${currentScenario.network.domain}` },
      { type: 'info', text: `[SYSTEM] IP Address: ${currentScenario.network.target.ip}` },
      { type: 'info', text: '[SYSTEM] All services running normally' },
      { type: 'info', text: '' }
    ]);
    
    setDefenseHistory([
      { type: 'info', text: `[DEFENSE] Blue Team Console Online. Monitoring Domain: ${currentScenario.network.domain}` },
      { type: 'info', text: "[DEFENSE] Active Policy: Strong Password Policy, NTLM Enabled (Legacy Support)" },
      { type: 'info', text: "" },
    ]);
  };
  
  // ========== RESOLVE LOOT VARIABLES ==========
  
  const resolveLootVariables = (commandString) => {
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
        setAttackerHistory(prev => [
          ...prev,
          { type: 'error', text: `[!] Credential not found: ${usernameToFind}` },
          { type: 'info', text: `[*] Available credentials: ${credentialInventory.map(c => c.username).join(', ') || 'None'}` }
        ]);
        return null;
      }
    }
    
    return resolvedCmd;
  };
  
  // ========== PROCESS STEP OUTPUT ==========
  
  const processStepOutput = async (step) => {
    if (!mountedRef.current) return;
    
    const { attackerOutput, serverOutput, delay, lootToGrant, enterSubShell } = step;
    
    try {
      setHighlightedMachine('target');
      setHighlightedArrow('attacker-to-target');
      
      // Process attacker output
      if (attackerOutput && mountedRef.current) {
        for (let i = 0; i < attackerOutput.length; i++) {
          if (!mountedRef.current) break;
          
          await new Promise(resolve => setTimeout(resolve, delay || 100));
          
          if (mountedRef.current) {
            setAttackerHistory(prev => [
              ...prev,
              { type: 'output', text: attackerOutput[i] }
            ]);
          }
        }
      }
      
      // Process server output
      if (serverOutput && mountedRef.current) {
        for (let i = 0; i < serverOutput.length; i++) {
          if (!mountedRef.current) break;
          
          await new Promise(resolve => setTimeout(resolve, delay || 100));
          
          if (mountedRef.current) {
            setServerHistory(prev => [
              ...prev,
              { type: 'log', text: serverOutput[i] }
            ]);
          }
        }
      }
      
      // Grant loot
      if (lootToGrant && mountedRef.current) {
        if (lootToGrant.files) {
          setSimulatedFileSystem(prev => ({ ...prev, ...lootToGrant.files }));
        }
        if (lootToGrant.creds) {
          lootToGrant.creds.forEach(cred => {
            harvestCredential(cred.type, cred.username, cred.secret);
          });
        }
        if (lootToGrant.download) {
          lootToGrant.download.forEach(file => {
            setSimulatedFiles(prev => [...prev, file]);
          });
        }
      }
      
      // Add defense alert
      const defenseAlert = getDefenseAlertForStep(step.id, scenarioId);
      if (defenseAlert && mountedRef.current) {
        setDefenseHistory(prev => [
          ...prev,
          { type: 'error', text: defenseAlert }
        ]);
      }
      
      // Clear highlights
      if (mountedRef.current) {
        setHighlightedMachine(null);
        setHighlightedArrow(null);
      }
      
      // Handle sub-shell or progression
      if (enterSubShell && mountedRef.current) {
        setSubShell(enterSubShell);
        setAttackerHistory(prev => [
          ...prev,
          { type: 'sub-prompt', text: getSubShellPrompt(enterSubShell) }
        ]);
        processingRef.current = false;
        setIsProcessing(false);
      } else if (mountedRef.current) {
        processingRef.current = false;
        setIsProcessing(false);
        
        if (currentStep === currentScenario.steps.length - 1) {
          completeScenario();
        } else {
          setCurrentStep(prev => prev + 1);
        }
      }
    } catch (error) {
      console.error('Error processing step output:', error);
      if (mountedRef.current) {
        processingRef.current = false;
        setIsProcessing(false);
      }
    }
  };
  
  // ========== PROCESS SUB-COMMAND OUTPUT ==========
  
  const processSubCommandOutput = async (subCommand) => {
    if (!mountedRef.current) return;
    
    const { attackerOutput, serverOutput, delay, lootToGrant } = subCommand;
    
    try {
      if (attackerOutput && mountedRef.current) {
        for (let i = 0; i < attackerOutput.length; i++) {
          if (!mountedRef.current) break;
          
          await new Promise(resolve => setTimeout(resolve, delay || 100));
          
          if (mountedRef.current) {
            setAttackerHistory(prev => [
              ...prev,
              { type: 'output', text: attackerOutput[i] }
            ]);
          }
        }
      }
      
      if (serverOutput && mountedRef.current) {
        for (let i = 0; i < serverOutput.length; i++) {
          if (!mountedRef.current) break;
          
          await new Promise(resolve => setTimeout(resolve, delay || 100));
          
          if (mountedRef.current) {
            setServerHistory(prev => [
              ...prev,
              { type: 'log', text: serverOutput[i] }
            ]);
          }
        }
      }
      
      if (lootToGrant && mountedRef.current) {
        if (lootToGrant.files) {
          setSimulatedFileSystem(prev => ({ ...prev, ...lootToGrant.files }));
        }
        if (lootToGrant.creds) {
          lootToGrant.creds.forEach(cred => {
            harvestCredential(cred.type, cred.username, cred.secret);
          });
        }
        if (lootToGrant.download) {
          lootToGrant.download.forEach(file => {
            setSimulatedFiles(prev => [...prev, file]);
          });
        }
      }
      
      if (mountedRef.current) {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'sub-prompt', text: getSubShellPrompt(subShell) }
        ]);
        
        processingRef.current = false;
        setIsProcessing(false);
      }
    } catch (error) {
      console.error('Error processing sub-command output:', error);
      if (mountedRef.current) {
        processingRef.current = false;
        setIsProcessing(false);
      }
    }
  };
  
  // ========== COMPLETE SCENARIO ==========
  
  const completeScenario = useCallback(() => {
    if (isMissionCompleted) return;
    
    setIsMissionCompleted(true);
    
    const timeSpent = Math.round((Date.now() - scenarioStats.startTime) / 1000);
    const scoreEarned = calculateScenarioScore(scenarioStats.wrongAttempts, scenarioStats.hintsUsed);
    
    let updatedProgress = { ...progress };
    updatedProgress = addScenarioCompletion(updatedProgress, scenarioId, {
      wrongAttempts: scenarioStats.wrongAttempts,
      hintsUsed: scenarioStats.hintsUsed,
      timeSpent
    });
    
    const previousUnlocked = getUnlockedAchievements(progress);
    const newUnlocked = getUnlockedAchievements(updatedProgress);
    const justUnlocked = newUnlocked.filter(id => !previousUnlocked.includes(id));
    
    justUnlocked.forEach(id => {
      updatedProgress = unlockAchievement(updatedProgress, id);
    });
    
    setProgress(updatedProgress);
    saveProgress(updatedProgress);
    
    const newAchievementObjects = justUnlocked
      .map(id => achievements.find(a => a.id === id))
      .filter(Boolean);
    
    setNewAchievements(newAchievementObjects);
    setShowMissionDebrief(true);
    
    setScenarioStats(prev => ({
      ...prev,
      scoreEarned,
      stepsCompleted: currentScenario.steps.length,
      timeSpent: `${Math.floor(timeSpent / 60)}m ${timeSpent % 60}s`
    }));
  }, [isMissionCompleted, scenarioStats, progress, scenarioId, currentScenario]);
  
  // ========== HANDLE COMMAND SUBMIT ==========
  
  const handleCommandSubmit = (command) => {
    // Validate command
    const validation = validateCommand(command);
    if (!validation.valid) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'error', text: `[!] ${validation.error}` }
      ]);
      return;
    }
    
    const normalizedInput = normalizeCommand(validation.command);
    
    // Add to command history
    if (validation.command && !commandHistory.includes(validation.command)) {
      setCommandHistory(prev => [...prev, validation.command].slice(-MAX_COMMAND_HISTORY));
    }
    setHistoryIndex(-1);
    
    // Display command in terminal
    if (subShell) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'command', text: `${getSubShellPrompt(subShell)}${validation.command}` }
      ]);
    } else {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'command', text: `root@${currentScenario.network.attacker.hostname}:~# ${validation.command}` }
      ]);
    }
    
    // Handle sub-shell commands
    if (subShell) {
      const step = currentScenario.steps[currentStep];
      
      // Built-in sub-shell commands
      if (normalizedInput === 'help') {
        const commands = step.subShellCommands?.[subShell]?.commands || [];
        setAttackerHistory(prev => [
          ...prev,
          { type: 'info', text: `Available ${subShell} commands:` },
          ...commands.map(c => ({ type: 'info', text: `  - ${c.expectedCommand || c.expectedCommands?.[0]}` })),
          { type: 'info', text: 'Type "exit" to leave sub-shell' }
        ]);
        return;
      }
      
      if (normalizedInput === 'exit') {
        if (step.expectedCommand === 'exit') {
          processingRef.current = true;
          setIsProcessing(true);
          processStepOutput(step);
        } else {
          setSubShell(null);
          if (subShellTimeout) clearTimeout(subShellTimeout);
          setAttackerHistory(prev => [
            ...prev,
            { type: 'system', text: 'Exiting sub-shell...' }
          ]);
        }
        return;
      }
      
      // Match sub-shell command
      const subCommands = step.subShellCommands?.[subShell]?.commands || [];
      let subMatch = null;
      
      for (const cmdData of subCommands) {
        const expectedList = Array.isArray(cmdData.expectedCommands)
          ? cmdData.expectedCommands
          : [cmdData.expectedCommand];
        
        for (const expectedCmd of expectedList) {
          if (!expectedCmd) continue;
          
          const resolvedCmd = resolveLootVariables(expectedCmd);
          if (resolvedCmd === null) return; // Loot resolution failed
          
          const matchResult = fuzzyMatchCommand(normalizedInput, resolvedCmd, tutorialMode ? 0.75 : 0.90);
          
          if (matchResult.match) {
            subMatch = cmdData;
            break;
          }
        }
        
        if (subMatch) break;
      }
      
      if (subMatch) {
        processingRef.current = true;
        setIsProcessing(true);
        processSubCommandOutput(subMatch);
      } else {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'error', text: `[!] ${subShell} error: command not recognized: "${validation.command}"` },
          { type: 'info', text: `[*] Type "help" for available commands` },
          { type: 'sub-prompt', text: getSubShellPrompt(subShell) }
        ]);
      }
      return;
    }
    
    // Handle built-in commands (ls, cat, etc.)
    if (normalizedInput === 'ls' || normalizedInput === 'dir') {
      const files = Object.keys(simulatedFileSystem);
      if (files.length === 0) {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'output', text: 'No files found.' }
        ]);
      } else {
        const fileList = files.map(file => `[File] ${file}`);
        setAttackerHistory(prev => [
          ...prev,
          { type: 'output', text: fileList.join('\n') }
        ]);
      }
      return;
    }
    
    if (normalizedInput.startsWith('cat ') || normalizedInput.startsWith('type ')) {
      const fileName = validation.command.split(' ')[1];
      const file = simulatedFileSystem[fileName?.toLowerCase()];
      if (file) {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'output', text: file.content }
        ]);
      } else {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'error', text: `[!] File not found: ${fileName}` }
        ]);
      }
      return;
    }
    
    // Match scenario step command
    const step = currentScenario.steps[currentStep];
    if (!step) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'error', text: '[!] Simulation complete. Select a new scenario to restart.' }
      ]);
      return;
    }
    
    const expectedList = Array.isArray(step.expectedCommands) && step.expectedCommands.length > 0
      ? step.expectedCommands
      : step.expectedCommand
        ? [step.expectedCommand]
        : [];
    
    let isMatch = false;
    let bestSuggestion = null;
    
    for (const expectedCmd of expectedList) {
      if (!expectedCmd) continue;
      
      const resolvedCmd = resolveLootVariables(expectedCmd);
      if (resolvedCmd === null) return;
      
      const matchResult = fuzzyMatchCommand(normalizedInput, resolvedCmd, tutorialMode ? 0.75 : 0.90);
      
      if (matchResult.match) {
        isMatch = true;
        break;
      } else if (matchResult.suggestion && !bestSuggestion) {
        bestSuggestion = matchResult.suggestion;
      }
    }
    
    if (!isMatch) {
      setScenarioStats(prev => ({ ...prev, wrongAttempts: prev.wrongAttempts + 1 }));
      
      // Check common mistakes
      const mistakes = Array.isArray(step.commonMistakes) ? step.commonMistakes : [];
      let handledMistake = false;
      
      for (const mistake of mistakes) {
        if (!mistake || !mistake.pattern) continue;
        try {
          const regex = new RegExp(mistake.pattern, 'i');
          if (regex.test(validation.command)) {
            handledMistake = true;
            setAttackerHistory(prev => [
              ...prev,
              { type: 'error', text: `[!] ${mistake.message}` }
            ]);
            break;
          }
        } catch (err) {
          console.error('Regex error:', err);
        }
      }
      
      if (!handledMistake) {
        if (tutorialMode) {
          setAttackerHistory(prev => [
            ...prev,
            { type: 'error', text: `[!] Not quite right. Hint: ${step.hintShort || 'Try again'}` }
          ]);
        } else {
          setAttackerHistory(prev => [
            ...prev,
            { type: 'error', text: `[!] Command not recognized or incorrect for this step.` },
            ...(bestSuggestion ? [{ type: 'info', text: `[*] Did you mean: ${bestSuggestion}?` }] : [])
          ]);
        }
      }
      return;
    }
    
    // Command matched - process step
    processingRef.current = true;
    setIsProcessing(true);
    processStepOutput(step);
  };
  
  // ========== SHOW HINT ==========
  
  const handleShowHint = (stepIndex) => {
    const step = currentScenario.steps[stepIndex];
    if (!step) return;
    
    const hintLevel = hintsShown[stepIndex] || 0;
    if (hintLevel === 0) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Hint: ${step.hintShort || 'No hint available'}` }
      ]);
      setHintsShown(prev => ({ ...prev, [stepIndex]: 1 }));
      setScenarioStats(prev => ({ ...prev, hintsUsed: prev.hintsUsed + 1 }));
    } else if (hintLevel === 1) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Full Hint: ${step.hintFull || 'No additional hint available'}` }
      ]);
      setHintsShown(prev => ({ ...prev, [stepIndex]: 2 }));
    }
  };
  
  // ========== HANDLE QUIZ COMPLETE ==========
  
  const handleQuizComplete = (quizStats) => {
    let updatedProgress = { ...progress };
    updatedProgress = addQuizScore(
      updatedProgress,
      scenarioId,
      quizStats.score,
      quizStats.correctAnswers,
      quizStats.totalQuestions
    );
    setProgress(updatedProgress);
    saveProgress(updatedProgress);
    setShowQuiz(false);
  };
  
  // ========== CLOSE BRIEFING ==========
  
  const handleCloseBriefing = () => {
    setShowMissionBriefing(false);
    safeSetItem(briefingStorageKey, true);
  };
  
  // ========== COMPROMISED NODES ==========
  
  const compromisedNodes = useMemo(() => {
    const nodes = new Set();
    nodes.add('attacker');
    
    const compromiseMap = {
      'pass-the-hash': ['target'],
      'dcsync': ['dc'],
      'golden-ticket': ['dc'],
      'gpo-abuse': ['dc'],
      'adcs-esc1': ['dc'],
      'trust-abuse': ['dc'],
      'credential-dumping-advanced': ['target', 'dc']
    };
    
    if (progress && progress.scenariosCompleted) {
      progress.scenariosCompleted.forEach(id => {
        if (compromiseMap[id]) {
          compromiseMap[id].forEach(node => nodes.add(node));
        }
      });
    }
    
    return Array.from(nodes);
  }, [progress]);
  
  // ========== RENDER ==========
  
  return (
    <div className="simulator-container full-page relative">
      {/* Loading Overlay */}
      {isLoadingScenario && (
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="text-white text-center">
            <Activity className="w-8 h-8 animate-spin mx-auto mb-2 text-[#2D9CDB]" />
            <p className="text-sm">Loading scenario...</p>
          </div>
        </div>
      )}
      
      <div 
        style={{
          '--terminal-text': customTheme.terminalText || '',
          '--accent-color': customTheme.accentColor || '',
          '--terminal-bg': customTheme.terminalBg || '',
        }}
        className="h-screen w-full flex flex-col overflow-hidden"
      >
        {/* Header */}
        <Header 
          title={currentScenario.title}
          currentStep={currentStep + 1}
          totalSteps={currentScenario.steps.length}
          score={progress.totalScore}
          rank={progress.rank}
          onOpenSettings={() => setIsSettingsOpen(true)}
          scenarioId={scenarioId}
          progress={progress}
        />
        
        {/* Main Content */}
        <main className="flex-1 flex overflow-hidden min-h-0">
          <ResizablePanelGroup
            direction="horizontal"
            className="w-full"
          >
            {/* Left Panel: Guide */}
            <ResizablePanel defaultSize={30} minSize={20}>
              <GuidePanel 
                scenario={currentScenario}
                currentStep={currentStep}
                tutorialMode={tutorialMode}
                onTutorialToggle={() => {
                  const newTutorialMode = !tutorialMode;
                  setTutorialMode(newTutorialMode);
                  setProgress(prev => ({ ...prev, tutorialMode: newTutorialMode }));
                }}
                highlightedMachine={highlightedMachine}
                highlightedArrow={highlightedArrow}
                onShowBriefing={() => setShowMissionBriefing(true)}
                progress={progress}
                onNodeClick={setInspectingNode}
              />
            </ResizablePanel>

            <ResizableHandle withHandle />

            {/* Right Panel: Terminal */}
            <ResizablePanel defaultSize={70} minSize={30}>
              <AttackerPanel 
                history={attackerHistory}
                onCommandSubmit={handleCommandSubmit}
                isProcessing={isProcessing}
                network={currentScenario.network}
                activeMachine={activeMachine}
                onMachineChange={setActiveMachine}
                serverHistory={serverHistory}
                defenseHistory={defenseHistory}
                credentialInventory={credentialInventory}
                simulatedFiles={simulatedFiles}
                onShowHint={() => handleShowHint(currentStep)}
                hintsAvailable={currentStep < currentScenario.steps.length}
                subShell={subShell}
              />
            </ResizablePanel>
          </ResizablePanelGroup>
        </main>

        {/* Modals */}
        <MissionModal
          isOpen={showMissionBriefing}
          onClose={handleCloseBriefing}
          type="briefing"
          scenario={currentScenario}
        />
        
        <MissionModal
          isOpen={showMissionDebrief}
          onClose={() => {
            setShowMissionDebrief(false);
            if (quizMap[scenarioId]) {
              setShowQuiz(true);
            }
          }}
          type="debrief"
          scenario={currentScenario}
          stats={scenarioStats}
          newAchievements={newAchievements}
        />
        
        {showQuiz && (
          <div className="modal-backdrop">
            <div className="modal-content quiz-modal">
              <QuizPanel
                quiz={quizMap[scenarioId]}
                onComplete={handleQuizComplete}
                onSkip={() => setShowQuiz(false)}
              />
            </div>
          </div>
        )}
        
        {showAchievements && (
          <div className="modal-backdrop">
            <div className="modal-content achievements-modal">
              <AchievementsPanel
                unlockedAchievements={progress.unlockedAchievements}
                newAchievements={newAchievements}
              />
            </div>
          </div>
        )}
        
        <SettingsModal 
          isOpen={isSettingsOpen}
          onClose={() => setIsSettingsOpen(false)}
          currentTheme={customTheme}
          onUpdateTheme={handleUpdateTheme}
        />
        
        {/* Machine Info Sheet */}
        <MachineInfoSheet
          nodeName={inspectingNode}
          network={currentScenario.network}
          compromisedNodes={compromisedNodes}
          isOpen={!!inspectingNode}
          onClose={() => setInspectingNode(null)}
        />
        
        {/* Debug Panel */}
        {debugMode && (
          <div className="fixed bottom-4 right-4 bg-black/95 text-xs text-green-400 p-4 rounded-lg font-mono max-w-md z-50 border border-green-500/30">
            <div className="text-white font-bold mb-2">🐛 DEBUG MODE</div>
            <div>Scenario: {scenarioId}</div>
            <div>Step: {currentStep + 1}/{currentScenario?.steps.length}</div>
            <div>Processing: {isProcessing.toString()}</div>
            <div>SubShell: {subShell || 'none'}</div>
            <div>History: {attackerHistory.length} lines</div>
            <div>Loot: {credentialInventory.length} creds, {simulatedFiles.length} files</div>
            <div>Wrong Attempts: {scenarioStats.wrongAttempts}</div>
            <div>Hints Used: {scenarioStats.hintsUsed}</div>
            <div className="mt-2 text-yellow-400">Press Ctrl+Shift+D to toggle</div>
          </div>
        )}
      </div>
    </div>
  );
}
