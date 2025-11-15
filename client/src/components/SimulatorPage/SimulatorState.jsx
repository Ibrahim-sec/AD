// client/src/components/SimulatorPage/SimulatorState.jsx

import { useState, useEffect } from 'react';
import { COMMAND_HISTORY_KEY, MAX_COMMAND_HISTORY } from '@/lib/simulator/constants';

export const useSimulatorState = (scenarioId) => {
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
  const [customTheme, setCustomTheme] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('terminal_theme')) || {};
    } catch (e) {
      return {};
    }
  });
  
  // Game state
  const [scenarioStats, setScenarioStats] = useState({
    wrongAttempts: 0,
    hintsUsed: 0,
    startTime: Date.now()
  });
  const [hintsShown, setHintsShown] = useState({});
  const [tutorialMode, setTutorialMode] = useState(true);
  
  // Command history state
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  
  // Debug mode
  const [debugMode, setDebugMode] = useState(false);
  
  // Processed steps tracker
  const [processedSteps, setProcessedSteps] = useState(new Set());
  
  // Load command history from localStorage
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
  
  // Save command history to localStorage
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
  
  // Debug mode toggle
  useEffect(() => {
    const handleKeyPress = (e) => {
      if (e.ctrlKey && e.shiftKey && e.key === 'D') {
        setDebugMode(prev => !prev);
      }
    };
    
    window.addEventListener('keydown', handleKeyPress);
    return () => window.removeEventListener('keydown', handleKeyPress);
  }, []);

  const handleUpdateTheme = (newTheme) => {
    setCustomTheme(newTheme);
    localStorage.setItem('terminal_theme', JSON.stringify(newTheme));
  };

  const setState = (updater) => {
    if (updater.credentialInventory !== undefined) {
      setCredentialInventory(updater.credentialInventory);
    }
    if (updater.simulatedFiles !== undefined) {
      setSimulatedFiles(updater.simulatedFiles);
    }
    if (updater.simulatedFileSystem !== undefined) {
      setSimulatedFileSystem(updater.simulatedFileSystem);
    }
  };

  return {
    // Core state
    currentStep,
    setCurrentStep,
    attackerHistory,
    setAttackerHistory,
    serverHistory,
    setServerHistory,
    defenseHistory,
    setDefenseHistory,
    isProcessing,
    setIsProcessing,
    activeMachine,
    setActiveMachine,
    highlightedMachine,
    setHighlightedMachine,
    highlightedArrow,
    setHighlightedArrow,
    
    // Loot state
    credentialInventory,
    setCredentialInventory,
    simulatedFiles,
    setSimulatedFiles,
    simulatedFileSystem,
    setSimulatedFileSystem,
    
    // Sub-shell state
    subShell,
    setSubShell,
    subShellTimeout,
    setSubShellTimeout,
    
    // Settings
    customTheme,
    handleUpdateTheme,
    
    // Game state
    scenarioStats,
    setScenarioStats,
    hintsShown,
    setHintsShown,
    tutorialMode,
    setTutorialMode,
    
    // Command history
    commandHistory,
    setCommandHistory,
    historyIndex,
    setHistoryIndex,
    
    // Debug
    debugMode,
    
    // Processed steps
    processedSteps,
    setProcessedSteps,
    
    // Utility
    setState
  };
};
