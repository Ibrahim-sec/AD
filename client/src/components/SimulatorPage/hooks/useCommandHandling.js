// client/src/components/SimulatorPage/hooks/useCommandHandling.js

import { useCallback } from 'react';
import { validateCommand, isBuiltInCommand } from '@/utils/commandValidator';
import { matchAgainstMultiple } from '@/utils/commandMatcher';
import { generateErrorMessages, generateSuccessMessages } from '@/utils/commandSuggestions';
import { resolveLootVariables } from '@/lib/simulator/lootResolver';
import { getExpectedCommands, getSubShellPrompt } from '@/lib/simulator/constants';

export const useCommandHandling = ({
  currentScenario,
  currentStep,
  subShell,
  tutorialMode,
  credentialInventory,
  simulatedFileSystem,
  setAttackerHistory,
  setScenarioStats,
  processStepOutput,
  processSubCommandOutput,
  setSubShell,
  subShellTimeout
}) => {
  
  const handleBuiltInCommand = useCallback((command) => {
    const normalizedCmd = command.trim().toLowerCase();
    
    if (normalizedCmd === 'ls' || normalizedCmd === 'dir') {
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
    
    if (normalizedCmd.startsWith('cat ') || normalizedCmd.startsWith('type ')) {
      const fileName = command.split(' ')[1];
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
    
    setAttackerHistory(prev => [
      ...prev,
      { type: 'info', text: `[*] Built-in command: ${command}` }
    ]);
  }, [simulatedFileSystem, setAttackerHistory]);
  
  const handleSubShellCommand = useCallback((command) => {
    const step = currentScenario.steps[currentStep];
    const normalizedInput = command.trim().toLowerCase();
    
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
    
    const subCommands = step.subShellCommands?.[subShell]?.commands || [];
    
    for (const cmdData of subCommands) {
      const expectedList = getExpectedCommands(cmdData);
      const resolvedExpected = expectedList.map(cmd => 
        resolveLootVariables(cmd, credentialInventory, (error) => {
          setAttackerHistory(prev => [
            ...prev,
            { type: 'error', text: `[!] Credential not found: ${error.username}` },
            { type: 'info', text: `[*] Available credentials: ${error.available.join(', ') || 'None'}` }
          ]);
        })
      ).filter(Boolean);
      
      if (resolvedExpected.length === 0) continue;
      
      const matchResult = matchAgainstMultiple(command, resolvedExpected, tutorialMode);
      
      if (matchResult.match) {
        processSubCommandOutput(cmdData);
        return;
      }
    }
    
    setAttackerHistory(prev => [
      ...prev,
      { type: 'error', text: `[!] ${subShell} error: command not recognized: "${command}"` },
      { type: 'info', text: `[*] Type "help" for available commands` },
      { type: 'sub-prompt', text: getSubShellPrompt(subShell) }
    ]);
  }, [currentScenario, currentStep, subShell, tutorialMode, credentialInventory, setAttackerHistory, processStepOutput, processSubCommandOutput, setSubShell, subShellTimeout]);
  
  const handleCommandSubmit = useCallback((command) => {
    const validation = validateCommand(command);
    if (!validation.valid) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'error', text: `[!] ${validation.error}` }
      ]);
      return;
    }
    
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
      handleSubShellCommand(validation.command);
      return;
    }
    
    // Handle built-in commands
    if (isBuiltInCommand(validation.command)) {
      handleBuiltInCommand(validation.command);
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
    
    const expectedCommands = getExpectedCommands(step);
    
    if (expectedCommands.length === 0) {
      return;
    }
    
    const resolvedExpected = expectedCommands.map(cmd => 
      resolveLootVariables(cmd, credentialInventory, (error) => {
        setAttackerHistory(prev => [
          ...prev,
          { type: 'error', text: `[!] Credential not found: ${error.username}` },
          { type: 'info', text: `[*] Available credentials: ${error.available.join(', ') || 'None'}` }
        ]);
      })
    ).filter(Boolean);
    
    if (resolvedExpected.length === 0) {
      return;
    }
    
    const matchResult = matchAgainstMultiple(validation.command, resolvedExpected, tutorialMode);
    
    if (!matchResult.match) {
      setScenarioStats(prev => ({ ...prev, wrongAttempts: prev.wrongAttempts + 1 }));
      
      const errorMessages = generateErrorMessages(matchResult, validation.command, tutorialMode);
      errorMessages.forEach(msg => {
        setAttackerHistory(prev => [...prev, msg]);
      });
      
      return;
    }
    
    const successMessages = generateSuccessMessages(matchResult);
    successMessages.forEach(msg => {
      setAttackerHistory(prev => [...prev, msg]);
    });
    
    processStepOutput(step);
  }, [
    currentScenario,
    currentStep,
    subShell,
    tutorialMode,
    credentialInventory,
    setAttackerHistory,
    setScenarioStats,
    handleBuiltInCommand,
    handleSubShellCommand,
    processStepOutput
  ]);
  
  return {
    handleCommandSubmit,
    handleBuiltInCommand,
    handleSubShellCommand
  };
};
