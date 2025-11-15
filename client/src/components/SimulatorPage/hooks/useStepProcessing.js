// client/src/components/SimulatorPage/hooks/useStepProcessing.js

import { useRef, useCallback } from 'react';
import { getDefenseAlertForStep, getSubShellPrompt } from '@/lib/simulator/constants';
import { processLootGrant } from '@/lib/simulator/lootResolver';

export const useStepProcessing = ({
  scenarioId,
  currentScenario,
  currentStep,
  setAttackerHistory,
  setServerHistory,
  setDefenseHistory,
  setHighlightedMachine,
  setHighlightedArrow,
  setSubShell,
  setIsProcessing,
  setCurrentStep,
  setState,
  completeScenario
}) => {
  const processingRef = useRef(false);
  const mountedRef = useRef(true);

  const processStepOutput = useCallback(async (step) => {
    if (!mountedRef.current) return;
    
    const { attackerOutput, serverOutput, delay, lootToGrant, enterSubShell } = step;
    
    try {
      processingRef.current = true;
      setIsProcessing(true);
      
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
        processLootGrant(lootToGrant, null, setState);
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
  }, [
    scenarioId,
    currentScenario,
    currentStep,
    setAttackerHistory,
    setServerHistory,
    setDefenseHistory,
    setHighlightedMachine,
    setHighlightedArrow,
    setSubShell,
    setIsProcessing,
    setCurrentStep,
    setState,
    completeScenario
  ]);

  const processSubCommandOutput = useCallback(async (subCommand) => {
    if (!mountedRef.current) return;
    
    const { attackerOutput, serverOutput, delay, lootToGrant } = subCommand;
    
    try {
      processingRef.current = true;
      setIsProcessing(true);
      
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
        processLootGrant(lootToGrant, null, setState);
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
  }, [setAttackerHistory, setServerHistory, setState, setIsProcessing]);

  return {
    processStepOutput,
    processSubCommandOutput,
    processingRef,
    mountedRef
  };
};
