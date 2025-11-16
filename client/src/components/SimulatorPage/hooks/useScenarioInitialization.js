// client/src/components/SimulatorPage/hooks/useScenarioInitialization.js

import { useEffect, useState } from 'react';
import { safeGetItem } from '@/lib/safeStorage';
import { getInitialHistories } from '@/lib/simulator/constants';

export const useScenarioInitialization = (scenarioId, currentScenario, progress) => {
  const [isLoadingScenario, setIsLoadingScenario] = useState(false);
  const briefingStorageKey = `hasSeenBriefing_${scenarioId}`;
  
  const [showMissionBriefing, setShowMissionBriefing] = useState(() => {
    const hasSeen = safeGetItem(briefingStorageKey, null);
    return hasSeen !== true;
  });

  const resetScenario = () => {
    const histories = getInitialHistories(currentScenario);
    
    // Load global inventory into session
    const globalCreds = progress?.globalInventory?.credentials || [];
    const globalFiles = progress?.globalInventory?.files || [];
    
    return {
      currentStep: 0,
      activeMachine: 'attacker',
      highlightedMachine: null,
      highlightedArrow: null,
      subShell: null,
      attackerHistory: histories.attacker,
      serverHistory: histories.server,
      defenseHistory: histories.defense,
      credentialInventory: globalCreds,  // Start with global creds
      simulatedFiles: globalFiles,        // Start with global files
      simulatedFileSystem: {},
      inspectingNode: null,
      isMissionCompleted: false,
      processedSteps: new Set(),
      scenarioStats: {
        wrongAttempts: 0,
        hintsUsed: 0,
        startTime: Date.now()
      },
      hintsShown: {}
    };
  };

  // Initialize scenario on mount or scenario change
  useEffect(() => {
    setIsLoadingScenario(true);
    
    const hasSeen = safeGetItem(briefingStorageKey, null);
    setShowMissionBriefing(hasSeen !== true);
    
    // Smooth loading transition
    const timer = setTimeout(() => {
      setIsLoadingScenario(false);
    }, 300);
    
    return () => clearTimeout(timer);
  }, [scenarioId, briefingStorageKey]);

  return {
    isLoadingScenario,
    showMissionBriefing,
    setShowMissionBriefing,
    briefingStorageKey,
    resetScenario
  };
};
