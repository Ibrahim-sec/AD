// client/src/components/SimulatorPage/hooks/useScenarioCompletion.js

import { useState, useCallback, useRef } from 'react';
import { calculateScenarioScore } from '@/lib/simulator/constants';
import { 
  saveProgress, 
  addScenarioCompletion,
  unlockAchievement
} from '@/lib/progressTracker';
import { 
  completeCampaignScenario, 
  isCampaignComplete, 
  completeCampaign 
} from '@/lib/campaignManager';
import { getUnlockableScenarios } from '@/lib/scenarioManager';
import { achievements, getUnlockedAchievements } from '@/data/achievements';

export const useScenarioCompletion = ({
  scenarioId,
  currentScenario,
  progress,
  setProgress,
  scenarioStats
}) => {
  const [isMissionCompleted, setIsMissionCompleted] = useState(false);
  const [newAchievements, setNewAchievements] = useState([]);
  const [showMissionDebrief, setShowMissionDebrief] = useState(false);
  const [completionStats, setCompletionStats] = useState(null);
  
  const completionInProgressRef = useRef(false);

  const completeScenario = useCallback((currentStats) => {
    if (completionInProgressRef.current || isMissionCompleted) {
      console.log('Completion already in progress or completed, skipping...');
      return;
    }
    
    completionInProgressRef.current = true;
    
    const statsToUse = currentStats || scenarioStats;
    
    setIsMissionCompleted(true);
    
    const timeSpent = Math.round((Date.now() - statsToUse.startTime) / 1000);
    const scoreEarned = calculateScenarioScore(
      statsToUse.wrongAttempts, 
      statsToUse.hintsUsed
    );
    
    const finalStats = {
      scoreEarned,
      stepsCompleted: currentScenario.steps.length,
      timeSpent: `${Math.floor(timeSpent / 60)}m ${timeSpent % 60}s`,
      wrongAttempts: statsToUse.wrongAttempts,
      hintsUsed: statsToUse.hintsUsed
    };
    
    setCompletionStats(finalStats);
    
    let updatedProgress = { ...progress };
    updatedProgress = addScenarioCompletion(updatedProgress, scenarioId, {
      wrongAttempts: statsToUse.wrongAttempts,
      hintsUsed: statsToUse.hintsUsed,
      timeSpent
    });
    
    // Campaign integration
    if (updatedProgress.activeCampaign) {
      updatedProgress = completeCampaignScenario(updatedProgress, scenarioId, {
        wrongAttempts: statsToUse.wrongAttempts,
        hintsUsed: statsToUse.hintsUsed,
        timeSpent
      });
      
      if (isCampaignComplete(updatedProgress)) {
        updatedProgress = completeCampaign(updatedProgress);
      }
    }
    
    // Check for unlocked scenarios
    const unlockedScenarios = getUnlockableScenarios(updatedProgress, scenarioId);
    if (unlockedScenarios.length > 0) {
      updatedProgress.recentlyUnlocked = unlockedScenarios.map(s => s.id);
    }
    
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
    
    return finalStats;
  }, [
    isMissionCompleted,
    scenarioStats,
    progress,
    scenarioId,
    currentScenario,
    setProgress
  ]);

  const resetCompletion = useCallback(() => {
    setIsMissionCompleted(false);
    completionInProgressRef.current = false;
    setCompletionStats(null);
    setNewAchievements([]);
    setShowMissionDebrief(false);
  }, []);

  return {
    isMissionCompleted,
    newAchievements,
    showMissionDebrief,
    setShowMissionDebrief,
    completeScenario,
    completionStats,
    resetCompletion
  };
};
