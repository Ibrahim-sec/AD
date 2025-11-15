// client/src/components/SimulatorPage/hooks/useScenarioCompletion.js

import { useState, useCallback } from 'react';
import { calculateScenarioScore } from '@/lib/simulator/constants';
import { 
  saveProgress, 
  addScenarioCompletion,
  unlockAchievement
} from '@/lib/progressTracker';
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

  const completeScenario = useCallback((currentStats) => {
    if (isMissionCompleted) return;
    
    // Use passed stats or fallback to closure stats
    const statsToUse = currentStats || scenarioStats;
    
    setIsMissionCompleted(true);
    
    const timeSpent = Math.round((Date.now() - statsToUse.startTime) / 1000);
    const scoreEarned = calculateScenarioScore(
      statsToUse.wrongAttempts, 
      statsToUse.hintsUsed
    );
    
    let updatedProgress = { ...progress };
    updatedProgress = addScenarioCompletion(updatedProgress, scenarioId, {
      wrongAttempts: statsToUse.wrongAttempts,
      hintsUsed: statsToUse.hintsUsed,
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
    
    return {
      scoreEarned,
      stepsCompleted: currentScenario.steps.length,
      timeSpent: `${Math.floor(timeSpent / 60)}m ${timeSpent % 60}s`,
      wrongAttempts: statsToUse.wrongAttempts
    };
  }, [
    isMissionCompleted,
    scenarioStats,
    progress,
    scenarioId,
    currentScenario,
    setProgress
  ]);

  return {
    isMissionCompleted,
    newAchievements,
    showMissionDebrief,
    setShowMissionDebrief,
    completeScenario
  };
};
