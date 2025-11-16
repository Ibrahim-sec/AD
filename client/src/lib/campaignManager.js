// client/src/lib/campaignManager.js

import { campaigns } from '@/data/campaigns/index.js';
import { saveProgress, addScenarioCompletion } from './progressTracker';

/**
 * Start a new campaign
 */
export const startCampaign = (progress, campaignId) => {
  const campaign = campaigns[campaignId];
  
  if (!campaign) {
    console.error(`Campaign not found: ${campaignId}`);
    return progress;
  }
  
  const updatedProgress = {
    ...progress,
    activeCampaign: {
      id: campaignId,
      startedAt: Date.now(),
      currentScenarioIndex: 0,
      completedScenarios: [],
      campaignStats: {
        totalTime: 0,
        wrongAttempts: 0,
        hintsUsed: 0
      }
    }
  };
  
  saveProgress(updatedProgress);
  return updatedProgress;
};

/**
 * Get current campaign scenario
 */
export const getCurrentCampaignScenario = (progress) => {
  if (!progress.activeCampaign) return null;
  
  const campaign = campaigns[progress.activeCampaign.id];
  if (!campaign) return null;
  
  const scenarioIndex = progress.activeCampaign.currentScenarioIndex;
  if (scenarioIndex >= campaign.scenarios.length) return null;
  
  return campaign.scenarios[scenarioIndex];
};

/**
 * Get next campaign scenario
 */
export const getNextCampaignScenario = (progress) => {
  if (!progress.activeCampaign) return null;
  
  const campaign = campaigns[progress.activeCampaign.id];
  if (!campaign) return null;
  
  const nextIndex = progress.activeCampaign.currentScenarioIndex + 1;
  if (nextIndex >= campaign.scenarios.length) return null;
  
  return campaign.scenarios[nextIndex];
};

/**
 * Complete a scenario within a campaign
 */
export const completeCampaignScenario = (progress, scenarioId, stats) => {
  let updatedProgress = { ...progress };
  
  // Update regular scenario completion
  updatedProgress = addScenarioCompletion(updatedProgress, scenarioId, stats);
  
  // Update campaign progress if in campaign mode
  if (updatedProgress.activeCampaign) {
    const campaign = campaigns[updatedProgress.activeCampaign.id];
    const currentIndex = updatedProgress.activeCampaign.currentScenarioIndex;
    
    // Verify this is the correct scenario
    if (campaign.scenarios[currentIndex]?.id === scenarioId) {
      updatedProgress.activeCampaign = {
        ...updatedProgress.activeCampaign,
        currentScenarioIndex: currentIndex + 1,
        completedScenarios: [
          ...updatedProgress.activeCampaign.completedScenarios,
          scenarioId
        ],
        campaignStats: {
          totalTime: updatedProgress.activeCampaign.campaignStats.totalTime + (stats.timeSpent || 0),
          wrongAttempts: updatedProgress.activeCampaign.campaignStats.wrongAttempts + (stats.wrongAttempts || 0),
          hintsUsed: updatedProgress.activeCampaign.campaignStats.hintsUsed + (stats.hintsUsed || 0)
        }
      };
    }
  }
  
  saveProgress(updatedProgress);
  return updatedProgress;
};

/**
 * Check if campaign is complete
 */
export const isCampaignComplete = (progress) => {
  if (!progress.activeCampaign) return false;
  
  const campaign = campaigns[progress.activeCampaign.id];
  if (!campaign) return false;
  
  // Check if all required scenarios are completed
  const requiredScenarios = campaign.scenarios.filter(s => s.required !== false);
  return requiredScenarios.every(s => 
    progress.activeCampaign.completedScenarios.includes(s.id)
  );
};

/**
 * Complete the entire campaign
 */
export const completeCampaign = (progress) => {
  if (!progress.activeCampaign) return progress;
  
  const campaign = campaigns[progress.activeCampaign.id];
  if (!campaign) return progress;
  
  const updatedProgress = {
    ...progress,
    completedCampaigns: [
      ...(progress.completedCampaigns || []),
      progress.activeCampaign.id
    ],
    totalScore: progress.totalScore + campaign.rewards.xp,
    unlockedAchievements: [
      ...progress.unlockedAchievements,
      ...campaign.rewards.achievements.filter(
        a => !progress.unlockedAchievements.includes(a)
      )
    ],
    activeCampaign: null
  };
  
  saveProgress(updatedProgress);
  return updatedProgress;
};

/**
 * Pause/exit campaign
 */
export const pauseCampaign = (progress) => {
  const updatedProgress = {
    ...progress,
    activeCampaign: null
  };
  
  saveProgress(updatedProgress);
  return updatedProgress;
};

/**
 * Get campaign progress percentage
 */
export const getCampaignProgress = (progress) => {
  if (!progress.activeCampaign) return 0;
  
  const campaign = campaigns[progress.activeCampaign.id];
  if (!campaign) return 0;
  
  const requiredCount = campaign.scenarios.filter(s => s.required !== false).length;
  const completedCount = progress.activeCampaign.completedScenarios.length;
  
  return Math.round((completedCount / requiredCount) * 100);
};
