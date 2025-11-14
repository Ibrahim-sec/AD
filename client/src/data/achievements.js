// client/src/data/achievements.js

/**
 * Achievement system with validation and efficient unlock checking
 */

export const achievements = [
  {
    id: 'first-blood',
    name: 'First Blood',
    description: 'Complete your first scenario',
    icon: '🎯',
    rarity: 'common',
    condition: (progress) => progress.scenariosCompleted.length >= 1
  },
  {
    id: 'getting-started',
    name: 'Getting Started',
    description: 'Complete 3 scenarios',
    icon: '🚀',
    rarity: 'common',
    condition: (progress) => progress.scenariosCompleted.length >= 3
  },
  {
    id: 'on-a-roll',
    name: 'On a Roll',
    description: 'Complete 5 scenarios',
    icon: '🔥',
    rarity: 'uncommon',
    condition: (progress) => progress.scenariosCompleted.length >= 5
  },
  {
    id: 'dedicated-learner',
    name: 'Dedicated Learner',
    description: 'Complete 10 scenarios',
    icon: '📚',
    rarity: 'rare',
    condition: (progress) => progress.scenariosCompleted.length >= 10
  },
  {
    id: 'master-hacker',
    name: 'Master Hacker',
    description: 'Complete all 17 scenarios',
    icon: '👑',
    rarity: 'legendary',
    condition: (progress) => progress.scenariosCompleted.length >= 17
  },
  {
    id: 'perfect-score',
    name: 'Perfect Score',
    description: 'Complete a scenario with no hints and no wrong attempts',
    icon: '⭐',
    rarity: 'rare',
    condition: (progress) => {
      return Object.values(progress.scenarioStats || {}).some(
        stat => stat.wrongAttempts === 0 && stat.hintsUsed === 0
      );
    }
  },
  {
    id: 'speed-demon',
    name: 'Speed Demon',
    description: 'Complete any scenario in under 5 minutes',
    icon: '⚡',
    rarity: 'rare',
    condition: (progress) => {
      return Object.values(progress.scenarioStats || {}).some(
        stat => stat.timeSpent && stat.timeSpent < 300
      );
    }
  },
  {
    id: 'quiz-master',
    name: 'Quiz Master',
    description: 'Get 100% on any quiz',
    icon: '🎓',
    rarity: 'uncommon',
    condition: (progress) => {
      return Object.values(progress.quizScores || {}).some(
        quiz => quiz.percentage === 100
      );
    }
  },
  {
    id: 'persistent',
    name: 'Persistent',
    description: 'Complete a scenario after 10 or more wrong attempts',
    icon: '💪',
    rarity: 'uncommon',
    condition: (progress) => {
      return Object.values(progress.scenarioStats || {}).some(
        stat => stat.wrongAttempts >= 10
      );
    }
  },
  {
    id: 'no-hints-needed',
    name: 'No Hints Needed',
    description: 'Complete 5 scenarios without using any hints',
    icon: '🧠',
    rarity: 'rare',
    condition: (progress) => {
      const noHintScenarios = Object.values(progress.scenarioStats || {}).filter(
        stat => stat.hintsUsed === 0
      );
      return noHintScenarios.length >= 5;
    }
  },
  {
    id: 'hundred-points',
    name: 'Century Club',
    description: 'Reach 100 total points',
    icon: '💯',
    rarity: 'uncommon',
    condition: (progress) => progress.totalScore >= 100
  },
  {
    id: 'five-hundred-points',
    name: 'Elite Status',
    description: 'Reach 500 total points',
    icon: '🏆',
    rarity: 'epic',
    condition: (progress) => progress.totalScore >= 500
  },
  {
    id: 'credential-collector',
    name: 'Credential Collector',
    description: 'Complete all credential dumping scenarios',
    icon: '🔑',
    rarity: 'rare',
    condition: (progress) => {
      const credScenarios = ['kerberoasting', 'asrep-roasting', 'dcsync', 'credential-dumping-advanced'];
      return credScenarios.every(id => progress.scenariosCompleted.includes(id));
    }
  },
  {
    id: 'domain-dominator',
    name: 'Domain Dominator',
    description: 'Complete DCSync and Golden Ticket scenarios',
    icon: '👑',
    rarity: 'epic',
    condition: (progress) => {
      return ['dcsync', 'golden-ticket'].every(id => progress.scenariosCompleted.includes(id));
    }
  },
  {
    id: 'certificate-authority',
    name: 'Certificate Authority',
    description: 'Complete the ADCS ESC1 scenario',
    icon: '📜',
    rarity: 'rare',
    condition: (progress) => progress.scenariosCompleted.includes('adcs-esc1')
  },
  {
    id: 'forest-ranger',
    name: 'Forest Ranger',
    description: 'Complete the domain trust exploitation scenario',
    icon: '🌲',
    rarity: 'epic',
    condition: (progress) => progress.scenariosCompleted.includes('trust-abuse')
  },
  {
    id: 'gpo-guru',
    name: 'GPO Guru',
    description: 'Complete the Group Policy abuse scenario',
    icon: '⚙️',
    rarity: 'rare',
    condition: (progress) => progress.scenariosCompleted.includes('gpo-abuse')
  },
  {
    id: 'delegation-master',
    name: 'Delegation Master',
    description: 'Complete the RBCD scenario',
    icon: '🔄',
    rarity: 'rare',
    condition: (progress) => progress.scenariosCompleted.includes('rbcd-attack')
  },
  {
    id: 'triple-threat',
    name: 'Triple Threat',
    description: 'Complete 3 scenarios in one session',
    icon: '🎯',
    rarity: 'uncommon',
    condition: (progress) => {
      // This would need session tracking - simplified here
      return progress.scenariosCompleted.length >= 3;
    }
  },
  {
    id: 'red-team-operator',
    name: 'Red Team Operator',
    description: 'Reach Red Team Operator rank',
    icon: '🎖️',
    rarity: 'epic',
    condition: (progress) => progress.rank === 'Red Team Operator' || progress.rank === 'Elite Hacker' || progress.rank === 'Cyber Ninja'
  }
];

/**
 * Get unlocked achievements for current progress
 * Optimized to only check conditions once
 */
export const getUnlockedAchievements = (progress) => {
  if (!progress || typeof progress !== 'object') {
    return [];
  }
  
  try {
    return achievements
      .filter(achievement => {
        try {
          return achievement.condition(progress);
        } catch (error) {
          console.error(`Error checking achievement ${achievement.id}:`, error);
          return false;
        }
      })
      .map(achievement => achievement.id);
  } catch (error) {
    console.error('Error getting unlocked achievements:', error);
    return [];
  }
};

/**
 * Get achievement by ID
 */
export const getAchievementById = (id) => {
  return achievements.find(a => a.id === id);
};

/**
 * Get achievements by rarity
 */
export const getAchievementsByRarity = (rarity) => {
  return achievements.filter(a => a.rarity === rarity);
};

/**
 * Get achievement progress
 */
export const getAchievementProgress = (progress) => {
  const unlocked = getUnlockedAchievements(progress);
  const total = achievements.length;
  const percentage = Math.round((unlocked.length / total) * 100);
  
  const byRarity = {
    common: 0,
    uncommon: 0,
    rare: 0,
    epic: 0,
    legendary: 0
  };
  
  unlocked.forEach(id => {
    const achievement = getAchievementById(id);
    if (achievement) {
      byRarity[achievement.rarity]++;
    }
  });
  
  return {
    unlocked: unlocked.length,
    total,
    percentage,
    byRarity,
    remaining: total - unlocked.length
  };
};

/**
 * Get next achievable achievements
 */
export const getNextAchievements = (progress, limit = 3) => {
  const unlocked = new Set(getUnlockedAchievements(progress));
  
  return achievements
    .filter(a => !unlocked.has(a.id))
    .slice(0, limit);
};

/**
 * Check if achievement is unlocked
 */
export const isAchievementUnlocked = (progress, achievementId) => {
  const achievement = getAchievementById(achievementId);
  if (!achievement) return false;
  
  try {
    return achievement.condition(progress);
  } catch (error) {
    console.error(`Error checking achievement ${achievementId}:`, error);
    return false;
  }
};
