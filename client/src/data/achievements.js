/**
 * Achievements System
 * 
 * Defines all available achievements and unlock conditions
 */

export const achievements = [
  {
    id: 'first-blood',
    title: 'First Blood',
    description: 'Complete your first scenario',
    icon: '🎯',
    points: 10,
    condition: (progress) => progress.scenariosCompleted.length > 0
  },
  {
    id: 'bloodhound-master',
    title: 'Bloodhound Master',
    description: 'Complete BloodHound scenario without hints',
    icon: '🔍',
    points: 25,
    condition: (progress) => {
      const bh = progress.scenarioStats.find(s => s.scenarioId === 'bloodhound');
      return bh && bh.hintsUsed === 0 && bh.completed;
    }
  },
  {
    id: 'kerberoast-king',
    title: 'Kerberoast King',
    description: 'Complete Kerberoasting without hints',
    icon: '👑',
    points: 25,
    condition: (progress) => {
      const kb = progress.scenarioStats.find(s => s.scenarioId === 'kerberoasting');
      return kb && kb.hintsUsed === 0 && kb.completed;
    }
  },
  {
    id: 'no-help-needed',
    title: 'No Help Needed',
    description: 'Finish any scenario with 100% correct first-try commands',
    icon: '⭐',
    points: 30,
    condition: (progress) => {
      return progress.scenarioStats.some(s => 
        s.completed && s.wrongAttempts === 0 && s.hintsUsed === 0
      );
    }
  },
  {
    id: 'quiz-master',
    title: 'Quiz Master',
    description: 'Score 100% on any post-scenario quiz',
    icon: '🧠',
    points: 20,
    condition: (progress) => {
      return progress.quizScores.some(q => q.score === 100);
    }
  },
  {
    id: 'all-scenarios',
    title: 'Complete Arsenal',
    description: 'Complete all five attack scenarios',
    icon: '🎖️',
    points: 50,
    condition: (progress) => {
      // Updated: now there are five scenarios including DCSync
      return progress.scenariosCompleted.length === 5;
    }
  },
  {
    id: 'operator',
    title: 'Operator Rank',
    description: 'Reach Operator rank (71+ points)',
    icon: '🔴',
    points: 40,
    condition: (progress) => progress.rank === 'Operator'
  },
  {
    id: 'speedrunner',
    title: 'Speedrunner',
    description: 'Complete a scenario in under 2 minutes',
    icon: '⚡',
    points: 15,
    condition: (progress) => {
      return progress.scenarioStats.some(s => 
        s.completed && s.timeSpent < 120 // 120 seconds in seconds
      );
    }
  }
];

/**
 * Calculate which achievements have been unlocked
 * @param {Object} progress - Player progress object
 * @returns {Array} Array of unlocked achievement IDs
 */
export function getUnlockedAchievements(progress) {
  return achievements
    .filter(achievement => achievement.condition(progress))
    .map(achievement => achievement.id);
}

/**
 * Get achievement by ID
 * @param {string} id - Achievement ID
 * @returns {Object} Achievement object or null
 */
export function getAchievementById(id) {
  return achievements.find(a => a.id === id) || null;
}

export default achievements;