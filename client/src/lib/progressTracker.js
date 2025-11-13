/**
 * Progress Tracker
 * 
 * Manages player progress, scoring, and localStorage persistence
 */

const STORAGE_KEY = 'ad-attack-simulator-progress';

// Rank thresholds
export const RANK_THRESHOLDS = {
  'Script Kiddie': { min: 0, max: 30 },
  'Junior Red Teamer': { min: 31, max: 70 },
  'Operator': { min: 71, max: Infinity }
};

/**
 * Get the rank based on total score
 * @param {number} score - Total score
 * @returns {string} Rank name
 */
export function getRankFromScore(score) {
  for (const [rank, threshold] of Object.entries(RANK_THRESHOLDS)) {
    if (score >= threshold.min && score <= threshold.max) {
      return rank;
    }
  }
  return 'Script Kiddie';
}

/**
 * Initialize default progress object
 * @returns {Object} Default progress structure
 */
export function getDefaultProgress() {
  return {
    totalScore: 0,
    rank: 'Script Kiddie',
    scenariosCompleted: [],
    scenarioStats: [],
    quizScores: [],
    unlockedAchievements: [],
    tutorialMode: false,
    lastUpdated: new Date().toISOString()
  };
}

/**
 * Load progress from localStorage
 * @returns {Object} Player progress
 */
export function loadProgress() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      return JSON.parse(stored);
    }
  } catch (error) {
    console.error('Error loading progress:', error);
  }
  return getDefaultProgress();
}

/**
 * Save progress to localStorage
 * @param {Object} progress - Progress object to save
 */
export function saveProgress(progress) {
  try {
    progress.lastUpdated = new Date().toISOString();
    localStorage.setItem(STORAGE_KEY, JSON.stringify(progress));
  } catch (error) {
    console.error('Error saving progress:', error);
  }
}

/**
 * Calculate score for a scenario completion
 * @param {number} wrongAttempts - Number of wrong command attempts
 * @param {number} hintsUsed - Number of hints used
 * @returns {number} Points earned
 */
export function calculateScenarioScore(wrongAttempts, hintsUsed) {
  if (wrongAttempts === 0 && hintsUsed === 0) {
    return 10; // Perfect: +10 points
  } else if (hintsUsed > 0 && hintsUsed <= 2) {
    return 5; // With hints: +5 points
  } else if (wrongAttempts > 0) {
    return Math.max(0, 10 - (wrongAttempts * 2)); // Deduct for wrong attempts
  }
  return 0;
}

/**
 * Add scenario completion to progress
 * @param {Object} progress - Current progress
 * @param {string} scenarioId - Scenario ID
 * @param {Object} stats - Scenario statistics
 * @returns {Object} Updated progress
 */
export function addScenarioCompletion(progress, scenarioId, stats) {
  // Mark scenario as completed
  if (!progress.scenariosCompleted.includes(scenarioId)) {
    progress.scenariosCompleted.push(scenarioId);
  }

  // Add/update scenario stats
  const existingIndex = progress.scenarioStats.findIndex(s => s.scenarioId === scenarioId);
  const scenarioScore = calculateScenarioScore(stats.wrongAttempts, stats.hintsUsed);
  
  const scenarioData = {
    scenarioId,
    completed: true,
    score: scenarioScore,
    wrongAttempts: stats.wrongAttempts,
    hintsUsed: stats.hintsUsed,
    timeSpent: stats.timeSpent || 0,
    completedAt: new Date().toISOString()
  };

  if (existingIndex >= 0) {
    progress.scenarioStats[existingIndex] = scenarioData;
  } else {
    progress.scenarioStats.push(scenarioData);
  }

  // Update total score and rank
  progress.totalScore = progress.scenarioStats.reduce((sum, s) => sum + (s.score || 0), 0);
  progress.rank = getRankFromScore(progress.totalScore);

  return progress;
}

/**
 * Add quiz score to progress
 * @param {Object} progress - Current progress
 * @param {string} scenarioId - Scenario ID
 * @param {number} score - Quiz score (0-100)
 * @param {number} correctAnswers - Number of correct answers
 * @param {number} totalQuestions - Total questions in quiz
 * @returns {Object} Updated progress
 */
export function addQuizScore(progress, scenarioId, score, correctAnswers, totalQuestions) {
  const quizData = {
    scenarioId,
    score,
    correctAnswers,
    totalQuestions,
    completedAt: new Date().toISOString()
  };

  // Check if quiz for this scenario already exists
  const existingIndex = progress.quizScores.findIndex(q => q.scenarioId === scenarioId);
  if (existingIndex >= 0) {
    progress.quizScores[existingIndex] = quizData;
  } else {
    progress.quizScores.push(quizData);
  }

  // Add bonus points for perfect quiz (5 points per correct answer)
  if (score === 100) {
    progress.totalScore += 5;
    progress.rank = getRankFromScore(progress.totalScore);
  }

  return progress;
}

/**
 * Unlock an achievement
 * @param {Object} progress - Current progress
 * @param {string} achievementId - Achievement ID
 * @returns {Object} Updated progress
 */
export function unlockAchievement(progress, achievementId) {
  if (!progress.unlockedAchievements.includes(achievementId)) {
    progress.unlockedAchievements.push(achievementId);
  }
  return progress;
}

/**
 * Reset all progress
 * @returns {Object} Default progress
 */
export function resetProgress() {
  const defaultProgress = getDefaultProgress();
  saveProgress(defaultProgress);
  return defaultProgress;
}

/**
 * Get scenario statistics
 * @param {Object} progress - Current progress
 * @param {string} scenarioId - Scenario ID
 * @returns {Object|null} Scenario stats or null
 */
export function getScenarioStats(progress, scenarioId) {
  return progress.scenarioStats.find(s => s.scenarioId === scenarioId) || null;
}

/**
 * Get quiz score for scenario
 * @param {Object} progress - Current progress
 * @param {string} scenarioId - Scenario ID
 * @returns {Object|null} Quiz score or null
 */
export function getQuizScore(progress, scenarioId) {
  return progress.quizScores.find(q => q.scenarioId === scenarioId) || null;
}
