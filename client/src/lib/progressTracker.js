// client/src/lib/progressTracker.js

const STORAGE_KEY = 'ad-simulator-progress';
const MAX_SCORE = 10000;
const VERSION = 3; // Increment when schema changes

// Rank thresholds
const RANK_THRESHOLDS = [
  { minScore: 0, rank: 'Novice' },
  { minScore: 50, rank: 'Script Kiddie' },
  { minScore: 150, rank: 'Junior Red Teamer' },
  { minScore: 300, rank: 'Red Team Operator' },
  { minScore: 500, rank: 'Elite Hacker' },
  { minScore: 800, rank: 'Cyber Ninja' }
];

/**
 * Get default progress object
 */
export const getDefaultProgress = () => ({
  version: VERSION,
  totalScore: 0,
  rank: 'Novice',
  scenariosCompleted: [],
  scenarioStats: {},
  quizScores: {},
  unlockedAchievements: [],
  tutorialMode: true,
  createdAt: Date.now(),
  updatedAt: Date.now(),
  
  // NEW: Global inventory system
  globalInventory: {
    credentials: [],
    files: [],
    compromisedHosts: []
  },
  
  // NEW: Campaign system
  activeCampaign: null,
  completedCampaigns: [],
  
  // NEW: Recently unlocked scenarios
  recentlyUnlocked: []
});

/**
 * Migrate old progress format to new version
 */
const migrateProgress = (oldProgress) => {
  if (!oldProgress || oldProgress.version === VERSION) {
    return oldProgress;
  }
  
  console.log(`Migrating progress from v${oldProgress.version || 1} to v${VERSION}`);
  
  const migrated = {
    ...getDefaultProgress(),
    ...oldProgress,
    version: VERSION,
    updatedAt: Date.now()
  };
  
  // Ensure new fields exist
  if (!migrated.globalInventory) {
    migrated.globalInventory = {
      credentials: [],
      files: [],
      compromisedHosts: []
    };
  }
  
  if (!migrated.activeCampaign) {
    migrated.activeCampaign = null;
  }
  
  if (!migrated.completedCampaigns) {
    migrated.completedCampaigns = [];
  }
  
  if (!migrated.recentlyUnlocked) {
    migrated.recentlyUnlocked = [];
  }
  
  return migrated;
};

/**
 * Validate progress object structure
 */
const validateProgress = (progress) => {
  if (!progress || typeof progress !== 'object') return false;
  
  const required = ['totalScore', 'rank', 'scenariosCompleted', 'unlockedAchievements'];
  return required.every(key => key in progress);
};

/**
 * Load progress from localStorage with error handling
 */
export const loadProgress = () => {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    
    if (!stored) {
      return getDefaultProgress();
    }
    
    const parsed = JSON.parse(stored);
    
    if (!validateProgress(parsed)) {
      console.warn('Invalid progress structure, resetting...');
      return getDefaultProgress();
    }
    
    return migrateProgress(parsed);
  } catch (error) {
    console.error('Failed to load progress:', error);
    return getDefaultProgress();
  }
};

/**
 * Save progress to localStorage with error handling
 */
export const saveProgress = (progress) => {
  try {
    if (!validateProgress(progress)) {
      throw new Error('Invalid progress object');
    }
    
    const toSave = {
      ...progress,
      updatedAt: Date.now()
    };
    
    localStorage.setItem(STORAGE_KEY, JSON.stringify(toSave));
    return true;
  } catch (error) {
    if (error.name === 'QuotaExceededError') {
      console.error('LocalStorage quota exceeded');
      alert('Storage is full. Please clear some data.');
    } else {
      console.error('Failed to save progress:', error);
    }
    return false;
  }
};

/**
 * Clear all progress (with confirmation)
 */
export const clearProgress = () => {
  try {
    localStorage.removeItem(STORAGE_KEY);
    return getDefaultProgress();
  } catch (error) {
    console.error('Failed to clear progress:', error);
    return null;
  }
};

/**
 * Calculate rank based on total score
 */
export const calculateRank = (totalScore) => {
  for (let i = RANK_THRESHOLDS.length - 1; i >= 0; i--) {
    if (totalScore >= RANK_THRESHOLDS[i].minScore) {
      return RANK_THRESHOLDS[i].rank;
    }
  }
  
  return 'Novice';
};

/**
 * Calculate scenario score based on performance
 */
const calculateScenarioScore = (wrongAttempts, hintsUsed) => {
  if (wrongAttempts === 0 && hintsUsed === 0) {
    return 10;
  } else if (hintsUsed > 0 && hintsUsed <= 2) {
    return 5;
  } else if (wrongAttempts > 0) {
    return Math.max(0, 10 - (wrongAttempts * 2));
  }
  return 0;
};

/**
 * Add scenario completion with duplicate prevention
 */
export const addScenarioCompletion = (progress, scenarioId, stats) => {
  const updatedProgress = { ...progress };
  
  const isFirstCompletion = !updatedProgress.scenariosCompleted.includes(scenarioId);
  
  if (isFirstCompletion) {
    updatedProgress.scenariosCompleted = [...updatedProgress.scenariosCompleted, scenarioId];
  }
  
  const score = calculateScenarioScore(stats.wrongAttempts || 0, stats.hintsUsed || 0);
  
  updatedProgress.scenarioStats[scenarioId] = {
    ...(updatedProgress.scenarioStats[scenarioId] || {}),
    lastCompleted: Date.now(),
    attempts: (updatedProgress.scenarioStats[scenarioId]?.attempts || 0) + 1,
    bestScore: Math.max(updatedProgress.scenarioStats[scenarioId]?.bestScore || 0, score),
    lastScore: score,
    wrongAttempts: stats.wrongAttempts || 0,
    hintsUsed: stats.hintsUsed || 0,
    timeSpent: stats.timeSpent || 0
  };
  
  if (isFirstCompletion) {
    updatedProgress.totalScore = Math.min(
      updatedProgress.totalScore + score,
      MAX_SCORE
    );
  }
  
  updatedProgress.rank = calculateRank(updatedProgress.totalScore);
  
  return updatedProgress;
};

/**
 * Add quiz score
 */
export const addQuizScore = (progress, scenarioId, score, correctAnswers, totalQuestions) => {
  const updatedProgress = { ...progress };
  
  updatedProgress.quizScores[scenarioId] = {
    score,
    correctAnswers,
    totalQuestions,
    percentage: Math.round((correctAnswers / totalQuestions) * 100),
    completedAt: Date.now()
  };
  
  updatedProgress.totalScore = Math.min(
    updatedProgress.totalScore + score,
    MAX_SCORE
  );
  
  updatedProgress.rank = calculateRank(updatedProgress.totalScore);
  
  return updatedProgress;
};

/**
 * Unlock achievement with duplicate prevention
 */
export const unlockAchievement = (progress, achievementId) => {
  const updatedProgress = { ...progress };
  
  if (!updatedProgress.unlockedAchievements.includes(achievementId)) {
    updatedProgress.unlockedAchievements = [
      ...updatedProgress.unlockedAchievements,
      achievementId
    ];
  }
  
  return updatedProgress;
};

/**
 * NEW: Add credential to global inventory
 */
export const addCredentialToInventory = (progress, credential, scenarioId) => {
  const updatedProgress = { ...progress };
  
  if (!updatedProgress.globalInventory) {
    updatedProgress.globalInventory = { credentials: [], files: [], compromisedHosts: [] };
  }
  
  const isDuplicate = updatedProgress.globalInventory.credentials.some(
    c => c.username === credential.username && c.secret === credential.secret
  );
  
  if (!isDuplicate) {
    const newCred = {
      id: `cred-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      type: credential.type,
      username: credential.username,
      secret: credential.secret,
      sourceScenario: scenarioId,
      acquiredAt: Date.now(),
      usedIn: []
    };
    
    updatedProgress.globalInventory.credentials = [
      ...updatedProgress.globalInventory.credentials,
      newCred
    ];
  }
  
  return updatedProgress;
};

/**
 * NEW: Add file to global inventory
 */
export const addFileToInventory = (progress, file, scenarioId) => {
  const updatedProgress = { ...progress };
  
  if (!updatedProgress.globalInventory) {
    updatedProgress.globalInventory = { credentials: [], files: [], compromisedHosts: [] };
  }
  
  const isDuplicate = updatedProgress.globalInventory.files.some(
    f => f.name === file.name
  );
  
  if (!isDuplicate) {
    const newFile = {
      id: `file-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: file.name,
      content: file.content || '',
      size: file.size || '0 KB',
      sourceScenario: scenarioId,
      acquiredAt: Date.now()
    };
    
    updatedProgress.globalInventory.files = [
      ...updatedProgress.globalInventory.files,
      newFile
    ];
  }
  
  return updatedProgress;
};

/**
 * NEW: Add compromised host to global inventory
 */
export const addCompromisedHost = (progress, host, scenarioId) => {
  const updatedProgress = { ...progress };
  
  if (!updatedProgress.globalInventory) {
    updatedProgress.globalInventory = { credentials: [], files: [], compromisedHosts: [] };
  }
  
  const existingHost = updatedProgress.globalInventory.compromisedHosts.find(
    h => h.hostname === host.hostname
  );
  
  if (existingHost) {
    const accessLevels = ['user', 'admin', 'system'];
    const currentLevel = accessLevels.indexOf(existingHost.access);
    const newLevel = accessLevels.indexOf(host.access);
    
    if (newLevel > currentLevel) {
      existingHost.access = host.access;
      existingHost.lastEscalation = Date.now();
    }
  } else {
    const newHost = {
      id: `host-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      hostname: host.hostname,
      ip: host.ip,
      access: host.access || 'user',
      compromisedBy: scenarioId,
      compromisedAt: Date.now()
    };
    
    updatedProgress.globalInventory.compromisedHosts = [
      ...updatedProgress.globalInventory.compromisedHosts,
      newHost
    ];
  }
  
  return updatedProgress;
};

/**
 * NEW: Mark credential as used in a scenario
 */
export const markCredentialUsed = (progress, credentialId, scenarioId) => {
  const updatedProgress = { ...progress };
  
  if (!updatedProgress.globalInventory?.credentials) return updatedProgress;
  
  const cred = updatedProgress.globalInventory.credentials.find(c => c.id === credentialId);
  if (cred && !cred.usedIn.includes(scenarioId)) {
    cred.usedIn = [...cred.usedIn, scenarioId];
  }
  
  return updatedProgress;
};

/**
 * Get progress statistics
 */
export const getProgressStats = (progress) => {
  const totalScenarios = 17;
  
  return {
    completionPercentage: Math.round((progress.scenariosCompleted.length / totalScenarios) * 100),
    totalScenarios: progress.scenariosCompleted.length,
    totalScore: progress.totalScore,
    rank: progress.rank,
    achievements: progress.unlockedAchievements.length,
    quizzesCompleted: Object.keys(progress.quizScores).length,
    averageQuizScore: calculateAverageQuizScore(progress),
    totalTimeSpent: calculateTotalTimeSpent(progress),
    bestScenario: findBestScenario(progress),
    inventorySize: {
      credentials: progress.globalInventory?.credentials?.length || 0,
      files: progress.globalInventory?.files?.length || 0,
      hosts: progress.globalInventory?.compromisedHosts?.length || 0
    }
  };
};

/**
 * Calculate average quiz score
 */
const calculateAverageQuizScore = (progress) => {
  const scores = Object.values(progress.quizScores);
  if (scores.length === 0) return 0;
  
  const sum = scores.reduce((acc, quiz) => acc + (quiz.percentage || 0), 0);
  return Math.round(sum / scores.length);
};

/**
 * Calculate total time spent
 */
const calculateTotalTimeSpent = (progress) => {
  const times = Object.values(progress.scenarioStats)
    .map(stat => stat.timeSpent || 0)
    .filter(t => typeof t === 'number');
  
  return times.reduce((acc, time) => acc + time, 0);
};

/**
 * Find best performing scenario
 */
const findBestScenario = (progress) => {
  const stats = Object.entries(progress.scenarioStats);
  if (stats.length === 0) return null;
  
  const best = stats.reduce((best, [id, stat]) => {
    if (!best || (stat.bestScore || 0) > (best.score || 0)) {
      return { id, score: stat.bestScore };
    }
    return best;
  }, null);
  
  return best;
};

/**
 * Export progress as JSON
 */
export const exportProgress = (progress) => {
  try {
    const exportData = {
      ...progress,
      exportedAt: Date.now(),
      exportVersion: VERSION
    };
    
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `ad-simulator-progress-${Date.now()}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
    return true;
  } catch (error) {
    console.error('Failed to export progress:', error);
    return false;
  }
};

/**
 * Import progress from JSON
 */
export const importProgress = (jsonString) => {
  try {
    const imported = JSON.parse(jsonString);
    
    if (!validateProgress(imported)) {
      throw new Error('Invalid progress format');
    }
    
    const migrated = migrateProgress(imported);
    saveProgress(migrated);
    
    return migrated;
  } catch (error) {
    console.error('Failed to import progress:', error);
    throw error;
  }
};
