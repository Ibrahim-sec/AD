import { useState, useEffect } from 'react';
import { 
  Settings, 
  Shield, 
  Trophy, 
  Target,
  Zap,
  TrendingUp,
  Clock,
  Award,
  ChevronDown,
  Info,
  Star,
  Flame
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function Header({ 
  title, 
  currentStep, 
  totalSteps, 
  score, 
  rank,
  onOpenSettings,
  scenarioId,
  progress
}) {
  const [showStatsDropdown, setShowStatsDropdown] = useState(false);
  const [sessionTime, setSessionTime] = useState(0);
  const [prevScore, setPrevScore] = useState(score);
  const [scoreIncrease, setScoreIncrease] = useState(0);

  // Session timer
  useEffect(() => {
    const interval = setInterval(() => {
      setSessionTime(prev => prev + 1);
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Score animation
  useEffect(() => {
    if (score > prevScore) {
      setScoreIncrease(score - prevScore);
      setTimeout(() => setScoreIncrease(0), 2000);
    }
    setPrevScore(score);
  }, [score]);

  const progressPercentage = (currentStep / totalSteps) * 100;
  
  const getRankColor = (rank) => {
    const ranks = {
      'Novice': 'text-gray-400',
      'Script Kiddie': 'text-blue-400',
      'Junior Red Teamer': 'text-green-400',
      'Red Team Operator': 'text-yellow-400',
      'Elite Hacker': 'text-purple-400',
      'Cyber Ninja': 'text-red-400'
    };
    return ranks[rank] || 'text-white';
  };

  const getRankIcon = (rank) => {
    if (rank.includes('Elite') || rank.includes('Ninja')) return <Flame className="w-4 h-4" />;
    if (rank.includes('Operator')) return <Award className="w-4 h-4" />;
    if (rank.includes('Red Teamer')) return <Trophy className="w-4 h-4" />;
    return <Star className="w-4 h-4" />;
  };

  const formatTime = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return h > 0 ? `${h}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}` 
                 : `${m}:${s.toString().padStart(2, '0')}`;
  };

  const completionRate = progress?.scenariosCompleted?.length 
    ? Math.round((progress.scenariosCompleted.length / 12) * 100) 
    : 0;

  return (
    <header className="relative bg-[#101214] border-b border-white/10 shadow-2xl z-40">
      {/* Main Header Bar */}
      <div className="px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Left Section - Title & Scenario */}
          <div className="flex items-center gap-4">
            {/* Logo/Shield Icon */}
            <motion.div 
              className="relative"
              whileHover={{ scale: 1.1, rotate: 5 }}
              transition={{ type: "spring", stiffness: 400 }}
            >
              <div className="w-12 h-12 bg-gradient-to-br from-[#2D9CDB] to-[#1e6a8f] rounded-xl flex items-center justify-center shadow-lg shadow-[#2D9CDB]/30">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full border-2 border-[#101214] animate-pulse" />
            </motion.div>

            {/* Title & Subtitle */}
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                AD Attack Simulator
                <span className="px-2 py-0.5 bg-[#2D9CDB]/20 text-[#2D9CDB] text-xs rounded border border-[#2D9CDB]/30">
                  v2.0
                </span>
              </h1>
              <div className="flex items-center gap-2 mt-1">
                <Target className="w-3 h-3 text-[#2D9CDB]" />
                <p className="text-sm text-white/60 font-medium">{title}</p>
              </div>
            </div>
          </div>

          {/* Right Section - Stats & Actions */}
          <div className="flex items-center gap-4">
            {/* Score Display */}
            <motion.div 
              className="relative bg-[#1a1b1e] rounded-xl px-4 py-3 border border-white/10 min-w-[120px]"
              whileHover={{ scale: 1.05 }}
              transition={{ type: "spring", stiffness: 400 }}
            >
              <div className="flex items-center gap-2 mb-1">
                <Zap className="w-4 h-4 text-yellow-400" />
                <span className="text-xs text-white/50 uppercase tracking-wider">Score</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-2xl font-bold text-white">{score}</span>
                <AnimatePresence>
                  {scoreIncrease > 0 && (
                    <motion.span
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: -20 }}
                      exit={{ opacity: 0 }}
                      className="absolute -top-6 right-4 text-green-400 font-bold text-sm"
                    >
                      +{scoreIncrease}
                    </motion.span>
                  )}
                </AnimatePresence>
              </div>
            </motion.div>

            {/* Rank Display */}
            <motion.div 
              className="relative bg-[#1a1b1e] rounded-xl px-4 py-3 border border-white/10 min-w-[180px] cursor-pointer"
              whileHover={{ scale: 1.05 }}
              onClick={() => setShowStatsDropdown(!showStatsDropdown)}
            >
              <div className="flex items-center gap-2 mb-1">
                {getRankIcon(rank)}
                <span className="text-xs text-white/50 uppercase tracking-wider">Rank</span>
                <ChevronDown className={`w-3 h-3 text-white/50 ml-auto transition-transform ${showStatsDropdown ? 'rotate-180' : ''}`} />
              </div>
              <div className={`text-sm font-bold ${getRankColor(rank)}`}>
                {rank}
              </div>
            </motion.div>

            {/* Session Time */}
            <div className="bg-[#1a1b1e] rounded-xl px-4 py-3 border border-white/10 min-w-[100px]">
              <div className="flex items-center gap-2 mb-1">
                <Clock className="w-4 h-4 text-cyan-400" />
                <span className="text-xs text-white/50 uppercase tracking-wider">Time</span>
              </div>
              <div className="text-sm font-bold text-white font-mono">
                {formatTime(sessionTime)}
              </div>
            </div>

            {/* Progress Indicator */}
            <div className="bg-[#1a1b1e] rounded-xl px-4 py-3 border border-white/10 min-w-[140px]">
              <div className="flex items-center gap-2 mb-1">
                <TrendingUp className="w-4 h-4 text-green-400" />
                <span className="text-xs text-white/50 uppercase tracking-wider">Progress</span>
              </div>
              <div className="text-sm font-bold text-white">
                {currentStep} / {totalSteps}
              </div>
            </div>

            {/* Settings Button */}
            <motion.button
              onClick={onOpenSettings}
              className="w-12 h-12 bg-[#1a1b1e] hover:bg-[#2D9CDB] border border-white/10 hover:border-[#2D9CDB] rounded-xl flex items-center justify-center transition-all group"
              whileHover={{ scale: 1.1, rotate: 90 }}
              whileTap={{ scale: 0.95 }}
            >
              <Settings className="w-5 h-5 text-white/60 group-hover:text-white transition-colors" />
            </motion.button>
          </div>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="h-1 bg-white/5 relative overflow-hidden">
        <motion.div 
          className="h-full bg-gradient-to-r from-[#2D9CDB] via-cyan-400 to-[#2D9CDB]"
          initial={{ width: 0 }}
          animate={{ width: `${progressPercentage}%` }}
          transition={{ duration: 0.5, ease: "easeOut" }}
        />
        
        {/* Animated Glow */}
        <motion.div
          className="absolute top-0 left-0 h-full w-20 bg-gradient-to-r from-transparent via-white/30 to-transparent"
          animate={{
            x: ['-100%', '400%']
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: "linear"
          }}
        />
      </div>

      {/* Stats Dropdown */}
      <AnimatePresence>
        {showStatsDropdown && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="absolute top-full right-6 mt-2 w-80 bg-[#1a1b1e] rounded-xl border border-white/10 shadow-2xl z-50 overflow-hidden"
          >
            {/* Dropdown Header */}
            <div className="bg-gradient-to-r from-[#2D9CDB]/20 to-transparent px-4 py-3 border-b border-white/10">
              <div className="flex items-center gap-2">
                <Trophy className="w-5 h-5 text-[#2D9CDB]" />
                <h3 className="text-sm font-bold text-white">Your Statistics</h3>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="p-4 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-[#101214] rounded-lg p-3 border border-white/5">
                  <div className="text-xs text-white/40 mb-1">Total Score</div>
                  <div className="text-xl font-bold text-white">{score}</div>
                </div>
                <div className="bg-[#101214] rounded-lg p-3 border border-white/5">
                  <div className="text-xs text-white/40 mb-1">Scenarios</div>
                  <div className="text-xl font-bold text-[#2D9CDB]">
                    {progress?.scenariosCompleted?.length || 0} / 12
                  </div>
                </div>
                <div className="bg-[#101214] rounded-lg p-3 border border-white/5">
                  <div className="text-xs text-white/40 mb-1">Completion</div>
                  <div className="text-xl font-bold text-green-400">{completionRate}%</div>
                </div>
                <div className="bg-[#101214] rounded-lg p-3 border border-white/5">
                  <div className="text-xs text-white/40 mb-1">Achievements</div>
                  <div className="text-xl font-bold text-yellow-400">
                    {progress?.unlockedAchievements?.length || 0}
                  </div>
                </div>
              </div>

              {/* Rank Progress Bar */}
              <div className="bg-[#101214] rounded-lg p-3 border border-white/5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs text-white/40">Rank Progress</span>
                  <span className="text-xs text-[#2D9CDB] font-semibold">{rank}</span>
                </div>
                <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-gradient-to-r from-[#2D9CDB] to-cyan-400"
                    style={{ width: `${Math.min((score / 500) * 100, 100)}%` }}
                  />
                </div>
                <div className="text-xs text-white/30 mt-1">
                  {500 - score > 0 ? `${500 - score} points to next rank` : 'Max rank achieved!'}
                </div>
              </div>

              {/* Quick Actions */}
              <div className="flex gap-2 pt-2">
                <button className="flex-1 px-3 py-2 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white text-xs font-medium rounded-lg transition-all">
                  View Achievements
                </button>
                <button className="flex-1 px-3 py-2 bg-white/5 hover:bg-white/10 text-white text-xs font-medium rounded-lg transition-all">
                  Leaderboard
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Floating Achievement Toast */}
      {scoreIncrease > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 50, scale: 0.8 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -20 }}
          className="fixed top-24 right-6 bg-gradient-to-r from-green-500/90 to-emerald-500/90 backdrop-blur-sm text-white px-4 py-3 rounded-xl shadow-2xl z-50 border border-white/20"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-white/20 rounded-full flex items-center justify-center">
              <Zap className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold">Points Earned!</div>
              <div className="text-xs opacity-90">+{scoreIncrease} points</div>
            </div>
          </div>
        </motion.div>
      )}
    </header>
  );
}
