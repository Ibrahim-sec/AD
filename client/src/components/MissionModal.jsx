// client/src/components/MissionModal.jsx (Enhanced Version)

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Trophy,
  Clock,
  Target,
  AlertCircle,
  Zap,
  ChevronRight,
  RotateCcw,
  Award,
  TrendingUp,
  Star,
  CheckCircle,
  Sparkles,
  BookOpen
} from 'lucide-react';
import Confetti from 'react-confetti';

export default function MissionModal({ 
  isOpen, 
  onClose, 
  type, 
  scenario, 
  stats,
  newAchievements,
  onRetry,
  onNextScenario,
  progress
}) {
  const [showConfetti, setShowConfetti] = useState(false);
  const [animatedScore, setAnimatedScore] = useState(0);
  const [animatedSteps, setAnimatedSteps] = useState(0);
  const [animatedTime, setAnimatedTime] = useState(0);
  const [animatedAttempts, setAnimatedAttempts] = useState(0);

  // Trigger confetti on excellent performance
  useEffect(() => {
    if (isOpen && type === 'debrief' && stats?.scoreEarned >= 8) {
      setShowConfetti(true);
      setTimeout(() => setShowConfetti(false), 5000);
    }
  }, [isOpen, type, stats]);

  // Animate numbers counting up
  useEffect(() => {
    if (!isOpen || type !== 'debrief' || !stats) return;

    const duration = 1000;
    const steps = 60;
    const scoreIncrement = (stats.scoreEarned || 0) / steps;
    const stepsIncrement = (stats.stepsCompleted || 0) / steps;
    const timeIncrement = parseInt(stats.timeSpent?.split('m')[0] || 0) / steps;
    const attemptsIncrement = (stats.wrongAttempts || 0) / steps;

    let currentStep = 0;
    const timer = setInterval(() => {
      currentStep++;
      setAnimatedScore(Math.min(Math.floor(scoreIncrement * currentStep), stats.scoreEarned || 0));
      setAnimatedSteps(Math.min(Math.floor(stepsIncrement * currentStep), stats.stepsCompleted || 0));
      setAnimatedTime(Math.min(Math.floor(timeIncrement * currentStep), parseInt(stats.timeSpent?.split('m')[0] || 0)));
      setAnimatedAttempts(Math.min(Math.floor(attemptsIncrement * currentStep), stats.wrongAttempts || 0));

      if (currentStep >= steps) {
        clearInterval(timer);
      }
    }, duration / steps);

    return () => clearInterval(timer);
  }, [isOpen, type, stats]);

  if (!isOpen) return null;

  // Performance rating based on score
  const getPerformanceRating = (score) => {
    if (score >= 9) return { label: 'Outstanding', color: 'from-yellow-400 to-orange-500', emoji: '🏆' };
    if (score >= 7) return { label: 'Excellent', color: 'from-green-400 to-emerald-500', emoji: '⭐' };
    if (score >= 5) return { label: 'Good', color: 'from-blue-400 to-cyan-500', emoji: '👍' };
    if (score >= 3) return { label: 'Fair', color: 'from-purple-400 to-pink-500', emoji: '📈' };
    return { label: 'Keep Practicing', color: 'from-gray-400 to-gray-500', emoji: '💪' };
  };

  const performance = stats?.scoreEarned ? getPerformanceRating(stats.scoreEarned) : null;

  // Motivational messages
  const getMotivationalMessage = (score, attempts) => {
    if (score >= 9 && attempts === 0) return "Perfect execution! You're a natural.";
    if (score >= 9) return "Outstanding work! Almost flawless.";
    if (score >= 7) return "Great job! You're mastering AD attacks.";
    if (score >= 5) return "Well done! Keep practicing to improve.";
    if (attempts > 5) return "Don't give up! Every attempt teaches you something.";
    return "Keep going! Practice makes perfect.";
  };

  if (type === 'briefing') {
    return (
      <AnimatePresence>
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            className="bg-[#101214] border border-white/10 rounded-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-hidden shadow-2xl"
          >
            {/* Header */}
            <div className="bg-gradient-to-r from-[#2D9CDB] to-cyan-500 p-6 relative overflow-hidden">
              <div className="absolute inset-0 opacity-10" style={{
                backgroundImage: `repeating-linear-gradient(45deg, transparent, transparent 10px, rgba(255,255,255,0.1) 10px, rgba(255,255,255,0.1) 20px)`
              }} />
              
              <button
                onClick={onClose}
                className="absolute top-4 right-4 p-2 bg-white/10 hover:bg-white/20 rounded-lg transition-all"
              >
                <X className="w-5 h-5 text-white" />
              </button>

              <div className="relative">
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center">
                    <Target className="w-6 h-6 text-white" />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-white">Mission Briefing</h2>
                    <p className="text-white/80 text-sm">{scenario?.title}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto max-h-[calc(90vh-200px)]">
              {/* Objective */}
              <div className="mb-6">
                <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
                  <Target className="w-5 h-5 text-[#2D9CDB]" />
                  Objective
                </h3>
                <p className="text-white/70 leading-relaxed">
                  {scenario?.description}
                </p>
              </div>

              {/* Mission Details */}
              <div className="grid grid-cols-2 gap-4 mb-6">
                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <div className="text-white/50 text-xs mb-1">Difficulty</div>
                  <div className="text-white font-semibold">{scenario?.difficulty}</div>
                </div>
                <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                  <div className="text-white/50 text-xs mb-1">Steps</div>
                  <div className="text-white font-semibold">{scenario?.steps?.length} Steps</div>
                </div>
              </div>

              {/* Network Info */}
              <div className="mb-6">
                <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
                  <Zap className="w-4 h-4 text-[#2D9CDB]" />
                  Target Environment
                </h3>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-white/50">Domain:</span>
                    <span className="text-white font-mono">{scenario?.network?.domain}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-white/50">Target:</span>
                    <span className="text-white font-mono">{scenario?.network?.target?.hostname}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-white/50">IP:</span>
                    <span className="text-white font-mono">{scenario?.network?.target?.ip}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="p-6 border-t border-white/10">
              <button
                onClick={onClose}
                className="w-full px-6 py-3 bg-gradient-to-r from-[#2D9CDB] to-cyan-500 hover:from-[#2D9CDB]/90 hover:to-cyan-500/90 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-[#2D9CDB]/30"
              >
                <Zap className="w-5 h-5" />
                Start Mission
              </button>
            </div>
          </motion.div>
        </div>
      </AnimatePresence>
    );
  }

  // DEBRIEF (Mission Complete)
  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
        {showConfetti && (
          <Confetti
            width={window.innerWidth}
            height={window.innerHeight}
            recycle={false}
            numberOfPieces={500}
            gravity={0.3}
          />
        )}

        <motion.div
          initial={{ opacity: 0, scale: 0.9, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.9, y: 20 }}
          className="bg-[#101214] border border-white/10 rounded-2xl max-w-3xl w-full mx-4 max-h-[90vh] overflow-hidden shadow-2xl"
        >
          {/* Header with Trophy */}
          <div className="relative p-8 text-center overflow-hidden">
            {/* Animated background */}
            <div className="absolute inset-0 bg-gradient-to-br from-[#2D9CDB]/20 via-transparent to-purple-500/20" />
            <motion.div
              className="absolute inset-0"
              animate={{
                background: [
                  'radial-gradient(circle at 20% 50%, rgba(45, 156, 219, 0.1) 0%, transparent 50%)',
                  'radial-gradient(circle at 80% 50%, rgba(45, 156, 219, 0.1) 0%, transparent 50%)',
                  'radial-gradient(circle at 20% 50%, rgba(45, 156, 219, 0.1) 0%, transparent 50%)',
                ],
              }}
              transition={{ duration: 4, repeat: Infinity }}
            />

            <button
              onClick={onClose}
              className="absolute top-4 right-4 p-2 bg-white/5 hover:bg-white/10 rounded-lg transition-all z-10"
            >
              <X className="w-5 h-5 text-white" />
            </button>

            {/* Trophy Icon */}
            <motion.div
              initial={{ scale: 0, rotate: -180 }}
              animate={{ scale: 1, rotate: 0 }}
              transition={{ type: 'spring', duration: 0.8, delay: 0.2 }}
              className="relative z-10 mb-6"
            >
              <div className={`w-24 h-24 mx-auto rounded-full bg-gradient-to-br ${performance?.color} p-1`}>
                <div className="w-full h-full rounded-full bg-[#101214] flex items-center justify-center">
                  <Trophy className="w-12 h-12 text-white" />
                </div>
              </div>
            </motion.div>

            <motion.h1
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="text-4xl font-bold text-white mb-2 relative z-10"
            >
              Mission Complete!
            </motion.h1>

            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="text-white/60 text-lg relative z-10"
            >
              {scenario?.title}
            </motion.p>

            {/* Performance Badge */}
            {performance && (
              <motion.div
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.5 }}
                className="mt-4 relative z-10"
              >
                <div className={`inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r ${performance.color} rounded-full text-white font-bold text-lg shadow-lg`}>
                  <span>{performance.emoji}</span>
                  <span>{performance.label}</span>
                </div>
              </motion.div>
            )}
          </div>

          {/* Stats Grid */}
          <div className="px-8 pb-6">
            <div className="grid grid-cols-2 gap-4 mb-6">
              {/* Score */}
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.6 }}
                className="bg-gradient-to-br from-yellow-500/10 to-orange-500/10 border border-yellow-500/20 rounded-xl p-4"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 rounded-lg bg-yellow-500/20 flex items-center justify-center">
                    <Zap className="w-5 h-5 text-yellow-400" />
                  </div>
                  <span className="text-sm text-white/60">Score Earned</span>
                </div>
                <div className="text-4xl font-bold text-yellow-400">
                  {animatedScore}
                </div>
              </motion.div>

              {/* Time */}
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.7 }}
                className="bg-gradient-to-br from-cyan-500/10 to-blue-500/10 border border-cyan-500/20 rounded-xl p-4"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 rounded-lg bg-cyan-500/20 flex items-center justify-center">
                    <Clock className="w-5 h-5 text-cyan-400" />
                  </div>
                  <span className="text-sm text-white/60">Time Taken</span>
                </div>
                <div className="text-4xl font-bold text-cyan-400">
                  {animatedTime}m {stats?.timeSpent?.split(' ')[1] || '0s'}
                </div>
              </motion.div>

              {/* Steps */}
              <motion.div
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.8 }}
                className="bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/20 rounded-xl p-4"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                    <CheckCircle className="w-5 h-5 text-green-400" />
                  </div>
                  <span className="text-sm text-white/60">Steps Completed</span>
                </div>
                <div className="text-4xl font-bold text-green-400">
                  {animatedSteps}
                </div>
              </motion.div>

              {/* Wrong Attempts */}
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.9 }}
                className="bg-gradient-to-br from-red-500/10 to-pink-500/10 border border-red-500/20 rounded-xl p-4"
              >
                <div className="flex items-center gap-3 mb-2">
                  <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
                    <AlertCircle className="w-5 h-5 text-red-400" />
                  </div>
                  <span className="text-sm text-white/60">Wrong Attempts</span>
                </div>
                <div className="text-4xl font-bold text-red-400">
                  {animatedAttempts}
                </div>
              </motion.div>
            </div>

            {/* Progress Bar */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.0 }}
              className="mb-6"
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-white/60">Campaign Progress</span>
                <span className="text-sm text-[#2D9CDB] font-semibold">
                  {progress?.scenariosCompleted?.length || 0} / {progress?.totalScenarios || 19} scenarios
                </span>
              </div>
              <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${((progress?.scenariosCompleted?.length || 0) / (progress?.totalScenarios || 19)) * 100}%` }}
                  transition={{ duration: 1, delay: 1.1 }}
                  className="h-full bg-gradient-to-r from-[#2D9CDB] to-cyan-400"
                />
              </div>
            </motion.div>

            {/* Achievements */}
            {newAchievements && newAchievements.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 1.1 }}
                className="mb-6 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-xl p-4"
              >
                <div className="flex items-center gap-2 mb-3">
                  <Award className="w-5 h-5 text-purple-400" />
                  <h3 className="text-sm font-bold text-white">New Achievements Unlocked!</h3>
                </div>
                <div className="flex flex-wrap gap-2">
                  {newAchievements.map((achievement, idx) => (
                    <motion.div
                      key={achievement.id}
                      initial={{ opacity: 0, scale: 0 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: 1.2 + (idx * 0.1) }}
                      className="flex items-center gap-2 bg-white/5 px-3 py-2 rounded-lg border border-white/10"
                    >
                      <Sparkles className="w-4 h-4 text-yellow-400" />
                      <span className="text-sm text-white">{achievement.title}</span>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            )}

            {/* Key Takeaways */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 1.2 }}
              className="bg-white/5 border border-white/10 rounded-xl p-4 mb-6"
            >
              <div className="flex items-center gap-2 mb-3">
                <BookOpen className="w-5 h-5 text-[#2D9CDB]" />
                <h3 className="text-sm font-bold text-white">Key Takeaways</h3>
              </div>
              <ul className="space-y-2 text-sm text-white/70">
                <li className="flex items-start gap-2">
                  <span className="text-[#2D9CDB]">•</span>
                  <span>You successfully simulated a real-world AD attack</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#2D9CDB]">•</span>
                  <span>This technique is used in actual penetration tests</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#2D9CDB]">•</span>
                  <span>Understanding defense helps improve security posture</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="text-[#2D9CDB]">•</span>
                  <span>{getMotivationalMessage(stats?.scoreEarned, stats?.wrongAttempts)}</span>
                </li>
              </ul>
            </motion.div>
          </div>

          {/* Action Buttons */}
          <div className="px-8 pb-8">
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={onRetry}
                className="px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2"
              >
                <RotateCcw className="w-4 h-4" />
                Retry Mission
              </button>
              <button
                onClick={onClose}
                className="px-6 py-3 bg-gradient-to-r from-[#2D9CDB] to-cyan-500 hover:from-[#2D9CDB]/90 hover:to-cyan-500/90 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2 shadow-lg shadow-[#2D9CDB]/30"
              >
                Continue
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
