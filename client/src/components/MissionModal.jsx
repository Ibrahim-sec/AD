// client/src/components/MissionModal.jsx

import { useEffect, useRef } from 'react';
import { X, Trophy, Target, Clock, Zap, Award } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function MissionModal({
  isOpen,
  onClose,
  type, // 'briefing' or 'debrief'
  scenario,
  stats,
  newAchievements = []
}) {
  const modalRef = useRef(null);
  const closeButtonRef = useRef(null);
  
  // Lock body scroll when modal is open
  useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden';
      
      // Focus close button for accessibility
      setTimeout(() => {
        closeButtonRef.current?.focus();
      }, 100);
    } else {
      document.body.style.overflow = 'unset';
    }
    
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen]);
  
  // Handle escape key
  useEffect(() => {
    if (!isOpen) return;
    
    const handleEscape = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    
    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isOpen, onClose]);
  
  // Handle backdrop click
  const handleBackdropClick = (e) => {
    if (e.target === modalRef.current) {
      onClose();
    }
  };
  
  if (!scenario) return null;
  
  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          ref={modalRef}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={handleBackdropClick}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0, y: 20 }}
            animate={{ scale: 1, opacity: 1, y: 0 }}
            exit={{ scale: 0.9, opacity: 0, y: 20 }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className="relative bg-[#101214] rounded-xl border border-white/10 shadow-2xl max-w-2xl w-full max-h-[90vh] overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Close Button */}
            <button
              ref={closeButtonRef}
              onClick={onClose}
              className="absolute top-4 right-4 z-10 p-2 rounded-lg bg-white/5 hover:bg-white/10 text-white/60 hover:text-white transition-all"
              aria-label="Close modal"
            >
              <X className="w-5 h-5" />
            </button>
            
            {/* Content */}
            <div className="overflow-y-auto max-h-[90vh] scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent">
              {type === 'briefing' ? (
                <BriefingContent scenario={scenario} />
              ) : (
                <DebriefContent 
                  scenario={scenario} 
                  stats={stats} 
                  newAchievements={newAchievements}
                />
              )}
            </div>
            
            {/* Footer Button */}
            <div className="sticky bottom-0 bg-gradient-to-t from-[#101214] via-[#101214] to-transparent p-6 border-t border-white/5">
              <button
                onClick={onClose}
                className="w-full px-6 py-3 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white font-semibold rounded-lg transition-all shadow-lg shadow-[#2D9CDB]/20"
              >
                {type === 'briefing' ? 'Start Mission' : 'Continue'}
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// Briefing Content Component
function BriefingContent({ scenario }) {
  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center gap-4 mb-6">
        <div className="w-16 h-16 rounded-xl bg-[#2D9CDB]/20 flex items-center justify-center">
          <Target className="w-8 h-8 text-[#2D9CDB]" />
        </div>
        <div>
          <h2 className="text-2xl font-bold text-white">{scenario.title}</h2>
          <div className="flex items-center gap-2 mt-1">
            <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
              scenario.difficulty === 'Beginner'
                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                : scenario.difficulty === 'Intermediate'
                ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                : scenario.difficulty === 'Advanced'
                ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                : 'bg-purple-500/20 text-purple-400 border border-purple-500/30'
            }`}>
              {scenario.difficulty}
            </span>
            {scenario.mitreAttack && (
              <span className="px-2 py-0.5 rounded text-xs bg-blue-500/20 text-blue-400 border border-blue-500/30 font-mono">
                {scenario.mitreAttack}
              </span>
            )}
          </div>
        </div>
      </div>
      
      {/* Objective */}
      <div className="bg-[#1a1b1e] rounded-lg p-6 border border-white/5 mb-6">
        <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2">
          <Trophy className="w-5 h-5 text-[#2D9CDB]" />
          Mission Objective
        </h3>
        <p className="text-white/70 leading-relaxed">
          {scenario.description}
        </p>
      </div>
      
      {/* Network Info */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <div className="bg-[#1a1b1e] rounded-lg p-4 border border-white/5">
          <div className="text-xs text-white/40 mb-1">Target Network</div>
          <div className="text-sm font-semibold text-white">{scenario.network.domain}</div>
        </div>
        <div className="bg-[#1a1b1e] rounded-lg p-4 border border-white/5">
          <div className="text-xs text-white/40 mb-1">Total Steps</div>
          <div className="text-sm font-semibold text-white">{scenario.steps.length}</div>
        </div>
      </div>
      
      {/* Tips */}
      <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
        <h4 className="text-sm font-semibold text-blue-400 mb-2">💡 Tips for Success</h4>
        <ul className="text-xs text-blue-300/80 space-y-1">
          <li>• Read each step carefully before executing commands</li>
          <li>• Use hints if you get stuck (reduces score slightly)</li>
          <li>• Pay attention to the target machine's responses</li>
          <li>• Complete without hints for maximum points!</li>
        </ul>
      </div>
    </div>
  );
}

// Debrief Content Component
function DebriefContent({ scenario, stats, newAchievements }) {
  return (
    <div className="p-8">
      {/* Header */}
      <div className="text-center mb-8">
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: 'spring', stiffness: 200, delay: 0.2 }}
          className="w-24 h-24 mx-auto mb-4 rounded-full bg-green-500/20 flex items-center justify-center"
        >
          <Trophy className="w-12 h-12 text-green-400" />
        </motion.div>
        <h2 className="text-3xl font-bold text-white mb-2">Mission Complete!</h2>
        <p className="text-white/60">{scenario.title}</p>
      </div>
      
      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-4 mb-6">
        <StatCard
          icon={<Zap className="w-5 h-5" />}
          label="Score Earned"
          value={stats.scoreEarned || 0}
          color="text-yellow-400"
          delay={0.3}
        />
        <StatCard
          icon={<Clock className="w-5 h-5" />}
          label="Time Taken"
          value={stats.timeSpent || '0s'}
          color="text-cyan-400"
          delay={0.4}
        />
        <StatCard
          icon={<Target className="w-5 h-5" />}
          label="Steps Completed"
          value={stats.stepsCompleted || 0}
          color="text-green-400"
          delay={0.5}
        />
        <StatCard
          icon={<Award className="w-5 h-5" />}
          label="Wrong Attempts"
          value={stats.wrongAttempts || 0}
          color="text-red-400"
          delay={0.6}
        />
      </div>
      
      {/* New Achievements */}
      {newAchievements.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="bg-gradient-to-r from-yellow-500/10 to-orange-500/10 border border-yellow-500/20 rounded-lg p-6 mb-6"
        >
          <h3 className="text-lg font-semibold text-yellow-400 mb-4 flex items-center gap-2">
            <Trophy className="w-5 h-5" />
            New Achievements Unlocked!
          </h3>
          <div className="space-y-2">
            {newAchievements.map((achievement, index) => (
              <motion.div
                key={achievement.id}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.8 + index * 0.1 }}
                className="flex items-center gap-3 bg-black/20 rounded-lg p-3"
              >
                <span className="text-2xl">{achievement.icon}</span>
                <div>
                  <div className="text-sm font-semibold text-white">{achievement.name}</div>
                  <div className="text-xs text-white/60">{achievement.description}</div>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}
      
      {/* Learning Points */}
      <div className="bg-[#1a1b1e] rounded-lg p-6 border border-white/5">
        <h3 className="text-lg font-semibold text-white mb-3">📚 Key Takeaways</h3>
        <ul className="text-sm text-white/70 space-y-2">
          <li>• You successfully simulated a real-world AD attack</li>
          <li>• This technique is used in actual penetration tests</li>
          <li>• Understanding defense helps improve security posture</li>
          <li>• Continue practicing to master more advanced techniques</li>
        </ul>
      </div>
    </div>
  );
}

// Stat Card Component
function StatCard({ icon, label, value, color, delay }) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay }}
      className="bg-[#1a1b1e] rounded-lg p-4 border border-white/5"
    >
      <div className={`flex items-center gap-2 mb-2 ${color}`}>
        {icon}
        <div className="text-xs text-white/40">{label}</div>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
    </motion.div>
  );
}
