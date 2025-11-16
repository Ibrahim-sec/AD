// client/src/components/CampaignModal.jsx

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Lock, Trophy, Clock, Zap, CheckCircle } from 'lucide-react';
import { campaigns, isCampaignUnlocked } from '@/data/campaigns/index';
import { startCampaign } from '@/lib/campaignManager';
import { useLocation } from 'wouter';

export default function CampaignModal({ isOpen, onClose, progress, setProgress }) {
  const [, setLocation] = useLocation();
  
  const handleStartCampaign = (campaignId) => {
    const updatedProgress = startCampaign(progress, campaignId);
    setProgress(updatedProgress);
    
    // Navigate to first scenario
    const campaign = campaigns[campaignId];
    const firstScenario = campaign.scenarios[0];
    setLocation(`/scenario/${firstScenario.id}`);
    onClose();
  };
  
  if (!isOpen) return null;
  
  return (
    <AnimatePresence>
      <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.9 }}
          className="bg-[#101214] border border-white/10 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"
        >
          {/* Header */}
          <div className="sticky top-0 bg-[#101214] border-b border-white/10 p-6 flex items-center justify-between z-10">
            <div>
              <h2 className="text-2xl font-bold text-white">Campaign Mode</h2>
              <p className="text-white/60 text-sm mt-1">Multi-scenario attack chains with story progression</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/5 rounded-lg transition-colors"
            >
              <X className="w-6 h-6 text-white/60" />
            </button>
          </div>
          
          {/* Campaigns Grid */}
          <div className="p-6 space-y-4">
            {Object.values(campaigns).map(campaign => {
              const locked = !isCampaignUnlocked(campaign.id, progress);
              const completed = progress.completedCampaigns?.includes(campaign.id);
              const active = progress.activeCampaign?.id === campaign.id;
              
              return (
                <div
                  key={campaign.id}
                  className={`relative bg-[#1a1d24] border rounded-xl p-6 transition-all ${
                    locked ? 'opacity-60 border-white/10' : 'hover:border-[#2D9CDB] cursor-pointer border-white/10'
                  }`}
                >
                  {/* Campaign Badge */}
                  <div className="flex items-start gap-4">
                    <div className="text-5xl">{campaign.badge}</div>
                    
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-bold text-white">{campaign.title}</h3>
                        {completed && <CheckCircle className="w-5 h-5 text-green-400" />}
                        {active && (
                          <span className="px-2 py-0.5 bg-yellow-400 text-black text-xs rounded-full font-semibold">
                            IN PROGRESS
                          </span>
                        )}
                        {locked && <Lock className="w-5 h-5 text-red-400" />}
                      </div>
                      
                      <p className="text-white/70 text-sm mb-4">{campaign.description}</p>
                      
                      {/* Meta Info */}
                      <div className="flex items-center gap-4 text-sm text-white/60 mb-4">
                        <span className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          {campaign.estimatedTime}
                        </span>
                        <span className="flex items-center gap-1">
                          <Zap className="w-4 h-4" />
                          +{campaign.xpReward} XP
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                          campaign.difficulty === 'Beginner' ? 'bg-green-500/20 text-green-400' :
                          campaign.difficulty === 'Intermediate' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          {campaign.difficulty}
                        </span>
                      </div>
                      
                      {/* Scenarios Preview */}
                      <div className="space-y-2 mb-4">
                        <p className="text-xs text-white/40 uppercase font-semibold">Scenarios ({campaign.scenarios.length}):</p>
                        <div className="flex flex-wrap gap-2">
                          {campaign.scenarios.map((s, i) => (
                            <div
                              key={i}
                              className="px-3 py-1 bg-white/5 rounded-full text-xs text-white/70"
                            >
                              {i + 1}. {s.description}
                              {s.required !== false && <span className="text-yellow-400 ml-1">*</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      {/* Prerequisites */}
                      {campaign.prerequisites.length > 0 && (
                        <div className="text-xs text-white/50 mb-4">
                          Requires: {campaign.prerequisites.join(', ')}
                        </div>
                      )}
                      
                      {/* Action Button */}
                      <button
                        disabled={locked}
                        onClick={() => handleStartCampaign(campaign.id)}
                        className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                          locked ? 'bg-white/5 text-white/30 cursor-not-allowed' :
                          completed ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' :
                          active ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30' :
                          'bg-[#2D9CDB] text-white hover:bg-[#2D9CDB]/80'
                        }`}
                      >
                        {completed ? '✓ Replay Campaign' :
                         active ? 'Continue Campaign' :
                         locked ? '🔒 Locked' :
                         'Start Campaign'}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
