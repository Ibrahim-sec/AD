// client/src/components/GuidePanel.jsx

import { useState } from 'react';
import { Book, HelpCircle, Lightbulb } from 'lucide-react';
import { hasTheoryModule, getTheoryModule } from '../data/theory/index.js';
import TheoryModal from './TheoryModal';

export default function GuidePanel({ 
  scenario, 
  currentStep, 
  tutorialMode,
  onTutorialToggle,
  highlightedMachine,
  highlightedArrow,
  onShowBriefing,
  progress,
  onNodeClick
}) {
  const [showTheoryModal, setShowTheoryModal] = useState(false);
  const hasTheory = hasTheoryModule(scenario.id);
  const theoryModule = hasTheory ? getTheoryModule(scenario.id) : null;

  const step = scenario.steps[currentStep];
  const totalSteps = scenario.steps.length;
  const progressPercentage = Math.round(((currentStep + 1) / totalSteps) * 100);

  return (
    <>
      <div className="h-full flex flex-col bg-[#1a1b1e] overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-bold text-white">Attack Guide</h2>
            
            {/* Theory Button */}
            {hasTheory && (
              <button
                onClick={() => setShowTheoryModal(true)}
                className="px-3 py-1.5 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/50 rounded-lg text-xs font-semibold text-blue-400 transition-all flex items-center gap-1.5"
                title="Learn theory for this attack"
              >
                <Book className="w-3.5 h-3.5" />
                Theory
              </button>
            )}
          </div>

          {/* Progress Bar */}
          <div className="mb-3">
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="text-white/60">Step {currentStep + 1} of {totalSteps}</span>
              <span className="text-[#2D9CDB] font-semibold">{progressPercentage}%</span>
            </div>
            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
              <div 
                className="h-full bg-gradient-to-r from-[#2D9CDB] to-cyan-400 transition-all duration-500"
                style={{ width: `${progressPercentage}%` }}
              />
            </div>
          </div>

          {/* Tutorial Mode Toggle */}
          <button
            onClick={onTutorialToggle}
            className="w-full px-3 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-xs transition-all flex items-center justify-between"
          >
            <span className="text-white/70">Tutorial Mode</span>
            <div className={`w-10 h-5 rounded-full relative transition-all ${
              tutorialMode ? 'bg-[#2D9CDB]' : 'bg-white/20'
            }`}>
              <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full transition-all ${
                tutorialMode ? 'left-5' : 'left-0.5'
              }`} />
            </div>
          </button>
        </div>

        {/* Current Step Content */}
        <div className="flex-1 overflow-y-auto p-4">
          {step && (
            <div className="space-y-4">
              {/* Step Description */}
              <div className="bg-white/5 rounded-lg p-4 border border-white/10">
                <div className="flex items-start gap-3">
                  <div className="w-8 h-8 rounded-lg bg-[#2D9CDB]/20 flex items-center justify-center flex-shrink-0">
                    <span className="text-sm font-bold text-[#2D9CDB]">{currentStep + 1}</span>
                  </div>
                  <div className="flex-1">
                    <h3 className="text-sm font-semibold text-white mb-2">Objective</h3>
                    <p className="text-xs text-white/70 leading-relaxed">
                      {step.description}
                    </p>
                  </div>
                </div>
              </div>

              {/* Expected Command */}
              {step.expectedCommand && (
                <div className="bg-[#0a0b0d] rounded-lg p-3 border border-white/10">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-xs font-semibold text-white/60">Expected Command:</span>
                  </div>
                  <code className="text-xs text-green-400 font-mono block break-all">
                    {Array.isArray(step.expectedCommands) ? step.expectedCommands[0] : step.expectedCommand}
                  </code>
                </div>
              )}

              {/* Hints */}
              {tutorialMode && step.hintShort && (
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <Lightbulb className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-semibold text-yellow-400 mb-1">Hint</div>
                      <p className="text-xs text-yellow-300/80">{step.hintShort}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Common Mistakes */}
              {step.commonMistakes && step.commonMistakes.length > 0 && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <HelpCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-semibold text-red-400 mb-2">Common Mistakes:</div>
                      <ul className="space-y-1">
                        {step.commonMistakes.slice(0, 2).map((mistake, idx) => (
                          <li key={idx} className="text-xs text-red-300/80 flex items-start gap-1">
                            <span className="text-red-400">•</span>
                            <span>{mistake.message}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-white/10 flex-shrink-0">
          <button
            onClick={onShowBriefing}
            className="w-full px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-xs text-white/70 hover:text-white transition-all"
          >
            View Mission Brief
          </button>
        </div>
      </div>

      {/* Theory Modal */}
      {showTheoryModal && theoryModule && (
        <TheoryModal
          isOpen={showTheoryModal}
          onClose={() => setShowTheoryModal(false)}
          module={theoryModule}
          onComplete={() => {
            setShowTheoryModal(false);
            // Optional: Track completion
          }}
        />
      )}
    </>
  );
}
