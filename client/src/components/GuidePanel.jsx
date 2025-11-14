// client/src/components/GuidePanel.jsx

import { useState, useEffect } from 'react';
import { Book, HelpCircle, Lightbulb, Map, NavigationIcon, Eye, ChevronRight } from 'lucide-react';
import { hasTheoryModule, getTheoryModule } from '../data/theory/index.js';
import TheoryModal from './TheoryModal';
import InteractiveNetworkMap from './InteractiveNetworkMap';

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
  const [activeTab, setActiveTab] = useState('guide'); // 'guide' or 'network'
  const [showMapSuggestion, setShowMapSuggestion] = useState(false);
  
  const hasTheory = hasTheoryModule(scenario.id);
  const theoryModule = hasTheory ? getTheoryModule(scenario.id) : null;

  const step = scenario.steps[currentStep];
  const totalSteps = scenario.steps.length;
  const progressPercentage = Math.round(((currentStep + 1) / totalSteps) * 100);

  // Determine current attack position in network
  const getCurrentPosition = () => {
    // Logic to determine which machines are involved in current step
    const positions = [];
    
    if (currentStep === 0) {
      positions.push('attacker');
    } else if (step?.description?.toLowerCase().includes('domain controller') || 
               step?.description?.toLowerCase().includes('dc')) {
      positions.push('attacker', 'target', 'dc');
    } else if (step?.description?.toLowerCase().includes('target') ||
               step?.description?.toLowerCase().includes('server')) {
      positions.push('attacker', 'target');
    } else {
      positions.push('attacker');
    }
    
    return positions;
  };

  const currentPosition = getCurrentPosition();

  // Auto-suggest network map at key moments
  useEffect(() => {
    // Show suggestion when moving to steps that involve network movement
    const networkKeywords = ['connect', 'access', 'move', 'lateral', 'domain controller', 'dc', 'compromise'];
    const hasNetworkMovement = networkKeywords.some(keyword => 
      step?.description?.toLowerCase().includes(keyword)
    );
    
    if (hasNetworkMovement && activeTab === 'guide') {
      setShowMapSuggestion(true);
      const timer = setTimeout(() => setShowMapSuggestion(false), 8000);
      return () => clearTimeout(timer);
    }
  }, [currentStep, step?.description, activeTab]);

  // Get machine icon color
  const getMachineColor = (machineName) => {
    if (currentPosition.includes(machineName)) {
      return 'text-[#2D9CDB]';
    }
    return 'text-white/30';
  };

  return (
    <>
      <div className="h-full flex flex-col bg-[#1a1b1e] overflow-hidden">
        {/* Header */}
        <div className="p-4 border-b border-white/10 flex-shrink-0">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-bold text-white">Learning Center</h2>
            
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

          {/* Mini Network Breadcrumb */}
          <div className="mb-3 bg-white/5 rounded-lg p-2 border border-white/10">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-white/40 uppercase font-semibold">Attack Position</span>
              <button
                onClick={() => setActiveTab('network')}
                className="text-[10px] text-[#2D9CDB] hover:text-[#2D9CDB]/80 flex items-center gap-1 transition-colors"
              >
                <Eye className="w-3 h-3" />
                View Map
              </button>
            </div>
            <div className="flex items-center gap-1.5 text-xs">
              <div className={`flex items-center gap-1 transition-colors ${getMachineColor('attacker')}`}>
                <div className={`w-2 h-2 rounded-full ${currentPosition.includes('attacker') ? 'bg-[#2D9CDB]' : 'bg-white/20'}`} />
                <span className="font-mono text-[10px]">Attacker</span>
              </div>
              
              {currentPosition.length > 1 && (
                <>
                  <ChevronRight className="w-3 h-3 text-white/30" />
                  <div className={`flex items-center gap-1 transition-colors ${getMachineColor('target')}`}>
                    <div className={`w-2 h-2 rounded-full ${currentPosition.includes('target') ? 'bg-[#2D9CDB]' : 'bg-white/20'}`} />
                    <span className="font-mono text-[10px]">Target</span>
                  </div>
                </>
              )}
              
              {currentPosition.includes('dc') && (
                <>
                  <ChevronRight className="w-3 h-3 text-white/30" />
                  <div className={`flex items-center gap-1 transition-colors ${getMachineColor('dc')}`}>
                    <div className={`w-2 h-2 rounded-full ${currentPosition.includes('dc') ? 'bg-[#2D9CDB]' : 'bg-white/20'}`} />
                    <span className="font-mono text-[10px]">DC</span>
                  </div>
                </>
              )}
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex items-center gap-2 mb-3">
            <button
              onClick={() => setActiveTab('guide')}
              className={`flex-1 px-3 py-2 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-2 ${
                activeTab === 'guide'
                  ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/20'
                  : 'bg-white/5 text-white/60 hover:text-white hover:bg-white/10'
              }`}
            >
              <Book className="w-4 h-4" />
              Attack Guide
            </button>
            
            <button
              onClick={() => setActiveTab('network')}
              className={`flex-1 px-3 py-2 rounded-lg text-xs font-semibold transition-all flex items-center justify-center gap-2 relative ${
                activeTab === 'network'
                  ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/20'
                  : 'bg-white/5 text-white/60 hover:text-white hover:bg-white/10'
              }`}
            >
              <Map className="w-4 h-4" />
              Network Map
              {showMapSuggestion && activeTab !== 'network' && (
                <div className="absolute -top-1 -right-1 w-3 h-3 bg-yellow-400 rounded-full animate-ping" />
              )}
            </button>
          </div>

          {/* Progress Bar - Only show on Guide tab */}
          {activeTab === 'guide' && (
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
          )}

          {/* Tutorial Mode Toggle - Only show on Guide tab */}
          {activeTab === 'guide' && (
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
          )}
        </div>

        {/* Tab Content */}
        <div className="flex-1 overflow-hidden">
          {activeTab === 'guide' ? (
            // Attack Guide Content
            <div className="h-full overflow-y-auto p-4">
              {/* Map Suggestion Banner */}
              {showMapSuggestion && (
                <div className="mb-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-3 animate-pulse">
                  <div className="flex items-start gap-2">
                    <NavigationIcon className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <div className="text-xs font-semibold text-yellow-400 mb-1">Network Movement Detected!</div>
                      <p className="text-xs text-yellow-300/80 mb-2">
                        This step involves network topology. View the network map to understand the attack path.
                      </p>
                      <button
                        onClick={() => setActiveTab('network')}
                        className="text-xs bg-yellow-500/20 hover:bg-yellow-500/30 px-3 py-1.5 rounded border border-yellow-500/50 transition-all flex items-center gap-1"
                      >
                        <Map className="w-3 h-3" />
                        View Network Map
                      </button>
                    </div>
                  </div>
                </div>
              )}

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

                  {/* Quick Access to Network Map */}
                  {currentPosition.length > 1 && (
                    <button
                      onClick={() => setActiveTab('network')}
                      className="w-full px-4 py-3 bg-gradient-to-r from-[#2D9CDB]/10 to-cyan-500/10 hover:from-[#2D9CDB]/20 hover:to-cyan-500/20 border border-[#2D9CDB]/30 rounded-lg text-xs transition-all flex items-center justify-between group"
                    >
                      <div className="flex items-center gap-2">
                        <Map className="w-4 h-4 text-[#2D9CDB]" />
                        <div className="text-left">
                          <div className="text-white font-semibold">View Network Topology</div>
                          <div className="text-white/50 text-[10px]">See your position in the attack chain</div>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-[#2D9CDB] group-hover:translate-x-1 transition-transform" />
                    </button>
                  )}
                </div>
              )}
            </div>
          ) : (
            // Network Map Content
            <div className="h-full flex flex-col bg-[#0a0b0d]">
              <div className="p-4 border-b border-white/10">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-sm font-semibold text-white">Network Topology</h3>
                  <div className="flex items-center gap-2">
                    <div className="flex items-center gap-1 text-[10px] text-white/50">
                      <div className="w-2 h-2 rounded-full bg-[#2D9CDB]" />
                      <span>Active</span>
                    </div>
                    <div className="flex items-center gap-1 text-[10px] text-white/50">
                      <div className="w-2 h-2 rounded-full bg-white/20" />
                      <span>Inactive</span>
                    </div>
                  </div>
                </div>
                <p className="text-xs text-white/50">
                  Click on machines to view details
                </p>
              </div>
              
              <div className="flex-1 overflow-hidden relative">
                {scenario && scenario.network ? (
                  <InteractiveNetworkMap
                    scenario={scenario}
                    currentStep={currentStep}
                    highlightedMachine={highlightedMachine}
                    highlightedArrow={highlightedArrow}
                    onNodeClick={onNodeClick}
                    progress={progress}
                  />
                ) : (
                  <div className="flex items-center justify-center h-full">
                    <div className="text-center">
                      <div className="text-white/40 mb-2">
                        <Map className="w-12 h-12 mx-auto mb-2" />
                      </div>
                      <p className="text-sm text-white/60">Loading network topology...</p>
                    </div>
                  </div>
                )}
              </div>
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
