import { useState } from 'react';
import { Book, Target, CheckCircle, Circle, Radio, Info, Play } from 'lucide-react';
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
  const [activeTab, setActiveTab] = useState('guide'); // 'guide' or 'topology'

  if (!scenario) {
    return (
      <div className="guide-panel h-full flex items-center justify-center">
        <div className="text-center text-white/40">
          <Book className="w-12 h-12 mx-auto mb-4 opacity-50" />
          <p>No scenario selected</p>
        </div>
      </div>
    );
  }

  const step = scenario.steps[currentStep];
  const isCompleted = currentStep >= scenario.steps.length;

  return (
    <div className="guide-panel h-full flex flex-col bg-[#101214] border-r border-white/5">
      {/* Header */}
      <div className="flex-shrink-0 p-4 border-b border-white/10">
        <div className="flex items-start justify-between mb-3">
          <div className="flex items-center gap-2">
            <Target className="w-5 h-5 text-[#2D9CDB]" />
            <h2 className="text-lg font-bold text-white">{scenario.title}</h2>
          </div>
          <button
            onClick={onShowBriefing}
            className="text-[#2D9CDB] hover:text-[#2D9CDB]/80 transition-colors"
            title="Show mission briefing"
          >
            <Info className="w-5 h-5" />
          </button>
        </div>

        {/* Difficulty Badge */}
        <div className="flex items-center gap-2 mb-3">
          <span
            className={`px-2 py-1 rounded text-xs font-semibold ${
              scenario.difficulty === 'Beginner'
                ? 'bg-green-500/20 text-green-400 border border-green-500/30'
                : scenario.difficulty === 'Intermediate'
                ? 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30'
                : 'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}
          >
            {scenario.difficulty}
          </span>
          <span className="text-xs text-white/40">
            Target: {scenario.network.domain}
          </span>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 bg-[#0a0b0d] rounded-lg p-1">
          <button
            onClick={() => setActiveTab('guide')}
            className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === 'guide'
                ? 'bg-[#2D9CDB] text-white'
                : 'text-white/60 hover:text-white hover:bg-white/5'
            }`}
          >
            <Book className="w-4 h-4 inline mr-2" />
            Attack Guide
          </button>
          <button
            onClick={() => setActiveTab('topology')}
            className={`flex-1 px-3 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === 'topology'
                ? 'bg-[#2D9CDB] text-white'
                : 'text-white/60 hover:text-white hover:bg-white/5'
            }`}
          >
            <Radio className="w-4 h-4 inline mr-2" />
            Network Map
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {activeTab === 'guide' ? (
          <div className="p-4 space-y-6">
            {/* Scenario Description */}
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-white/80 uppercase tracking-wide">
                Objective
              </h3>
              <p className="text-sm text-white/70 leading-relaxed">
                {scenario.description}
              </p>
            </div>

            {/* Tutorial Mode Toggle */}
            <div className="bg-[#0a0b0d] rounded-lg p-3 border border-white/5">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Play className="w-4 h-4 text-[#2D9CDB]" />
                  <span className="text-sm font-semibold text-white">Tutorial Mode</span>
                </div>
                <button
                  onClick={onTutorialToggle}
                  className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                    tutorialMode ? 'bg-[#2D9CDB]' : 'bg-white/20'
                  }`}
                >
                  <span
                    className={`inline-block h-3 w-3 transform rounded-full bg-white transition-transform ${
                      tutorialMode ? 'translate-x-5' : 'translate-x-1'
                    }`}
                  />
                </button>
              </div>
              <p className="text-xs text-white/50">
                {tutorialMode
                  ? 'Forgiving command matching and helpful hints enabled'
                  : 'Precise command matching required'}
              </p>
            </div>

            {/* Progress Indicator */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-white/60">Progress</span>
                <span className="text-[#2D9CDB] font-semibold">
                  {Math.min(currentStep + 1, scenario.steps.length)} / {scenario.steps.length}
                </span>
              </div>
              <div className="h-1.5 bg-white/5 rounded-full overflow-hidden">
                <div
                  className="h-full bg-[#2D9CDB] transition-all duration-500 ease-out"
                  style={{
                    width: `${((Math.min(currentStep + 1, scenario.steps.length)) / scenario.steps.length) * 100}%`
                  }}
                />
              </div>
            </div>

            {/* Steps List */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-white/80 uppercase tracking-wide flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-[#2D9CDB]" />
                Attack Steps
              </h3>

              <div className="space-y-2">
                {scenario.steps.map((stepItem, index) => {
                  const isPast = index < currentStep;
                  const isCurrent = index === currentStep;
                  const isFuture = index > currentStep;

                  return (
                    <div
                      key={index}
                      className={`relative pl-8 pb-4 ${
                        isFuture ? 'opacity-40' : 'opacity-100'
                      }`}
                    >
                      {/* Vertical line */}
                      {index < scenario.steps.length - 1 && (
                        <div
                          className={`absolute left-[11px] top-6 bottom-0 w-0.5 ${
                            isPast ? 'bg-[#2D9CDB]' : 'bg-white/10'
                          }`}
                        />
                      )}

                      {/* Step indicator */}
                      <div className="absolute left-0 top-0">
                        {isPast ? (
                          <CheckCircle className="w-6 h-6 text-[#2D9CDB] fill-[#2D9CDB]/20" />
                        ) : isCurrent ? (
                          <div className="relative">
                            <Circle className="w-6 h-6 text-[#2D9CDB]" />
                            <div className="absolute inset-0 flex items-center justify-center">
                              <div className="w-2 h-2 bg-[#2D9CDB] rounded-full animate-pulse" />
                            </div>
                          </div>
                        ) : (
                          <Circle className="w-6 h-6 text-white/20" />
                        )}
                      </div>

                      {/* Step content */}
                      <div
                        className={`space-y-1 ${
                          isCurrent
                            ? 'bg-[#2D9CDB]/10 -ml-2 -mr-4 pl-2 pr-4 py-2 rounded-lg border-l-2 border-[#2D9CDB]'
                            : ''
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1">
                            <div className="text-xs font-semibold text-white/90 mb-1">
                              Step {index + 1}
                            </div>
                            <p className="text-sm text-white/70 leading-relaxed">
                              {stepItem.description}
                            </p>
                          </div>
                        </div>

                        {/* Show command preview for current step */}
                        {isCurrent && stepItem.expectedCommand && (
                          <div className="mt-2 bg-[#0a0b0d] rounded px-3 py-2 border border-white/5">
                            <div className="text-xs text-white/40 mb-1">Expected Command:</div>
                            <code className="text-xs text-[#2D9CDB] font-mono break-all">
                              {Array.isArray(stepItem.expectedCommands) && stepItem.expectedCommands.length > 0
                                ? stepItem.expectedCommands[0]
                                : stepItem.expectedCommand}
                            </code>
                          </div>
                        )}

                        {/* Show hint for current step if available */}
                        {isCurrent && stepItem.hintShort && tutorialMode && (
                          <div className="mt-2 bg-yellow-500/10 rounded px-3 py-2 border border-yellow-500/20">
                            <div className="text-xs text-yellow-400 font-medium flex items-center gap-1">
                              <Info className="w-3 h-3" />
                              Hint
                            </div>
                            <p className="text-xs text-yellow-300/80 mt-1">
                              {stepItem.hintShort}
                            </p>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Completion Message */}
            {isCompleted && (
              <div className="bg-green-500/10 rounded-lg p-4 border border-green-500/20">
                <div className="flex items-center gap-2 mb-2">
                  <CheckCircle className="w-5 h-5 text-green-400" />
                  <span className="text-sm font-semibold text-green-400">
                    Scenario Complete!
                  </span>
                </div>
                <p className="text-xs text-green-300/80">
                  You've successfully completed all attack steps. Review your mission debrief for
                  detailed results.
                </p>
              </div>
            )}

            {/* Learning Resources */}
            <div className="space-y-2 pt-4 border-t border-white/5">
              <h3 className="text-sm font-semibold text-white/80 uppercase tracking-wide">
                Learn More
              </h3>
              <div className="space-y-2">
                <a
                  href={`https://attack.mitre.org/techniques/${scenario.mitreAttack || 'T1003'}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block text-xs text-[#2D9CDB] hover:text-[#2D9CDB]/80 transition-colors"
                >
                  → MITRE ATT&CK Framework
                </a>
                <a
                  href="https://www.hackingarticles.in/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="block text-xs text-[#2D9CDB] hover:text-[#2D9CDB]/80 transition-colors"
                >
                  → Detailed Write-ups
                </a>
              </div>
            </div>
          </div>
        ) : (
          // Network Topology Tab
          <div className="h-full p-4">
            <div className="h-full min-h-[500px] rounded-lg overflow-hidden">
              <InteractiveNetworkMap
                network={scenario.network}
                highlightedMachine={highlightedMachine}
                highlightedArrow={highlightedArrow}
                compromisedNodes={
                  progress?.scenariosCompleted?.map(id => {
                    // Map scenario IDs to node IDs
                    if (id === 'pass-the-hash' || id === 'kerberoasting') return 'target';
                    if (id === 'dcsync' || id === 'golden-ticket') return 'dc';
                    return null;
                  }).filter(Boolean) || ['attacker']
                }
                onNodeClick={onNodeClick}
                currentStep={currentStep + 1}
                showTraffic={true}
              />
            </div>

            {/* Network Info Panel */}
            <div className="mt-4 space-y-3">
              <div className="bg-[#0a0b0d] rounded-lg p-3 border border-white/5">
                <h4 className="text-xs font-semibold text-white/80 uppercase tracking-wide mb-2">
                  Network Information
                </h4>
                <div className="space-y-2 text-xs">
                  <div className="flex justify-between">
                    <span className="text-white/50">Domain:</span>
                    <span className="text-white/90 font-mono">{scenario.network.domain}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-white/50">Attacker IP:</span>
                    <span className="text-[#2D9CDB] font-mono">{scenario.network.attacker.ip}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-white/50">Target IP:</span>
                    <span className="text-blue-400 font-mono">{scenario.network.target.ip}</span>
                  </div>
                  {scenario.network.dc && (
                    <div className="flex justify-between">
                      <span className="text-white/50">DC IP:</span>
                      <span className="text-purple-400 font-mono">{scenario.network.dc.ip}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Interactive Instructions */}
              <div className="bg-[#2D9CDB]/10 rounded-lg p-3 border border-[#2D9CDB]/20">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-[#2D9CDB] flex-shrink-0 mt-0.5" />
                  <div className="text-xs text-white/70">
                    <p className="font-semibold text-[#2D9CDB] mb-1">Interactive Controls</p>
                    <ul className="space-y-1 text-white/60">
                      <li>• <strong>Click & Drag</strong> to pan the network</li>
                      <li>• <strong>Scroll</strong> to zoom in/out</li>
                      <li>• <strong>Click nodes</strong> for detailed info</li>
                      <li>• <strong>Watch</strong> live traffic animations</li>
                    </ul>
                  </div>
                </div>
              </div>

              {/* Attack Progress Info */}
              {currentStep > 0 && (
                <div className="bg-green-500/10 rounded-lg p-3 border border-green-500/20">
                  <div className="flex items-center gap-2 mb-2">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <span className="text-xs font-semibold text-green-400">
                      Attack Progress
                    </span>
                  </div>
                  <p className="text-xs text-green-300/80">
                    {currentStep} of {scenario.steps.length} steps completed. 
                    {highlightedMachine && (
                      <span className="block mt-1">
                        Currently targeting: <strong>{highlightedMachine}</strong>
                      </span>
                    )}
                  </p>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Footer Stats */}
      <div className="flex-shrink-0 p-3 border-t border-white/10 bg-[#0a0b0d]">
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-4">
            <div>
              <span className="text-white/40">Score:</span>
              <span className="ml-1 text-[#2D9CDB] font-semibold">
                {progress?.totalScore || 0}
              </span>
            </div>
            <div>
              <span className="text-white/40">Rank:</span>
              <span className="ml-1 text-white/90 font-semibold">
                {progress?.rank || 'Novice'}
              </span>
            </div>
          </div>
          <div className="text-white/40">
            {progress?.scenariosCompleted?.length || 0} scenarios completed
          </div>
        </div>
      </div>
    </div>
  );
}
