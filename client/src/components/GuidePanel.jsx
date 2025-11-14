import { useState, useEffect, useMemo } from 'react';
import { BookOpen, Lightbulb, Terminal, ChevronDown, Network } from 'lucide-react';
import { Streamdown } from 'streamdown';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import NetworkMap from './NetworkMap';

// --- Helper Functions ---
const GUIDE_COLLAPSE_KEY = 'guide_panel_open';
const NETWORK_COLLAPSE_KEY = 'network_map_open';

const getInitialCollapseState = (key) => {
    try {
        const stored = localStorage.getItem(key);
        if (stored === null) return true; 
        return JSON.parse(stored);
    } catch (e) {
        return true;
    }
};

const compromiseMap = {
  'pass-the-hash': ['target', 'dc'],
  'dcsync': ['dc'],
  'golden-ticket': ['dc']
};

// --- Main Component ---
export default function GuidePanel({ 
  scenario, 
  currentStep, 
  tutorialMode = false, 
  onTutorialToggle,
  highlightedMachine,
  highlightedArrow,
  progress,
  onNodeClick
}) {
  const { guide } = scenario;
  const currentGuideStep = guide.steps[currentStep];

  // --- Local State ---
  const [isNetworkOpen, setIsNetworkOpen] = useState(() => getInitialCollapseState(NETWORK_COLLAPSE_KEY));
  const [isGuideOpen, setIsGuideOpen] = useState(() => getInitialCollapseState(GUIDE_COLLAPSE_KEY));
  
  const handleNetworkToggle = (open) => {
      setIsNetworkOpen(open);
      try {
          localStorage.setItem(NETWORK_COLLAPSE_KEY, JSON.stringify(open));
      } catch (e) { /* ignore */ }
  };
  
  const handleGuideToggle = (open) => {
      setIsGuideOpen(open);
      try {
          localStorage.setItem(GUIDE_COLLAPSE_KEY, JSON.stringify(open));
      } catch (e) { /* ignore */ }
  };

  // --- Compute compromised nodes ---
  const compromisedNodes = useMemo(() => {
    const nodes = new Set();
    nodes.add('attacker'); 
    if (progress && progress.scenariosCompleted) {
      progress.scenariosCompleted.forEach(scenarioId => {
        if (compromiseMap[scenarioId]) {
          compromiseMap[scenarioId].forEach(node => nodes.add(node));
        }
      });
    }
    return Array.from(nodes);
  }, [progress]);

  // --- RENDERING (WITH FIX) ---
  return (
    <div className="panel guide-panel flex flex-col gap-4 h-full overflow-hidden">
        
        {/* 1. Network Topology Panel (Collapsible, Fixed Height, Doesn't Grow) */}
        <Collapsible 
            open={isNetworkOpen}
            onOpenChange={handleNetworkToggle}
            className="border border-border-color rounded-lg overflow-hidden flex-shrink-0"
        >
            <div className="panel-header !bg-transparent !border-b !border-border-color">
                <Network size={20} />
                <h2 className="!text-sm !font-medium flex-1">Network Topology</h2>
                <CollapsibleTrigger asChild>
                    <button 
                        title="Toggle Network Topology" 
                        className="text-server-text hover:text-accent-color transition"
                    >
                        <ChevronDown size={20} className="collapsible-icon" />
                    </button>
                </CollapsibleTrigger>
            </div>
            <CollapsibleContent>
                <div className="p-4 pt-0 bg-terminal-bg">
                    <NetworkMap 
                        highlightedMachine={highlightedMachine}
                        highlightedArrow={highlightedArrow}
                        network={scenario.network}
                        compromisedNodes={compromisedNodes}
                        onNodeClick={onNodeClick}
                    />
                </div>
            </CollapsibleContent>
        </Collapsible>
        
        {/* 
          2. Attack Guide Panel (Main Content) 
          FIXED: Uses flex-1 + overflow-hidden + min-h-0 to fill remaining space
          and scroll internally without affecting page height
        */}
        <div className="flex-1 border border-border-color rounded-lg overflow-hidden flex flex-col min-h-0">
            <Collapsible 
                open={isGuideOpen}
                onOpenChange={handleGuideToggle}
                className="flex-1 flex flex-col min-h-0 overflow-hidden"
            >
                {/* Header - Fixed, always visible */}
                <div className="panel-header !bg-transparent !border-b !border-border-color relative flex-shrink-0">
                    <BookOpen size={20} />
                    <h2 className="!text-sm !font-medium flex-1">Attack Guide</h2>
                    
                    {onTutorialToggle && (
                        <button 
                            className={`tutorial-toggle absolute right-10 ${tutorialMode ? 'active' : ''}`}
                            onClick={onTutorialToggle}
                            title="Toggle tutorial mode for extra hints on incorrect commands"
                        >
                            <span>Tutorial</span>
                            <div className="toggle-switch">
                                <div className="toggle-dot"></div>
                            </div>
                        </button>
                    )}
                    
                    <CollapsibleTrigger asChild>
                        <button 
                            title="Toggle Guide Visibility" 
                            className="text-server-text hover:text-accent-color transition"
                        >
                            <ChevronDown size={20} className="collapsible-icon" />
                        </button>
                    </CollapsibleTrigger>
                </div>
                
                {/* Content - Scrolls internally, doesn't affect page height */}
                <CollapsibleContent className="flex-1 overflow-y-auto min-h-0">
                    <div className="panel-content !p-4">
                        
                        {/* Overview Section */}
                        <section className="guide-section">
                            <h3 className="guide-section-title">Overview</h3>
                            <div className="guide-text">
                                <Streamdown>{guide.overview}</Streamdown>
                            </div>
                        </section>

                        {/* Current Step Section */}
                        {currentGuideStep && (
                            <section className="guide-section current-step">
                                <h3 className="guide-section-title">
                                    Current Step: {currentGuideStep.number}. {currentGuideStep.title}
                                </h3>
                                
                                <div className="guide-text">
                                    <p>{currentGuideStep.description}</p>
                                </div>
                                
                                {/* Command to Execute */}
                                {currentGuideStep.command && (
                                    <div className="command-box">
                                        <div className="command-box-header">
                                            <Terminal size={16} />
                                            <span>Command to Execute</span>
                                        </div>
                                        <code className="command-code">{currentGuideStep.command}</code>
                                    </div>
                                )}
                                
                                {/* Tutorial Mode Hint */}
                                {tutorialMode && currentGuideStep.hintShort && (
                                    <div className="tip-box">
                                        <Lightbulb size={16} />
                                        <span><strong>Hint:</strong> {currentGuideStep.hintShort}</span>
                                    </div>
                                )}
                                
                                {/* General Tip */}
                                {currentGuideStep.tip && (
                                    <div className="tip-box">
                                        <Lightbulb size={16} />
                                        <span>{currentGuideStep.tip}</span>
                                    </div>
                                )}
                            </section>
                        )}

                        {/* All Steps Section */}
                        <section className="guide-section">
                            <h3 className="guide-section-title">All Steps</h3>
                            <ol className="steps-list">
                                {guide.steps.map((step, index) => (
                                    <li 
                                        key={step.number} 
                                        className={`step-item ${index === currentStep ? 'active' : ''} ${index < currentStep ? 'completed' : ''}`}
                                    >
                                        <span className="step-number">{step.number}</span>
                                        <span className="step-title">{step.title}</span>
                                    </li>
                                ))}
                            </ol>
                        </section>
                    </div>
                </CollapsibleContent>
            </Collapsible>
        </div>
    </div>
  );
}
