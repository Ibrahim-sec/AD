import { BookOpen, Lightbulb, Terminal, ChevronDown, Network } from 'lucide-react';
import { Streamdown } from 'streamdown';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';
import NetworkMap from './NetworkMap';

export default function GuidePanel({ 
  scenario, 
  currentStep, 
  tutorialMode = false, 
  onTutorialToggle,
  highlightedMachine,
  highlightedArrow
}) {
  const { guide } = scenario;
  const currentGuideStep = guide.steps[currentStep];

  return (
    <div className="panel guide-panel flex flex-col gap-4">
        
        {/* 1. Network Topology Panel (Collapsible) */}
        <Collapsible defaultOpen={true} className="border border-border-color rounded-lg overflow-hidden flex-shrink-0">
            <div className="panel-header !bg-transparent !border-b !border-border-color">
                <Network size={20} />
                <h2 className="!text-sm !font-medium flex-1">Network Topology</h2>
                <CollapsibleTrigger asChild>
                    <button title="Toggle Network Topology" className="text-server-text hover:text-accent-color transition">
                        <ChevronDown size={20} className="collapsible-icon" />
                    </button>
                </CollapsibleTrigger>
            </div>
            <CollapsibleContent>
                <div className="p-4 pt-0 bg-terminal-bg">
                    <NetworkMap 
                        highlightedMachine={highlightedMachine}
                        highlightedArrow={highlightedArrow}
                    />
                </div>
            </CollapsibleContent>
        </Collapsible>
        
        {/* 2. Attack Guide Panel (Main Content) */}
        <div className="flex-1 border border-border-color rounded-lg overflow-hidden flex flex-col min-h-0">
            <Collapsible defaultOpen={true} className="flex-1 flex flex-col min-h-0">
                <div className="panel-header !bg-transparent !border-b !border-border-color relative">
                    <BookOpen size={20} />
                    <h2 className="!text-sm !font-medium flex-1">Attack Guide</h2>
                    
                    {/* Tutorial Toggle */}
                    {onTutorialToggle && (
                        <button 
                            className={`tutorial-toggle absolute right-10 ${tutorialMode ? 'active' : ''}`}
                            onClick={onTutorialToggle}
                            title="Toggle tutorial mode for hints and forgiving command matching"
                        >
                            <span>Tutorial</span>
                            <div className="toggle-switch">
                                <div className="toggle-dot"></div>
                            </div>
                        </button>
                    )}
                    
                    <CollapsibleTrigger asChild>
                        <button title="Toggle Guide Visibility" className="text-server-text hover:text-accent-color transition">
                            <ChevronDown size={20} className="collapsible-icon" />
                        </button>
                    </CollapsibleTrigger>
                </div>
                
                <CollapsibleContent className="flex-1 overflow-y-auto">
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

                                {currentGuideStep.command && (
                                    <div className="command-box">
                                        <div className="command-box-header">
                                            <Terminal size={16} />
                                            <span>Command to Execute</span>
                                        </div>
                                        <code className="command-code">{currentGuideStep.command}</code>
                                    </div>
                                )}

                                {tutorialMode && currentGuideStep.hintShort && (
                                    <div className="tip-box">
                                        <Lightbulb size={16} />
                                        <span><strong>Hint:</strong> {currentGuideStep.hintShort}</span>
                                    </div>
                                )}

                                {currentGuideStep.tip && (
                                    <div className="tip-box">
                                        <Lightbulb size={16} />
                                        <span>{currentGuideStep.tip}</span>
                                    </div>
                                )}
                            </section>
                        )}

                        {/* All Steps Overview */}
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