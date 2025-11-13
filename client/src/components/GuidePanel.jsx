import { BookOpen, Lightbulb, Terminal, ChevronDown } from 'lucide-react';
import { Streamdown } from 'streamdown';
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

export default function GuidePanel({ scenario, currentStep, tutorialMode = false, onTutorialToggle }) {
  const { guide } = scenario;
  const currentGuideStep = guide.steps[currentStep];

  return (
    <div className="panel guide-panel">
      <Collapsible defaultOpen={true}>
        <div className="panel-header">
          <BookOpen size={20} />
          <h2>Attack Guide</h2>
          <CollapsibleTrigger asChild>
            <button className="ml-auto" title="Toggle Guide Visibility">
                <ChevronDown size={20} className="collapsible-icon" />
            </button>
          </CollapsibleTrigger>
        </div>
        
        <CollapsibleContent>
          <div className="panel-content">
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
      {/* Moved Tutorial Toggle outside the collapsible content so it is always visible */}
      {onTutorialToggle && (
        <button 
          className={`tutorial-toggle absolute top-3 right-16 ${tutorialMode ? 'active' : ''}`}
          onClick={onTutorialToggle}
          title="Toggle tutorial mode for hints and forgiving command matching"
        >
          <span>Tutorial</span>
          <div className="toggle-switch">
            <div className="toggle-dot"></div>
          </div>
        </button>
      )}
    </div>
  );
}