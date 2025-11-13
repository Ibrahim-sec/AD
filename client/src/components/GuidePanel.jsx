import { BookOpen, Lightbulb, Terminal } from 'lucide-react';
import { Streamdown } from 'streamdown';

export default function GuidePanel({ scenario, currentStep, tutorialMode = false, onTutorialToggle }) {
  const { guide } = scenario;
  const currentGuideStep = guide.steps[currentStep];

  return (
    <div className="panel guide-panel">
      <div className="panel-header">
        <BookOpen size={20} />
        <h2>Attack Guide</h2>
        {onTutorialToggle && (
          <button 
            className={`tutorial-toggle ${tutorialMode ? 'active' : ''}`}
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
    </div>
  );
}
