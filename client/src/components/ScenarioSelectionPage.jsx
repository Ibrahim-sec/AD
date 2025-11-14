import { scenarioMap } from '../data/scenarios/index.js';
import { CheckCircle2, Circle, Swords } from 'lucide-react';
import { Link } from 'wouter';

export default function ScenarioSelectionPage({ allScenarios, progress, customScenarios, onScenarioSelect }) {
  const builtInScenarios = Object.values(scenarioMap) || [];
  const customScenariosList = customScenarios || [];
  
  // Combine lists for display
  const scenariosToDisplay = [
    { type: 'Built-in', list: builtInScenarios },
    { type: 'Custom', list: customScenariosList },
  ];

  return (
    <div className="scenario-selection-page">
      <div className="selector-header">
        <Swords size={28} className="text-accent-color" />
        <h1>Select Your Attack Scenario</h1>
      </div>
      
      <div className="scenarios-grid-container">
        {scenariosToDisplay.map(({ type, list }) => {
          if (list.length === 0 && type === 'Custom') return null; // Hide empty custom section
          
          return (
            <div key={type} className="scenarios-section">
              <h2 className="section-title">{type} Scenarios</h2>
              <div className="scenarios-list-grid">
                {list.map((scenario) => {
                  const isCompleted = progress.scenariosCompleted?.includes(scenario.id);
                  const difficultyClass = `difficulty-${scenario.difficulty?.toLowerCase() || 'beginner'}`;
                  
                  return (
                    // Link handles navigation to the simulator page
                    <Link 
                      key={scenario.id} 
                      href={`/scenario/${scenario.id}`}
                      onClick={() => onScenarioSelect(scenario)}
                      className={`scenario-card ${difficultyClass}`}
                    >
                      <div className="scenario-header">
                        <h3 className="scenario-title">{scenario.name || scenario.title}</h3>
                        <span className={`difficulty-badge ${difficultyClass}`}>
                          {scenario.difficulty || 'Beginner'}
                        </span>
                      </div>
                      
                      <p className="scenario-description">{scenario.description || scenario.mission.objective}</p>

                      <div className="scenario-footer">
                          <span className="step-count">
                              Steps: {scenario.steps.length}
                          </span>
                          <span className={`completion-status ${isCompleted ? 'completed' : ''}`}>
                              {isCompleted ? <CheckCircle2 size={16} /> : <Circle size={16} />} 
                              {isCompleted ? 'Completed' : 'New'}
                          </span>
                      </div>
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}