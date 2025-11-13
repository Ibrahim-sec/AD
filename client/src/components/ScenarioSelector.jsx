import { CheckCircle2, Circle } from 'lucide-react';
import { scenarioMap } from '../data/scenarios/index.js';

export default function ScenarioSelector({ currentScenarioId, customScenarios = [], onScenarioSelect }) {
  const builtInScenarios = Object.values(scenarioMap) || [];
  const customScenariosList = customScenarios || [];
  
  return (
    <aside className="scenario-selector">
      <div className="selector-header">
        <h3>Attack Scenarios</h3>
      </div>
      
      {/* Built-in Scenarios */}
      {builtInScenarios.length > 0 && (
        <div className="scenarios-section">
          <h4 className="section-title">Built-in</h4>
          <div className="scenarios-list">
            {builtInScenarios.map((scenario) => (
              <button
                key={scenario.id}
                onClick={() => onScenarioSelect(scenario.id)}
                className={`scenario-button ${currentScenarioId === scenario.id ? 'active' : ''}`}
              >
                <div className="scenario-icon">
                  {currentScenarioId === scenario.id ? (
                    <CheckCircle2 size={20} />
                  ) : (
                    <Circle size={20} />
                  )}
                </div>
                
                <div className="scenario-info">
                  <h4>{scenario.title}</h4>
                  <p>{scenario.description}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
      
      {/* Custom Scenarios */}
      {customScenariosList.length > 0 && (
        <div className="scenarios-section">
          <h4 className="section-title">Custom</h4>
          <div className="scenarios-list">
            {customScenariosList.map((scenario) => (
              <button
                key={scenario.id}
                onClick={() => onScenarioSelect(scenario.id)}
                className={`scenario-button custom ${currentScenarioId === scenario.id ? 'active' : ''}`}
              >
                <div className="scenario-icon">
                  {currentScenarioId === scenario.id ? (
                    <CheckCircle2 size={20} />
                  ) : (
                    <Circle size={20} />
                  )}
                </div>
                
                <div className="scenario-info">
                  <h4>{scenario.name}</h4>
                  <p>{scenario.mission.target}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}
      
      <div className="selector-footer">
        <p className="footer-text">Select a scenario to begin the simulation</p>
      </div>
    </aside>
  );
}
