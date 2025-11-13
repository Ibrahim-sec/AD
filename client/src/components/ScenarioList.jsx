import React from 'react';
import { deleteCustomScenario } from '../utils/scenarioStorage';

export default function ScenarioList({ 
  scenarios, 
  title, 
  onSelect, 
  onEdit, 
  onDelete,
  isBuiltIn = false 
}) {
  const handleDelete = (id) => {
    if (window.confirm('Are you sure you want to delete this scenario?')) {
      if (deleteCustomScenario(id)) {
        onDelete && onDelete(id);
      }
    }
  };

  if (!scenarios || scenarios.length === 0) {
    return (
      <div className="scenario-list empty">
        <h4>{title}</h4>
        <p className="empty-message">No scenarios available</p>
      </div>
    );
  }

  return (
    <div className="scenario-list">
      <h4>{title}</h4>
      <div className="scenarios-grid">
        {scenarios.map(scenario => (
          <div key={scenario.id} className="scenario-card">
            <div className="scenario-header">
              <h5>{scenario.name}</h5>
              <span className={`difficulty-badge difficulty-${scenario.difficulty.toLowerCase()}`}>
                {scenario.difficulty}
              </span>
            </div>
            
            <p className="scenario-target">Target: {scenario.mission.target}</p>
            <p className="scenario-steps">Steps: {scenario.steps.length}</p>
            
            <div className="scenario-actions">
              <button 
                onClick={() => onSelect(scenario)} 
                className="btn-small btn-primary"
              >
                Play
              </button>
              {!isBuiltIn && (
                <>
                  <button 
                    onClick={() => onEdit(scenario)} 
                    className="btn-small btn-secondary"
                  >
                    Edit
                  </button>
                  <button 
                    onClick={() => handleDelete(scenario.id)} 
                    className="btn-small btn-danger"
                  >
                    Delete
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
