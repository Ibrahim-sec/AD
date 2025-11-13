import React, { useState, useEffect } from 'react';
import { saveCustomScenario, deleteCustomScenario } from '../utils/scenarioStorage';
import { validateScenarioStructure, validateAndParseJSON } from '../utils/scenarioValidation';
import { getTemplate, templates } from '../utils/scenarioTemplates';

export default function ScenarioEditor({ onClose, initialScenario = null }) {
  const [scenario, setScenario] = useState(initialScenario || getEmptyScenario());
  const [errors, setErrors] = useState([]);
  const [successMessage, setSuccessMessage] = useState('');
  const [editingStepIndex, setEditingStepIndex] = useState(null);
  const [showTemplateModal, setShowTemplateModal] = useState(false);

  // Handle metadata field changes
  const handleMetadataChange = (field, value) => {
    setScenario(prev => ({
      ...prev,
      [field]: value
    }));
    setErrors([]);
  };

  // Handle machine configuration changes
  const handleMachineChange = (machineType, field, value) => {
    setScenario(prev => ({
      ...prev,
      machines: {
        ...prev.machines,
        [machineType]: {
          ...prev.machines[machineType],
          [field]: value
        }
      }
    }));
    setErrors([]);
  };

  // Handle mission field changes
  const handleMissionChange = (field, value) => {
    setScenario(prev => ({
      ...prev,
      mission: {
        ...prev.mission,
        [field]: value
      }
    }));
    setErrors([]);
  };

  // Handle step field changes
  const handleStepChange = (stepIndex, field, value) => {
    setScenario(prev => ({
      ...prev,
      steps: prev.steps.map((step, idx) =>
        idx === stepIndex ? { ...step, [field]: value } : step
      )
    }));
    setErrors([]);
  };

  // Add a new step
  const addStep = () => {
    const newStep = {
      id: scenario.steps.length + 1,
      description: '',
      expectedCommand: '',
      attackerOutput: '',
      internalOutput: '',
      dcOutput: '',
      hintShort: '',
      hintFull: '',
      scoreValue: 10
    };
    setScenario(prev => ({
      ...prev,
      steps: [...prev.steps, newStep]
    }));
  };

  // Delete a step
  const deleteStep = (index) => {
    setScenario(prev => ({
      ...prev,
      steps: prev.steps.filter((_, idx) => idx !== index)
    }));
  };

  // Move step up
  const moveStepUp = (index) => {
    if (index === 0) return;
    const newSteps = [...scenario.steps];
    [newSteps[index - 1], newSteps[index]] = [newSteps[index], newSteps[index - 1]];
    setScenario(prev => ({ ...prev, steps: newSteps }));
  };

  // Move step down
  const moveStepDown = (index) => {
    if (index === scenario.steps.length - 1) return;
    const newSteps = [...scenario.steps];
    [newSteps[index], newSteps[index + 1]] = [newSteps[index + 1], newSteps[index]];
    setScenario(prev => ({ ...prev, steps: newSteps }));
  };

  // Save scenario
  const handleSave = () => {
    const validation = validateScenarioStructure(scenario);
    if (!validation.valid) {
      setErrors(validation.errors);
      return;
    }

    if (saveCustomScenario(scenario)) {
      setSuccessMessage('Scenario saved successfully!');
      setTimeout(() => setSuccessMessage(''), 3000);
    } else {
      setErrors(['Failed to save scenario']);
    }
  };

  // Export scenario as JSON
  const handleExport = () => {
    const validation = validateScenarioStructure(scenario);
    if (!validation.valid) {
      setErrors(validation.errors);
      return;
    }

    const dataStr = JSON.stringify(scenario, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${scenario.id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  // Import scenario from JSON
  const handleImport = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e) => {
      const file = e.target.files[0];
      if (!file) return;

      const reader = new FileReader();
      reader.onload = (event) => {
        const validation = validateAndParseJSON(event.target.result);
        if (!validation.valid) {
          setErrors(validation.errors);
          return;
        }
        setScenario(validation.data);
        setErrors([]);
        setSuccessMessage('Scenario imported successfully!');
        setTimeout(() => setSuccessMessage(''), 3000);
      };
      reader.readAsText(file);
    };
    input.click();
  };

  // Create from template
  const handleCreateFromTemplate = (templateId) => {
    const template = getTemplate(templateId);
    if (template) {
      setScenario(template);
      setShowTemplateModal(false);
      setSuccessMessage('Scenario created from template!');
      setTimeout(() => setSuccessMessage(''), 3000);
    }
  };

  return (
    <div className="scenario-editor">
      <div className="editor-header">
        <h2>Scenario Editor</h2>
        <div className="editor-actions">
          <button onClick={handleSave} className="btn-primary">Save Scenario</button>
          <button onClick={handleExport} className="btn-secondary">Export JSON</button>
          <button onClick={handleImport} className="btn-secondary">Import JSON</button>
          <button onClick={() => setShowTemplateModal(true)} className="btn-secondary">From Template</button>
          <button onClick={onClose} className="btn-close">Close</button>
        </div>
      </div>

      {errors.length > 0 && (
        <div className="error-box">
          <h4>Validation Errors:</h4>
          <ul>
            {errors.map((err, idx) => <li key={idx}>{err}</li>)}
          </ul>
        </div>
      )}

      {successMessage && (
        <div className="success-box">{successMessage}</div>
      )}

      <div className="editor-content">
        {/* Metadata Section */}
        <section className="editor-section">
          <h3>Scenario Metadata</h3>
          <div className="form-group">
            <label>Scenario Name *</label>
            <input
              type="text"
              value={scenario.name}
              onChange={(e) => handleMetadataChange('name', e.target.value)}
              placeholder="e.g., BloodHound Reconnaissance"
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Scenario ID *</label>
              <input
                type="text"
                value={scenario.id}
                onChange={(e) => handleMetadataChange('id', e.target.value)}
                placeholder="e.g., bloodhound_custom_01"
              />
            </div>
            <div className="form-group">
              <label>Difficulty *</label>
              <select
                value={scenario.difficulty}
                onChange={(e) => handleMetadataChange('difficulty', e.target.value)}
              >
                <option value="Beginner">Beginner</option>
                <option value="Intermediate">Intermediate</option>
                <option value="Advanced">Advanced</option>
              </select>
            </div>
          </div>
        </section>

        {/* Mission Section */}
        <section className="editor-section">
          <h3>Mission Configuration</h3>
          <div className="form-group">
            <label>Target Domain *</label>
            <input
              type="text"
              value={scenario.mission.target}
              onChange={(e) => handleMissionChange('target', e.target.value)}
              placeholder="e.g., contoso.local"
            />
          </div>

          <div className="form-group">
            <label>Objective *</label>
            <textarea
              value={scenario.mission.objective}
              onChange={(e) => handleMissionChange('objective', e.target.value)}
              placeholder="Describe the attack objective..."
              rows="3"
            />
          </div>

          <div className="form-group">
            <label>Notes</label>
            <textarea
              value={scenario.mission.notes || ''}
              onChange={(e) => handleMissionChange('notes', e.target.value)}
              placeholder="Additional mission notes..."
              rows="2"
            />
          </div>
        </section>

        {/* Machines Section */}
        <section className="editor-section">
          <h3>Machine Configuration</h3>
          {['attacker', 'internal', 'dc'].map(machineType => (
            <div key={machineType} className="machine-config">
              <h4>{machineType.charAt(0).toUpperCase() + machineType.slice(1)} Machine</h4>
              <div className="form-row">
                <div className="form-group">
                  <label>Name</label>
                  <input
                    type="text"
                    value={scenario.machines[machineType].name}
                    onChange={(e) => handleMachineChange(machineType, 'name', e.target.value)}
                    placeholder="e.g., ATTACKER01"
                  />
                </div>
                <div className="form-group">
                  <label>IP Address</label>
                  <input
                    type="text"
                    value={scenario.machines[machineType].ip}
                    onChange={(e) => handleMachineChange(machineType, 'ip', e.target.value)}
                    placeholder="e.g., 10.0.0.5"
                  />
                </div>
              </div>
            </div>
          ))}
        </section>

        {/* Steps Section */}
        <section className="editor-section">
          <div className="steps-header">
            <h3>Attack Steps ({scenario.steps.length})</h3>
            <button onClick={addStep} className="btn-secondary">+ Add Step</button>
          </div>

          {scenario.steps.map((step, index) => (
            <div key={index} className="step-editor">
              <div className="step-header">
                <h4>Step {index + 1}: {step.description || 'Untitled'}</h4>
                <div className="step-controls">
                  <button onClick={() => moveStepUp(index)} disabled={index === 0} className="btn-small">↑</button>
                  <button onClick={() => moveStepDown(index)} disabled={index === scenario.steps.length - 1} className="btn-small">↓</button>
                  <button onClick={() => deleteStep(index)} className="btn-small btn-danger">Delete</button>
                </div>
              </div>

              <div className="form-group">
                <label>Description *</label>
                <input
                  type="text"
                  value={step.description}
                  onChange={(e) => handleStepChange(index, 'description', e.target.value)}
                  placeholder="What does this step do?"
                />
              </div>

              <div className="form-group">
                <label>Expected Command *</label>
                <input
                  type="text"
                  value={step.expectedCommand}
                  onChange={(e) => handleStepChange(index, 'expectedCommand', e.target.value)}
                  placeholder="e.g., neo4j-start"
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Score Value</label>
                  <input
                    type="number"
                    value={step.scoreValue}
                    onChange={(e) => handleStepChange(index, 'scoreValue', parseInt(e.target.value))}
                    min="0"
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Attacker Output *</label>
                <textarea
                  value={step.attackerOutput}
                  onChange={(e) => handleStepChange(index, 'attackerOutput', e.target.value)}
                  placeholder="What the attacker sees in their terminal..."
                  rows="4"
                />
              </div>

              <div className="form-group">
                <label>Internal Server Output</label>
                <textarea
                  value={step.internalOutput}
                  onChange={(e) => handleStepChange(index, 'internalOutput', e.target.value)}
                  placeholder="What appears in the internal server logs..."
                  rows="3"
                />
              </div>

              <div className="form-group">
                <label>Domain Controller Output</label>
                <textarea
                  value={step.dcOutput}
                  onChange={(e) => handleStepChange(index, 'dcOutput', e.target.value)}
                  placeholder="What appears in DC logs (optional)..."
                  rows="3"
                />
              </div>

              <div className="form-row">
                <div className="form-group">
                  <label>Short Hint</label>
                  <input
                    type="text"
                    value={step.hintShort}
                    onChange={(e) => handleStepChange(index, 'hintShort', e.target.value)}
                    placeholder="Brief hint for users..."
                  />
                </div>
              </div>

              <div className="form-group">
                <label>Full Hint</label>
                <textarea
                  value={step.hintFull}
                  onChange={(e) => handleStepChange(index, 'hintFull', e.target.value)}
                  placeholder="Detailed hint explanation..."
                  rows="2"
                />
              </div>
            </div>
          ))}
        </section>
      </div>

      {/* Template Modal */}
      {showTemplateModal && (
        <div className="modal-overlay" onClick={() => setShowTemplateModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <h3>Create from Template</h3>
            <div className="template-grid">
              {templates.map(template => (
                <div key={template.id} className="template-card">
                  <h4>{template.name}</h4>
                  <p>{template.description}</p>
                  <button onClick={() => handleCreateFromTemplate(template.id)} className="btn-primary">
                    Use Template
                  </button>
                </div>
              ))}
            </div>
            <button onClick={() => setShowTemplateModal(false)} className="btn-secondary">Cancel</button>
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * Get an empty scenario template
 */
function getEmptyScenario() {
  return {
    id: `custom_${Date.now()}`,
    name: 'New Custom Scenario',
    difficulty: 'Beginner',
    machines: {
      attacker: { name: 'ATTACKER01', ip: '10.0.0.5' },
      internal: { name: 'SRV-APP01', ip: '10.0.0.10' },
      dc: { name: 'DC01', ip: '10.0.0.20' }
    },
    mission: {
      target: 'contoso.local',
      objective: '',
      notes: ''
    },
    steps: [
      {
        id: 1,
        description: '',
        expectedCommand: '',
        attackerOutput: '',
        internalOutput: '',
        dcOutput: '',
        hintShort: '',
        hintFull: '',
        scoreValue: 10
      }
    ]
  };
}
