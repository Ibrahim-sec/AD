// client/src/components/ScenarioEditor.jsx

import { useState, useRef } from 'react';
import { 
  Save, 
  Upload, 
  Download, 
  Plus, 
  Trash2, 
  Copy,
  AlertCircle,
  CheckCircle,
  ArrowLeft,
  Code,
  Eye
} from 'lucide-react';
import { Link } from 'wouter';

const TEMPLATE_SCENARIO = {
  id: 'custom-scenario',
  title: 'Custom Attack Scenario',
  description: 'Describe your attack scenario here',
  difficulty: 'Intermediate',
  mitreAttack: 'T1000',
  network: {
    attacker: { hostname: 'KALI-ATTACK', ip: '10.0.0.5' },
    target: { hostname: 'TARGET-01', ip: '10.0.1.20' },
    dc: { hostname: 'DC01', ip: '10.0.1.10' },
    domain: 'contoso.local'
  },
  steps: [
    {
      id: 0,
      description: 'First step description',
      expectedCommand: 'command-here',
      hintShort: 'Short hint',
      hintFull: 'Detailed hint',
      attackerOutput: ['Output line 1', 'Output line 2'],
      serverOutput: ['Server log line 1'],
      delay: 150
    }
  ]
};

export default function ScenarioEditor() {
  const [scenario, setScenario] = useState(TEMPLATE_SCENARIO);
  const [activeTab, setActiveTab] = useState('editor'); // 'editor' or 'preview'
  const [validationErrors, setValidationErrors] = useState([]);
  const [saveStatus, setSaveStatus] = useState(null);
  const fileInputRef = useRef(null);

  // ========== VALIDATION ==========

  const validateScenario = (scenarioData) => {
    const errors = [];

    // Required fields
    if (!scenarioData.id || scenarioData.id.trim() === '') {
      errors.push('Scenario ID is required');
    }

    if (!scenarioData.title || scenarioData.title.trim() === '') {
      errors.push('Scenario title is required');
    }

    if (!scenarioData.description || scenarioData.description.trim() === '') {
      errors.push('Scenario description is required');
    }

    // Network validation
    if (!scenarioData.network) {
      errors.push('Network configuration is required');
    } else {
      if (!scenarioData.network.attacker?.hostname) {
        errors.push('Attacker hostname is required');
      }
      if (!scenarioData.network.attacker?.ip) {
        errors.push('Attacker IP is required');
      }
      if (!scenarioData.network.target?.hostname) {
        errors.push('Target hostname is required');
      }
      if (!scenarioData.network.target?.ip) {
        errors.push('Target IP is required');
      }
      if (!scenarioData.network.domain) {
        errors.push('Domain is required');
      }
    }

    // Steps validation
    if (!scenarioData.steps || scenarioData.steps.length === 0) {
      errors.push('At least one step is required');
    } else {
      scenarioData.steps.forEach((step, index) => {
        if (step.id === undefined) {
          errors.push(`Step ${index + 1}: ID is required`);
        }
        if (!step.description) {
          errors.push(`Step ${index + 1}: Description is required`);
        }
        if (!step.attackerOutput || step.attackerOutput.length === 0) {
          errors.push(`Step ${index + 1}: Attacker output is required`);
        }
      });
    }

    // ID format validation
    if (scenarioData.id && !/^[a-z0-9-]+$/.test(scenarioData.id)) {
      errors.push('Scenario ID can only contain lowercase letters, numbers, and hyphens');
    }

    // IP validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (scenarioData.network?.attacker?.ip && !ipRegex.test(scenarioData.network.attacker.ip)) {
      errors.push('Invalid attacker IP address format');
    }
    if (scenarioData.network?.target?.ip && !ipRegex.test(scenarioData.network.target.ip)) {
      errors.push('Invalid target IP address format');
    }

    return errors;
  };

  // ========== HANDLERS ==========

  const handleFieldChange = (path, value) => {
    setScenario(prev => {
      const newScenario = { ...prev };
      const keys = path.split('.');
      let current = newScenario;
      
      for (let i = 0; i < keys.length - 1; i++) {
        current = current[keys[i]];
      }
      
      current[keys[keys.length - 1]] = value;
      return newScenario;
    });
  };

  const handleAddStep = () => {
    const newStep = {
      id: scenario.steps.length,
      description: 'New step description',
      expectedCommand: 'command',
      hintShort: 'Hint',
      hintFull: 'Detailed hint',
      attackerOutput: ['Output'],
      serverOutput: ['Log'],
      delay: 150
    };

    setScenario(prev => ({
      ...prev,
      steps: [...prev.steps, newStep]
    }));
  };

  const handleDeleteStep = (index) => {
    if (confirm('Are you sure you want to delete this step?')) {
      setScenario(prev => ({
        ...prev,
        steps: prev.steps.filter((_, i) => i !== index)
      }));
    }
  };

  const handleDuplicateStep = (index) => {
    const stepToDuplicate = { ...scenario.steps[index] };
    stepToDuplicate.id = scenario.steps.length;

    setScenario(prev => ({
      ...prev,
      steps: [...prev.steps, stepToDuplicate]
    }));
  };

  const handleSave = () => {
    const errors = validateScenario(scenario);
    setValidationErrors(errors);

    if (errors.length === 0) {
      try {
        const json = JSON.stringify(scenario, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `${scenario.id}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
        
        setSaveStatus({ type: 'success', message: 'Scenario exported successfully!' });
        setTimeout(() => setSaveStatus(null), 3000);
      } catch (error) {
        setSaveStatus({ type: 'error', message: 'Failed to export scenario' });
      }
    } else {
      setSaveStatus({ type: 'error', message: 'Please fix validation errors first' });
    }
  };

  const handleImport = (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    
    reader.onload = (e) => {
      try {
        const imported = JSON.parse(e.target.result);
        const errors = validateScenario(imported);
        
        if (errors.length === 0) {
          setScenario(imported);
          setValidationErrors([]);
          setSaveStatus({ type: 'success', message: 'Scenario imported successfully!' });
          setTimeout(() => setSaveStatus(null), 3000);
        } else {
          setValidationErrors(errors);
          setSaveStatus({ type: 'error', message: 'Imported scenario has validation errors' });
        }
      } catch (error) {
        setSaveStatus({ type: 'error', message: 'Invalid JSON file' });
      }
    };
    
    reader.readAsText(file);
    event.target.value = null;
  };

  const handleLoadTemplate = () => {
    if (confirm('This will replace your current scenario. Continue?')) {
      setScenario(TEMPLATE_SCENARIO);
      setValidationErrors([]);
      setSaveStatus({ type: 'success', message: 'Template loaded' });
      setTimeout(() => setSaveStatus(null), 2000);
    }
  };

  // ========== RENDER ==========

  return (
    <div className="min-h-screen bg-[#0a0b0d] text-white">
      {/* Header */}
      <div className="bg-[#101214] border-b border-white/10 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <Link href="/">
              <a className="flex items-center gap-2 text-white/60 hover:text-white transition-colors">
                <ArrowLeft className="w-5 h-5" />
                Back
              </a>
            </Link>
            <div className="h-6 w-px bg-white/10"></div>
            <h1 className="text-xl font-bold">Scenario Editor</h1>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleLoadTemplate}
              className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg transition-all text-sm"
            >
              Load Template
            </button>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg transition-all text-sm"
            >
              <Upload className="w-4 h-4" />
              Import
            </button>
            <button
              onClick={handleSave}
              className="flex items-center gap-2 px-4 py-2 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 rounded-lg transition-all text-sm font-semibold"
            >
              <Download className="w-4 h-4" />
              Export
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex gap-2 mt-4">
          <button
            onClick={() => setActiveTab('editor')}
            className={`px-4 py-2 rounded-lg transition-all text-sm font-medium ${
              activeTab === 'editor'
                ? 'bg-[#2D9CDB] text-white'
                : 'bg-white/5 text-white/60 hover:text-white'
            }`}
          >
            <Code className="w-4 h-4 inline mr-2" />
            Editor
          </button>
          <button
            onClick={() => setActiveTab('preview')}
            className={`px-4 py-2 rounded-lg transition-all text-sm font-medium ${
              activeTab === 'preview'
                ? 'bg-[#2D9CDB] text-white'
                : 'bg-white/5 text-white/60 hover:text-white'
            }`}
          >
            <Eye className="w-4 h-4 inline mr-2" />
            JSON Preview
          </button>
        </div>
      </div>

      {/* Status Messages */}
      {saveStatus && (
        <div className={`px-6 py-3 text-sm ${
          saveStatus.type === 'success'
            ? 'bg-green-500/20 text-green-400 border-b border-green-500/30'
            : 'bg-red-500/20 text-red-400 border-b border-red-500/30'
        }`}>
          {saveStatus.message}
        </div>
      )}

      {/* Validation Errors */}
      {validationErrors.length > 0 && (
        <div className="bg-red-500/20 border-b border-red-500/30 px-6 py-4">
          <div className="flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="text-sm font-semibold text-red-400 mb-2">
                Validation Errors ({validationErrors.length})
              </div>
              <ul className="text-xs text-red-300 space-y-1">
                {validationErrors.map((error, index) => (
                  <li key={index}>• {error}</li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      <div className="p-6 max-w-6xl mx-auto">
        {activeTab === 'editor' ? (
          <EditorView 
            scenario={scenario}
            onFieldChange={handleFieldChange}
            onAddStep={handleAddStep}
            onDeleteStep={handleDeleteStep}
            onDuplicateStep={handleDuplicateStep}
          />
        ) : (
          <PreviewView scenario={scenario} />
        )}
      </div>

      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".json"
        onChange={handleImport}
        className="hidden"
      />
    </div>
  );
}

// ========== EDITOR VIEW ==========

function EditorView({ scenario, onFieldChange, onAddStep, onDeleteStep, onDuplicateStep }) {
  return (
    <div className="space-y-6">
      {/* Basic Info */}
      <Section title="Basic Information">
        <Input
          label="Scenario ID"
          value={scenario.id}
          onChange={(e) => onFieldChange('id', e.target.value)}
          placeholder="custom-scenario"
        />
        <Input
          label="Title"
          value={scenario.title}
          onChange={(e) => onFieldChange('title', e.target.value)}
          placeholder="Custom Attack Scenario"
        />
        <TextArea
          label="Description"
          value={scenario.description}
          onChange={(e) => onFieldChange('description', e.target.value)}
          placeholder="Describe your scenario..."
          rows={3}
        />
        <div className="grid grid-cols-2 gap-4">
          <Select
            label="Difficulty"
            value={scenario.difficulty}
            onChange={(e) => onFieldChange('difficulty', e.target.value)}
            options={['Beginner', 'Intermediate', 'Advanced', 'Expert']}
          />
          <Input
            label="MITRE ATT&CK ID"
            value={scenario.mitreAttack}
            onChange={(e) => onFieldChange('mitreAttack', e.target.value)}
            placeholder="T1000"
          />
        </div>
      </Section>

      {/* Network Configuration */}
      <Section title="Network Configuration">
        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Attacker Hostname"
            value={scenario.network.attacker.hostname}
            onChange={(e) => onFieldChange('network.attacker.hostname', e.target.value)}
          />
          <Input
            label="Attacker IP"
            value={scenario.network.attacker.ip}
            onChange={(e) => onFieldChange('network.attacker.ip', e.target.value)}
          />
          <Input
            label="Target Hostname"
            value={scenario.network.target.hostname}
            onChange={(e) => onFieldChange('network.target.hostname', e.target.value)}
          />
          <Input
            label="Target IP"
            value={scenario.network.target.ip}
            onChange={(e) => onFieldChange('network.target.ip', e.target.value)}
          />
          <Input
            label="Domain"
            value={scenario.network.domain}
            onChange={(e) => onFieldChange('network.domain', e.target.value)}
            className="col-span-2"
          />
        </div>
      </Section>

      {/* Steps */}
      <Section 
        title={`Attack Steps (${scenario.steps.length})`}
        action={
          <button
            onClick={onAddStep}
            className="flex items-center gap-2 px-3 py-1.5 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 rounded-lg text-sm transition-all"
          >
            <Plus className="w-4 h-4" />
            Add Step
          </button>
        }
      >
        <div className="space-y-4">
          {scenario.steps.map((step, index) => (
            <StepEditor
              key={index}
              step={step}
              index={index}
              onDelete={() => onDeleteStep(index)}
              onDuplicate={() => onDuplicateStep(index)}
              onChange={(field, value) => onFieldChange(`steps.${index}.${field}`, value)}
            />
          ))}
        </div>
      </Section>
    </div>
  );
}

// ========== PREVIEW VIEW ==========

function PreviewView({ scenario }) {
  const json = JSON.stringify(scenario, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(json);
  };

  return (
    <div className="bg-[#101214] rounded-lg border border-white/5 overflow-hidden">
      <div className="flex items-center justify-between p-4 border-b border-white/5">
        <h3 className="text-sm font-semibold">JSON Output</h3>
        <button
          onClick={handleCopy}
          className="flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded text-xs transition-all"
        >
          <Copy className="w-3 h-3" />
          Copy
        </button>
      </div>
      <pre className="p-4 text-xs font-mono text-white/80 overflow-auto max-h-[70vh]">
        {json}
      </pre>
    </div>
  );
}

// ========== HELPER COMPONENTS ==========

function Section({ title, action, children }) {
  return (
    <div className="bg-[#101214] rounded-lg border border-white/5 p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">{title}</h3>
        {action}
      </div>
      <div className="space-y-4">
        {children}
      </div>
    </div>
  );
}

function Input({ label, ...props }) {
  return (
    <div>
      <label className="block text-sm font-medium text-white/80 mb-2">
        {label}
      </label>
      <input
        {...props}
        className="w-full px-3 py-2 bg-[#1a1b1e] border border-white/10 rounded-lg text-white focus:border-[#2D9CDB] focus:outline-none transition-colors"
      />
    </div>
  );
}

function TextArea({ label, ...props }) {
  return (
    <div>
      <label className="block text-sm font-medium text-white/80 mb-2">
        {label}
      </label>
      <textarea
        {...props}
        className="w-full px-3 py-2 bg-[#1a1b1e] border border-white/10 rounded-lg text-white focus:border-[#2D9CDB] focus:outline-none transition-colors resize-none"
      />
    </div>
  );
}

function Select({ label, options, ...props }) {
  return (
    <div>
      <label className="block text-sm font-medium text-white/80 mb-2">
        {label}
      </label>
      <select
        {...props}
        className="w-full px-3 py-2 bg-[#1a1b1e] border border-white/10 rounded-lg text-white focus:border-[#2D9CDB] focus:outline-none transition-colors"
      >
        {options.map(opt => (
          <option key={opt} value={opt}>{opt}</option>
        ))}
      </select>
    </div>
  );
}

function StepEditor({ step, index, onDelete, onDuplicate, onChange }) {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="bg-[#1a1b1e] rounded-lg border border-white/5 p-4">
      <div className="flex items-center justify-between mb-4">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-sm font-semibold text-white hover:text-[#2D9CDB] transition-colors"
        >
          Step {index + 1}: {step.description.substring(0, 50)}
          {step.description.length > 50 && '...'}
        </button>
        <div className="flex items-center gap-2">
          <button
            onClick={onDuplicate}
            className="p-1.5 hover:bg-white/5 rounded transition-colors"
            title="Duplicate"
          >
            <Copy className="w-4 h-4" />
          </button>
          <button
            onClick={onDelete}
            className="p-1.5 hover:bg-red-500/20 text-red-400 rounded transition-colors"
            title="Delete"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="space-y-4 pt-4 border-t border-white/5">
          <TextArea
            label="Description"
            value={step.description}
            onChange={(e) => onChange('description', e.target.value)}
            rows={2}
          />
          <Input
            label="Expected Command"
            value={step.expectedCommand}
            onChange={(e) => onChange('expectedCommand', e.target.value)}
          />
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Short Hint"
              value={step.hintShort}
              onChange={(e) => onChange('hintShort', e.target.value)}
            />
            <Input
              label="Delay (ms)"
              type="number"
              value={step.delay}
              onChange={(e) => onChange('delay', parseInt(e.target.value))}
            />
          </div>
          <TextArea
            label="Full Hint"
            value={step.hintFull}
            onChange={(e) => onChange('hintFull', e.target.value)}
            rows={2}
          />
        </div>
      )}
    </div>
  );
}
