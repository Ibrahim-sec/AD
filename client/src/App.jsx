import { useState } from 'react';
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./contexts/ThemeContext";
import ErrorBoundary from "./components/ErrorBoundary.tsx";
// Use wouter for routing
import { Router, Route, Switch, Redirect } from 'wouter'; 

// New Page Components
import ScenarioSelectionPage from './components/ScenarioSelectionPage';
import SimulatorPage from './components/SimulatorPage';
import ScenarioEditor from './components/ScenarioEditor';
import ScenarioList from './components/ScenarioList';

// Utilities and Data
import { scenarioMap } from './data/scenarios/index.js';
import { getCustomScenarios } from './utils/scenarioStorage.js';
import { loadProgress } from './lib/progressTracker.js';
import { safeSetItem } from './lib/safeStorage.js';
import './styles.css';

// Migrate legacy storage (Keep this outside the component)
const legacyKeys = ['playerProgress', 'customScenarios', 'achievements'];
legacyKeys.forEach(key => {
  const oldValue = localStorage.getItem(key);
  if (oldValue) {
    try {
      safeSetItem(key, JSON.parse(oldValue));
      localStorage.removeItem(key);
    } catch (e) {
      console.warn(`Could not migrate legacy key: ${key}`);
    }
  }
});

function SimulatorApp() {
  // Global State (persists across routes)
  const [appMode, setAppMode] = useState('play');
  const [showEditor, setShowEditor] = useState(false);
  const [editingScenario, setEditingScenario] = useState(null);
  const [customScenarios, setCustomScenarios] = useState(() => getCustomScenarios());
  const [progress, setProgress] = useState(() => loadProgress());

  // Consolidate scenario map for all components
  const allScenarios = { ...scenarioMap };
  customScenarios.forEach(scenario => {
    allScenarios[scenario.id] = scenario;
  });

  // Function to pass to selection page, triggers navigation
  const handleScenarioSelect = (scenario) => {
    if (import.meta.env.DEV) {
      console.log('[DEBUG] Scenario selected:', scenario.id);
    }
    // Navigation is handled by the <Link> component in ScenarioSelectionPage
  };

  // Handle editor close actions
  const handleEditorClose = () => {
    setShowEditor(false);
    setEditingScenario(null);
    setCustomScenarios(getCustomScenarios());
  };

  // Handle scenario edit (used in ScenarioList)
  const handleEditScenario = (scenario) => {
    setEditingScenario(scenario);
    setShowEditor(true);
  };
  
  // Handle scenario delete (used in ScenarioList)
  const handleDeleteScenario = () => {
    setCustomScenarios(getCustomScenarios());
  };

  // Editor View (Renders the Scenario Editor and Custom Scenario List)
  const EditorView = () => (
    <div className="editor-mode-container">
      <div className="mode-toggle">
        <button onClick={() => setAppMode('play')} className="mode-btn">Play Scenarios</button>
        <button onClick={() => setAppMode('editor')} className="mode-btn active">Scenario Editor</button>
      </div>
      {showEditor ? (
        <ScenarioEditor onClose={handleEditorClose} initialScenario={editingScenario} />
      ) : (
        <div className="editor-home">
          <h2>Scenario Editor</h2>
          <div className="editor-actions">
            <button onClick={() => { setEditingScenario(null); setShowEditor(true); }} className="btn-primary">Create New Scenario</button>
          </div>
          <ScenarioList 
            scenarios={customScenarios} 
            title="Custom Scenarios" 
            onSelect={() => { /* no-op in editor home */ }} 
            onEdit={handleEditScenario} 
            onDelete={handleDeleteScenario} 
          />
        </div>
      )}
    </div>
  );

  // Main App Content (Router Switch)
  return (
    <div className="simulator-container">
      {/* Mode Toggle remains visible on all primary routes */}
      <div className="mode-toggle-bar">
        <button onClick={() => setAppMode('play')} className={appMode === 'play' ? 'mode-btn active' : 'mode-btn'}>Play Scenarios</button>
        <button onClick={() => setAppMode('editor')} className={appMode === 'editor' ? 'mode-btn active' : 'mode-btn'}>Scenario Editor</button>
      </div>
      
      {appMode === 'editor' ? (
        <EditorView />
      ) : (
        <Router>
          <Switch>
            {/* Route 1: Scenario Selector Page (Home) */}
            <Route path="/">
              <div className="main-layout main-home-layout">
                <div className="main-content">
                  <ScenarioSelectionPage 
                    allScenarios={allScenarios} 
                    progress={progress}
                    customScenarios={customScenarios}
                    onScenarioSelect={handleScenarioSelect}
                  />
                </div>
              </div>
            </Route>

            {/* Route 2: Simulator Page */}
            <Route path="/scenario/:id">
              {({ id }) => (
                <SimulatorPage 
                  scenarioId={id}
                  allScenarios={allScenarios}
                  progress={progress}
                  setProgress={setProgress}
                  appMode={appMode}
                  setAppMode={setAppMode}
                />
              )}
            </Route>

            {/* Fallback */}
            <Route>
              <Redirect to="/" />
            </Route>
          </Switch>
        </Router>
      )}
    </div>
  );
}

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="dark">
        <TooltipProvider>
          <Toaster />
          <SimulatorApp />
        </TooltipProvider>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;