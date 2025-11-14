import { useState, useMemo } from 'react';
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./contexts/ThemeContext";
import ErrorBoundary from "./components/ErrorBoundary.tsx";
// Use wouter for routing
import { Router, Route, Switch, Redirect, useLocation } from 'wouter'; 

// New Page Components
import ScenarioSelectionPage from './components/ScenarioSelectionPage';
import SimulatorPage from './components/SimulatorPage';
import ScenarioEditor from './components/ScenarioEditor';

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

import { useState, useMemo } from 'react';

function SimulatorApp() {
  const [customScenarios, setCustomScenarios] = useState(() => getCustomScenarios());
  const [progress, setProgress] = useState(() => loadProgress());
  const [location, setLocation] = useLocation();

  // Determine current mode based on route
  const isEditorMode = location.startsWith('/editor');

  // Consolidate scenario map for all components
  const allScenarios = useMemo(() => {
    const map = { ...scenarioMap };
    customScenarios.forEach(scenario => {
      map[scenario.id] = scenario;
    });
    return map;
  }, [customScenarios]);

  // Function to pass to selection page, triggers navigation
  const handleScenarioSelect = (scenario) => {
    if (import.meta.env.DEV) {
      console.log('[DEBUG] Scenario selected:', scenario.id);
    }
    // Navigation is handled by the <Link> component in ScenarioSelectionPage
  };

  // Function to update custom scenarios after save/delete
  const updateCustomScenarios = () => {
    setCustomScenarios(getCustomScenarios());
  };

  // Main App Content (Router Switch)
  return (
    <div className="simulator-container">
      {/* Mode Toggle remains visible on all primary routes */}
      <div className="mode-toggle-bar">
        <button 
          onClick={() => setLocation('/')} 
          className={!isEditorMode ? 'mode-btn active' : 'mode-btn'}
        >
          Play Scenarios
        </button>
        <button 
          onClick={() => setLocation('/editor')} 
          className={isEditorMode ? 'mode-btn active' : 'mode-btn'}
        >
          Scenario Editor
        </button>
      </div>
      
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
                // Removed appMode/setAppMode props as they are now derived from route
              />
            )}
          </Route>

          {/* Route 3: Scenario Editor Home/List */}
          <Route path="/editor">
            <div className="main-layout main-editor-layout">
              <div className="main-content">
                <ScenarioList 
                  scenarios={customScenarios} 
                  title="Custom Scenarios" 
                  onScenarioUpdate={updateCustomScenarios}
                />
              </div>
            </div>
          </Route>

          {/* Route 4: Scenario Editor (Edit/New) */}
          <Route path="/editor/:id">
            {({ id }) => (
              <div className="main-layout main-editor-layout">
                <div className="main-content">
                  <ScenarioEditor scenarioId={id} onSave={updateCustomScenarios} onDelete={updateCustomScenarios} />
                </div>
              </div>
            )}
          </Route>

          {/* Fallback */}
          <Route>
            <Redirect to="/" />
          </Route>
        </Switch>
      </Router>
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