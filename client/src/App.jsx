import { useState, useEffect } from 'react';
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { ThemeProvider } from "./contexts/ThemeContext";
import ErrorBoundary from "./components/ErrorBoundary.tsx";
import Header from './components/Header';
import GuidePanel from './components/GuidePanel';
import AttackerPanel from './components/AttackerPanel';
// REMOVED: import InternalPanel - Logic moved to AttackerPanel
import ScenarioSelector from './components/ScenarioSelector';
import NetworkMap from './components/NetworkMap';
import PlayerHUD from './components/PlayerHUD';
import MissionModal from './components/MissionModal';
import QuizPanel from './components/QuizPanel';
import AchievementsPanel from './components/AchievementsPanel';
import ScenarioEditor from './components/ScenarioEditor';
import ScenarioList from './components/ScenarioList';
import { scenarioMap } from './data/scenarios/index.js';
import { quizMap } from './data/quizzes/index.js';
import { achievements, getUnlockedAchievements } from './data/achievements.js';
import { getCustomScenarios } from './utils/scenarioStorage.js';
import { 
  loadProgress, 
  saveProgress, 
  addScenarioCompletion,
  addQuizScore,
  unlockAchievement
} from './lib/progressTracker.js';
import { safeGetItem, safeSetItem } from './lib/safeStorage.js';
import { validateScenario } from './lib/validation.js';
import './styles.css';

// Migrate legacy storage if needed
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
  // App mode: play or editor
  const [appMode, setAppMode] = useState('play');
  const [showEditor, setShowEditor] = useState(false);
  const [editingScenario, setEditingScenario] = useState(null);
  const [customScenarios, setCustomScenarios] = useState(() => getCustomScenarios());
  
  // Player progress
  const [progress, setProgress] = useState(() => loadProgress());

  // Current scenario
  const [currentScenarioId, setCurrentScenarioId] = useState('bloodhound');
  
  // Merge built-in and custom scenarios
  const allScenarios = { ...scenarioMap };
  customScenarios.forEach(scenario => {
    allScenarios[scenario.id] = scenario;
  });
  
  const currentScenario = allScenarios[currentScenarioId];
  
  // Current step in the scenario (0-indexed)
  const [currentStep, setCurrentStep] = useState(0);
  
  // Command history for attacker terminal
  const [attackerHistory, setAttackerHistory] = useState([]);
  
  // Server log history
  const [serverHistory, setServerHistory] = useState([]);
  
  // Is currently displaying output (animating)
  const [isProcessing, setIsProcessing] = useState(false);
  
  // Currently active machine tab: 'attacker' (console) or 'internal'/'dc' (log view)
  const [activeMachine, setActiveMachine] = useState('attacker');
  
  // Network map highlighting
  const [highlightedMachine, setHighlightedMachine] = useState(null);
  const [highlightedArrow, setHighlightedArrow] = useState(null);

  // Gamification state
  const [showMissionBriefing, setShowMissionBriefing] = useState(false); 
  const [showMissionDebrief, setShowMissionDebrief] = useState(false);
  const [showQuiz, setShowQuiz] = useState(false);
  const [showAchievements, setShowAchievements] = useState(false);
  const [scenarioStats, setScenarioStats] = useState({
    wrongAttempts: 0,
    hintsUsed: 0,
    startTime: Date.now()
  });
  const [newAchievements, setNewAchievements] = useState([]);
  const [tutorialMode, setTutorialMode] = useState(progress.tutorialMode);
  const [hintsShown, setHintsShown] = useState({});

  // Initialize history when scenario changes
  useEffect(() => {
    resetScenario();
    setShowMissionDebrief(false);
    setShowQuiz(false);
    setScenarioStats({
      wrongAttempts: 0,
      hintsUsed: 0,
      startTime: Date.now()
    });
    setHintsShown({});
  }, [currentScenarioId]);

  const resetScenario = () => {
    setCurrentStep(0);
    setActiveMachine('attacker');
    setHighlightedMachine(null);
    setHighlightedArrow(null);
    
    setAttackerHistory([
      { type: 'system', text: `Welcome to ${currentScenario.network.attacker.hostname}` },
      { type: 'system', text: `IP: ${currentScenario.network.attacker.ip}` },
      { type: 'system', text: `Target: ${currentScenario.network.target.hostname} (${currentScenario.network.target.ip})` },
      { type: 'system', text: '' },
      { type: 'system', text: 'Type the commands from the guide to begin the attack simulation.' },
      { type: 'system', text: '' }
    ]);
    
    setServerHistory([
      { type: 'info', text: `[SYSTEM] ${currentScenario.network.target.hostname} - Windows Server 2019` },
      { type: 'info', text: `[SYSTEM] Domain Controller for ${currentScenario.network.domain}` },
      { type: 'info', text: `[SYSTEM] IP Address: ${currentScenario.network.target.ip}` },
      { type: 'info', text: '[SYSTEM] All services running normally' },
      { type: 'info', text: '' }
    ]);
  };

  // Handle command submission
  const handleCommandSubmit = (command) => {
    setAttackerHistory(prev => [
      ...prev,
      { type: 'command', text: `root@${currentScenario.network.attacker.hostname}:~# ${command}` }
    ]);

    const currentScenarioStep = currentScenario.steps[currentStep];
    
    if (!currentScenarioStep) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'error', text: '[!] Simulation complete. Select a new scenario to restart.' }
      ]);
      return;
    }

    const expectedCmd = currentScenarioStep.expectedCommand;
    const normalizedInput = command.trim().toLowerCase();
    const normalizedExpected = expectedCmd ? expectedCmd.trim().toLowerCase() : null;

    // Check for near-miss or wrong command
    if (normalizedExpected && normalizedInput !== normalizedExpected) {
      setScenarioStats(prev => ({ ...prev, wrongAttempts: prev.wrongAttempts + 1 }));
      
      if (tutorialMode) {
        // In tutorial mode, show hint instead of error
        const step = currentScenario.steps[currentStep];
        setAttackerHistory(prev => [
          ...prev,
          { type: 'error', text: `[!] Not quite right. Hint: ${step.hintShort || 'Try again'}` }
        ]);
      } else {
        const suggestion = `Did you mean: ${expectedCmd}?`;
        setAttackerHistory(prev => [
          ...prev,
          { type: 'error', text: `[!] Command not recognized or incorrect for this step.` },
          { type: 'error', text: `[!] ${suggestion}` }
        ]);
      }
      return;
    }

    setIsProcessing(true);
    processStepOutput(currentScenarioStep);
  };

  // Process step output with animation
  const processStepOutput = async (step) => {
    const { attackerOutput, serverOutput, delay } = step;

    setHighlightedMachine('target');
    setHighlightedArrow('attacker-to-target');

    for (let i = 0; i < attackerOutput.length; i++) {
      await new Promise(resolve => setTimeout(resolve, delay));
      setAttackerHistory(prev => [
        ...prev,
        { type: 'output', text: attackerOutput[i] }
      ]);
    }

    for (let i = 0; i < serverOutput.length; i++) {
      await new Promise(resolve => setTimeout(resolve, delay));
      setServerHistory(prev => [
        ...prev,
        { type: 'log', text: serverOutput[i] }
      ]);
    }

    setHighlightedMachine(null);
    setHighlightedArrow(null);

    setIsProcessing(false);
    
    // Check if scenario is complete
    if (currentStep === currentScenario.steps.length - 1) {
      completeScenario();
    } else {
      setCurrentStep(prev => prev + 1);
    }
  };

  // Complete scenario and show debrief
  const completeScenario = () => {
    const timeSpent = Math.round((Date.now() - scenarioStats.startTime) / 1000);
    const scoreEarned = calculateScenarioScore(scenarioStats.wrongAttempts, scenarioStats.hintsUsed);
    
    // Update progress
    let updatedProgress = { ...progress };
    updatedProgress = addScenarioCompletion(updatedProgress, currentScenarioId, {
      wrongAttempts: scenarioStats.wrongAttempts,
      hintsUsed: scenarioStats.hintsUsed,
      timeSpent
    });

    // Check for new achievements
    const previousUnlocked = getUnlockedAchievements(progress);
    const newUnlocked = getUnlockedAchievements(updatedProgress);
    const justUnlocked = newUnlocked.filter(id => !previousUnlocked.includes(id));
    
    justUnlocked.forEach(id => {
      updatedProgress = unlockAchievement(updatedProgress, id);
    });

    setProgress(updatedProgress);
    saveProgress(updatedProgress);

    // Show debrief with new achievements
    const newAchievementObjects = justUnlocked
      .map(id => achievements.find(a => a.id === id))
      .filter(Boolean);
    
    setNewAchievements(newAchievementObjects);
    setShowMissionDebrief(true);

    // Set debrief stats
    setScenarioStats(prev => ({
      ...prev,
      scoreEarned,
      stepsCompleted: currentScenario.steps.length,
      timeSpent: `${Math.floor(timeSpent / 60)}m ${timeSpent % 60}s`
    }));
  };

  // Calculate scenario score
  const calculateScenarioScore = (wrongAttempts, hintsUsed) => {
    if (wrongAttempts === 0 && hintsUsed === 0) {
      return 10;
    } else if (hintsUsed > 0 && hintsUsed <= 2) {
      return 5;
    } else if (wrongAttempts > 0) {
      return Math.max(0, 10 - (wrongAttempts * 2));
    }
    return 0;
  };

  // Handle hint button click
  const handleShowHint = (stepIndex) => {
    const step = currentScenario.steps[stepIndex];
    if (!step) return;

    const hintLevel = hintsShown[stepIndex] || 0;
    
    if (hintLevel === 0) {
      // Show short hint
      setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Hint: ${step.hintShort || 'No hint available'}` }
      ]);
      setHintsShown(prev => ({ ...prev, [stepIndex]: 1 }));
      setScenarioStats(prev => ({ ...prev, hintsUsed: prev.hintsUsed + 1 }));
    } else if (hintLevel === 1) {
      // Show full hint
      setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Full Hint: ${step.hintFull || 'No additional hint available'}` }
      ]);
      setHintsShown(prev => ({ ...prev, [stepIndex]: 2 }));
    }
  };

  // Handle quiz completion
  const handleQuizComplete = (quizStats) => {
    let updatedProgress = { ...progress };
    updatedProgress = addQuizScore(
      updatedProgress,
      currentScenarioId,
      quizStats.score,
      quizStats.correctAnswers,
      quizStats.totalQuestions
    );
    
    setProgress(updatedProgress);
    saveProgress(updatedProgress);
    setShowQuiz(false);
  };

  // Handle scenario selection
  const handleScenarioSelect = (scenario) => {
    try {
      if (import.meta.env.DEV) {
        console.log('[DEBUG] handleScenarioSelect called with:', scenario);
      }
      const scenarioId = typeof scenario === 'string' ? scenario : scenario.id;
      
      if (!scenarioId) {
        if (import.meta.env.DEV) {
          console.error('[ERROR] Invalid scenario ID:', scenarioId);
        }
        return;
      }
      
      const scenarioExists = allScenarios[scenarioId];
      
      if (!scenarioExists) {
        if (import.meta.env.DEV) {
          console.error('[ERROR] Scenario not found in allScenarios:', scenarioId);
          console.log('[DEBUG] Available scenarios:', Object.keys(allScenarios));
        }
        return;
      }
      
      setCurrentScenarioId(scenarioId);
      setShowMissionBriefing(true); 
      if (import.meta.env.DEV) {
        console.log('[DEBUG] Scenario selected successfully');
      }
    } catch (error) {
      if (import.meta.env.DEV) {
        console.error('[ERROR] Error in handleScenarioSelect:', error);
        console.error('[ERROR] Stack:', error.stack);
      }
    }
  };

  // Handle editor close
  const handleEditorClose = () => {
    setShowEditor(false);
    setEditingScenario(null);
    setCustomScenarios(getCustomScenarios());
  };

  // Handle scenario edit
  const handleEditScenario = (scenario) => {
    setEditingScenario(scenario);
    setShowEditor(true);
  };

  // Handle scenario delete
  const handleDeleteScenario = (id) => {
    setCustomScenarios(getCustomScenarios());
    if (currentScenarioId === id) {
      setCurrentScenarioId('bloodhound');
    }
  };

  // Show editor mode
  if (appMode === 'editor') {
    return (
      <div className="editor-mode-container">
        <div className="mode-toggle">
          <button onClick={() => setAppMode('play')} className="mode-btn active">Play Scenarios</button>
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
            <ScenarioList scenarios={customScenarios} title="Custom Scenarios" onSelect={handleScenarioSelect} onEdit={handleEditScenario} onDelete={handleDeleteScenario} />
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="simulator-container">
      <Header 
        title={currentScenario.title}
        currentStep={currentStep + 1}
        totalSteps={currentScenario.steps.length}
      />

      <PlayerHUD 
        score={progress.totalScore}
        rank={progress.rank}
        currentStep={currentStep + 1}
        totalSteps={currentScenario.steps.length}
        scenario={currentScenario}
      />
      
      <NetworkMap 
        highlightedMachine={highlightedMachine}
        highlightedArrow={highlightedArrow}
      />
      
      <div className="mode-toggle-bar">
        <button onClick={() => { setAppMode('play'); handleScenarioSelect(currentScenarioId || 'bloodhound'); }} className="mode-btn active">Play Scenarios</button>
        <button onClick={() => setAppMode('editor')} className="mode-btn">Scenario Editor</button>
      </div>
      
      <div className="main-layout">
        <div className="main-content">
          <div className="main-grid">
            {/* COLUMN 1: Scenario Selector (Fixed Width) */}
            <ScenarioSelector 
              currentScenarioId={currentScenarioId}
              customScenarios={customScenarios}
              onScenarioSelect={handleScenarioSelect}
            />
            
            {/* COLUMN 2: Main Simulation Area (Flexible Stack) - NEW DESIGN */}
            <div className="simulation-main-column">
              {/* Row 1: Collapsible Guide Panel */}
              <GuidePanel 
                scenario={currentScenario}
                currentStep={currentStep}
                tutorialMode={tutorialMode}
                onTutorialToggle={() => {
                  setTutorialMode(!tutorialMode);
                  setProgress(prev => ({ ...prev, tutorialMode: !tutorialMode }));
                }}
              />
              
              {/* Row 2: Unified Terminal & Logs Panel (Takes remaining vertical space) */}
              <AttackerPanel 
                history={attackerHistory}
                onCommandSubmit={handleCommandSubmit}
                isProcessing={isProcessing}
                network={currentScenario.network}
                activeMachine={activeMachine} // Passed down to control tab state
                onMachineChange={setActiveMachine}
                serverHistory={serverHistory}
                onShowHint={() => handleShowHint(currentStep)}
                hintsAvailable={currentStep < currentScenario.steps.length}
              />
              
              {/* REMOVED: InternalPanel is now obsolete. */}
            </div>
          </div>
        </div>
      </div>

      {/* Modals */}
      <MissionModal
        isOpen={showMissionBriefing}
        onClose={() => setShowMissionBriefing(false)}
        type="briefing"
        scenario={currentScenario}
      />

      <MissionModal
        isOpen={showMissionDebrief}
        onClose={() => {
          setShowMissionDebrief(false);
          setShowQuiz(true);
        }}
        type="debrief"
        scenario={currentScenario}
        stats={scenarioStats}
        newAchievements={newAchievements}
      />

      {showQuiz && (
        <div className="modal-backdrop">
          <div className="modal-content quiz-modal">
            <QuizPanel
              quiz={quizMap[currentScenarioId]}
              onComplete={handleQuizComplete}
              onSkip={() => setShowQuiz(false)}
            />
          </div>
        </div>
      )}

      {showAchievements && (
        <div className="modal-backdrop">
          <div className="modal-content achievements-modal">
            <AchievementsPanel
              unlockedAchievements={progress.unlockedAchievements}
              newAchievements={newAchievements}
            />
          </div>
        </div>
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