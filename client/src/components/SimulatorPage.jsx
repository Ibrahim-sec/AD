import { useState, useEffect } from 'react';
import { Redirect, Link } from 'wouter';
import Header from './Header';
import GuidePanel from './GuidePanel';
import AttackerPanel from './AttackerPanel';
import MissionModal from './MissionModal';
import QuizPanel from './QuizPanel';
import AchievementsPanel from './AchievementsPanel';
import SettingsModal from './SettingsModal';
import { quizMap } from '../data/quizzes/index.js';
import { achievements, getUnlockedAchievements } from '../data/achievements.js';
import { 
  saveProgress, 
  addScenarioCompletion,
  addQuizScore,
  unlockAchievement
} from '../lib/progressTracker.js';
// ADD THIS IMPORT
import { safeGetItem, safeSetItem } from '../lib/safeStorage.js';

// Helper function definitions
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

// Helper function to simulate defense alerts (for feature #1)
const getDefenseAlertForStep = (stepId, scenarioId) => {
    if (scenarioId === 'kerberoasting') {
        if (stepId === 1) return "[DEFENSE] ALERT: LDAP Query pattern detected (SPN enumeration).";
        if (stepId === 4) return "[DEFENSE] ALERT: Weak hash identified (Service account compromised).";
    }
    if (scenarioId === 'pass-the-hash') {
        if (stepId === 3) return "[DEFENSE] ALERT: Unusual NTLM authentication without password detected (PtH).";
    }
    return null;
}

export default function SimulatorPage({ 
  scenarioId, 
  allScenarios,
  progress,
  setProgress,
  appMode, 
  setAppMode,
}) {
  const currentScenario = allScenarios[scenarioId];

  // --- LOCAL SIMULATOR STATE ---
  const [currentStep, setCurrentStep] = useState(0);
  const [attackerHistory, setAttackerHistory] = useState([]);
  const [serverHistory, setServerHistory] = useState([]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [activeMachine, setActiveMachine] = useState('attacker');
  const [highlightedMachine, setHighlightedMachine] = useState(null);
  const [highlightedArrow, setHighlightedArrow] = useState(null);
  
  // NEW STATE: Feature Management
  const [defenseHistory, setDefenseHistory] = useState([]);
  const [credentialInventory, setCredentialInventory] = useState([]);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [customTheme, setCustomTheme] = useState(() => {
    try {
        return JSON.parse(localStorage.getItem('terminal_theme')) || {};
    } catch (e) {
        return {};
    }
  });


  // --- MODAL / GAME STATE ---
  
  // MODIFICATION 1: Make useState check localStorage
  const briefingStorageKey = `hasSeenBriefing_${scenarioId}`;
  const [showMissionBriefing, setShowMissionBriefing] = useState(() => {
    // Read from storage. Default to `null` if not found.
    const hasSeen = safeGetItem(briefingStorageKey, null);
    // Show the modal only if `hasSeen` is NOT true.
    return hasSeen !== true;
  }); 
  
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

  // Redirect if scenario doesn't exist
  if (!currentScenario) {
    return <Redirect to="/" />;
  }
  
  // --- HANDLERS ---
  
  const handleUpdateTheme = (newTheme) => {
    setCustomTheme(newTheme);
    localStorage.setItem('terminal_theme', JSON.stringify(newTheme));
  };

  const harvestCredential = (type, username, secret) => {
      setCredentialInventory(prev => {
          const newCred = { id: Date.now(), type, username, secret };
          if (prev.some(c => c.secret === secret)) return prev;
          return [...prev, newCred];
      });
  };

  // --- Initialize/Reset State ---
  useEffect(() => {
    resetScenario();
    setCredentialInventory([]); // Reset inventory on new scenario load
    
    // MODIFICATION: Check storage key to decide if briefing should be shown on scenario load
    const hasSeen = safeGetItem(briefingStorageKey, null);
    setShowMissionBriefing(hasSeen !== true);

    setShowMissionDebrief(false);
    setShowQuiz(false);
    setScenarioStats({
      wrongAttempts: 0,
      hintsUsed: 0,
      startTime: Date.now()
    });
    setHintsShown({});
  }, [scenarioId, briefingStorageKey]); // Add briefingStorageKey to dependency array

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
    
    setDefenseHistory([
        { type: 'info', text: "[DEFENSE] Blue Team Console Online. Monitoring Domain: contoso.local" },
        { type: 'info', text: "[DEFENSE] Active Policy: Strong Password Policy, NTLM Enabled (Legacy Support)" },
        { type: 'info', text: "" },
    ]);
  };
  
  // --- CORE SIMULATION LOGIC ---
  
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

    // NEW: Simulate credential harvesting on certain successful steps
    if (step.id === 4 && scenarioId === 'kerberoasting') {
        harvestCredential('Password', 'sqlservice', 'P@ssw0rd123!');
        harvestCredential('Password', 'iis_app', 'ServicePass2024');
    }
    if (step.id === 3 && scenarioId === 'asrep-roasting') {
        harvestCredential('Hash', 'svc_backup', 'BackupHash123');
    }
    if (step.id === 1 && scenarioId === 'pass-the-hash') {
        harvestCredential('Hash', 'admin', '5f4dcc3b5aa765d61d8327deb882cf99');
    }

    // NEW: Add Defense Alert after outputs are streamed
    const defenseAlert = getDefenseAlertForStep(step.id, scenarioId);
    if (defenseAlert) {
        setDefenseHistory(prev => [
            ...prev,
            { type: 'error', text: defenseAlert } 
        ]);
    }

    setHighlightedMachine(null);
    setHighlightedArrow(null);

    setIsProcessing(false);
    
    if (currentStep === currentScenario.steps.length - 1) {
      completeScenario();
    } else {
      setCurrentStep(prev => prev + 1);
    }
  };


  const completeScenario = () => {
    const timeSpent = Math.round((Date.now() - scenarioStats.startTime) / 1000);
    const scoreEarned = calculateScenarioScore(scenarioStats.wrongAttempts, scenarioStats.hintsUsed);
    
    let updatedProgress = { ...progress };
    updatedProgress = addScenarioCompletion(updatedProgress, scenarioId, {
      wrongAttempts: scenarioStats.wrongAttempts,
      hintsUsed: scenarioStats.hintsUsed,
      timeSpent
    });

    const previousUnlocked = getUnlockedAchievements(progress);
    const newUnlocked = getUnlockedAchievements(updatedProgress);
    const justUnlocked = newUnlocked.filter(id => !previousUnlocked.includes(id));
    
    justUnlocked.forEach(id => {
      updatedProgress = unlockAchievement(updatedProgress, id);
    });

    setProgress(updatedProgress);
    saveProgress(updatedProgress);

    const newAchievementObjects = justUnlocked
      .map(id => achievements.find(a => a.id === id))
      .filter(Boolean);
    
    setNewAchievements(newAchievementObjects);
    setShowMissionDebrief(true);

    setScenarioStats(prev => ({
      ...prev,
      scoreEarned,
      stepsCompleted: currentScenario.steps.length,
      timeSpent: `${Math.floor(timeSpent / 60)}m ${timeSpent % 60}s`
    }));
  };

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

    if (normalizedExpected && normalizedInput !== normalizedExpected) {
      setScenarioStats(prev => ({ ...prev, wrongAttempts: prev.wrongAttempts + 1 }));
      
      if (tutorialMode) {
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
  
  const handleShowHint = (stepIndex) => {
    const step = currentScenario.steps[stepIndex];
    if (!step) return;

    const hintLevel = hintsShown[stepIndex] || 0;
    
    if (hintLevel === 0) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Hint: ${step.hintShort || 'No hint available'}` }
      ]);
      setHintsShown(prev => ({ ...prev, [stepIndex]: 1 }));
      setScenarioStats(prev => ({ ...prev, hintsUsed: prev.hintsUsed + 1 }));
    } else if (hintLevel === 1) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Full Hint: ${step.hintFull || 'No additional hint available'}` }
      ]);
      setHintsShown(prev => ({ ...prev, [stepIndex]: 2 }));
    }
  };

  const handleQuizComplete = (quizStats) => {
    let updatedProgress = { ...progress };
    updatedProgress = addQuizScore(
      updatedProgress,
      scenarioId,
      quizStats.score,
      quizStats.correctAnswers,
      quizStats.totalQuestions
    );
    
    setProgress(updatedProgress);
    saveProgress(updatedProgress);
    setShowQuiz(false);
  };
  
  // MODIFICATION: Create a handler to set the localStorage flag on close
  const handleCloseBriefing = () => {
    setShowMissionBriefing(false);
    safeSetItem(briefingStorageKey, true);
  };

  // --- RENDERING ---
  return (
    <div className="simulator-container full-page">
      {/* Settings CSS Variables are applied here */}
      <div 
          style={{
              '--terminal-text': customTheme.terminalText || '',
              '--accent-color': customTheme.accentColor || '',
              '--terminal-bg': customTheme.terminalBg || '',
          }}
          className="h-full w-full flex flex-col"
      >
          <Header 
            title={currentScenario.title}
            currentStep={currentStep + 1}
            totalSteps={currentScenario.steps.length}
            score={progress.totalScore}
            rank={progress.rank}
            onOpenSettings={() => setIsSettingsOpen(true)}
          />
          
          <div className="main-layout">
            <div className="main-content">
              <div className="simulation-page-grid">
                {/* COLUMN 1: Guide Panel (including the Collapsible Network Map) */}
                <GuidePanel 
                  scenario={currentScenario}
                  currentStep={currentStep}
                  tutorialMode={tutorialMode}
                  onTutorialToggle={() => {
                    const newTutorialMode = !tutorialMode;
                    setTutorialMode(newTutorialMode);
                    setProgress(prev => ({ ...prev, tutorialMode: newTutorialMode }));
                  }}
                  highlightedMachine={highlightedMachine}
                  highlightedArrow={highlightedArrow}
                  // MODIFICATION: Add prop to re-open the briefing
                  onShowBriefing={() => setShowMissionBriefing(true)}
                />
                
                {/* COLUMN 2: Unified Terminal & Logs Panel */}
                <AttackerPanel 
                  history={attackerHistory}
                  onCommandSubmit={handleCommandSubmit}
                  isProcessing={isProcessing}
                  network={currentScenario.network}
                  activeMachine={activeMachine}
                  onMachineChange={setActiveMachine}
                  serverHistory={serverHistory}
                  defenseHistory={defenseHistory} 
                  credentialInventory={credentialInventory}
                  onShowHint={() => handleShowHint(currentStep)}
                  hintsAvailable={currentStep < currentScenario.steps.length}
                />
              </div>
            </div>
          </div>

          {/* Modals */}
          <MissionModal
            isOpen={showMissionBriefing}
            // MODIFICATION: Use the new close handler
            onClose={handleCloseBriefing}
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
                  quiz={quizMap[scenarioId]}
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

          {/* Settings Modal */}
          <SettingsModal 
              isOpen={isSettingsOpen}
              onClose={() => setIsSettingsOpen(false)}
              currentTheme={customTheme}
              onUpdateTheme={handleUpdateTheme}
          />
      </div>
    </div>
  );
}