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
  
  // --- MODIFIED: Loot & File System State ---
  const [defenseHistory, setDefenseHistory] = useState([]);
  const [credentialInventory, setCredentialInventory] = useState([]);
  const [simulatedFiles, setSimulatedFiles] = useState([]);
  const [simulatedFileSystem, setSimulatedFileSystem] = useState({}); // NEW: Holds loot *before* it's downloaded
  
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [customTheme, setCustomTheme] = useState(() => {
    try {
        return JSON.parse(localStorage.getItem('terminal_theme')) || {};
    } catch (e) {
        return {};
    }
  });

  
  // --- MODAL / GAME STATE ---
  const briefingStorageKey = `hasSeenBriefing_${scenarioId}`;
  const [showMissionBriefing, setShowMissionBriefing] = useState(() => {
    const hasSeen = safeGetItem(briefingStorageKey, null);
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
    setCredentialInventory([]); 
    setSimulatedFiles([]);
    setSimulatedFileSystem({}); // NEW: Reset simulated file system
    
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
  }, [scenarioId, briefingStorageKey]); 

  // Auto-advances steps with expectedCommand: null
  useEffect(() => {
    const step = currentScenario?.steps[currentStep];
    if (step && step.expectedCommand == null && !isProcessing) {
      setIsProcessing(true);
      processStepOutput(step);
    }
  }, [currentStep, currentScenario, isProcessing]);

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
  
  // --- [ MODIFICATION 1: UPDATED processStepOutput ] ---
  // Replaced hardcoded `if (scenarioId === ...)` with a generic `lootToGrant` system.
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

    // --- NEW GENERIC LOOT SYSTEM ---
    // This block replaces the old hardcoded `if (scenarioId === ...)` checks
    if (step.lootToGrant) {
      // Grant files to the *simulated file system* (not the Files tab)
      if (step.lootToGrant.files) {
        setSimulatedFileSystem(prev => ({
          ...prev,
          ...step.lootToGrant.files
        }));
      }
      // Grant credentials (passwords/hashes)
      if (step.lootToGrant.creds) {
        step.lootToGrant.creds.forEach(cred => {
          harvestCredential(cred.type, cred.username, cred.secret);
        });
      }
      // Grant files directly to the "Files" tab (for `download` commands)
      if (step.lootToGrant.download) {
        step.lootToGrant.download.forEach(file => {
          setSimulatedFiles(prev => [...prev, file]);
        });
      }
    }
    // --- END NEW LOOT SYSTEM ---

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
    // ... (This function is unchanged)
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

  const resolveLootVariables = (commandString) => {
    const lootRegex = /\[loot:([^\]]+)\]/gi;
    let resolvedCmd = commandString;

    const matches = commandString.match(lootRegex);
    if (!matches) {
      return commandString;
    }

    for (const match of matches) {
      const usernameToFind = match.replace(lootRegex, '$1').toLowerCase();
      const foundCred = credentialInventory.find(
        (c) => c.username.toLowerCase() === usernameToFind
      );

      if (foundCred) {
        resolvedCmd = resolvedCmd.replace(match, foundCred.secret);
      } else {
        resolvedCmd = resolvedCmd.replace(match, "LOOT_NOT_FOUND");
      }
    }
    return resolvedCmd;
  };

  // --- [ MODIFICATION 2: UPDATED handleCommandSubmit ] ---
  // This now checks for 'dir', 'ls', 'cat', 'type' before checking the step command.
  const handleCommandSubmit = (command) => {
    const normalizedInput = command.trim().toLowerCase();
    
    // Always echo the command
    setAttackerHistory(prev => [
      ...prev,
      { type: 'command', text: `root@${currentScenario.network.attacker.hostname}:~# ${command}` }
    ]);

    // --- NEW: Interactive File System Commands (Pre-check) ---
    // These commands do NOT advance the step.
    if (normalizedInput === 'ls' || normalizedInput === 'dir') {
      const files = Object.keys(simulatedFileSystem);
      if (files.length === 0) {
        setAttackerHistory(prev => [
          ...prev, { type: 'output', text: 'No files found.' }
        ]);
      } else {
        const fileList = files.map(file => `[File] ${file}`);
        setAttackerHistory(prev => [
          ...prev, { type: 'output', text: fileList.join('\n') }
        ]);
      }
      return; // Do not proceed to step check
    }

    if (normalizedInput.startsWith('cat ') || normalizedInput.startsWith('type ')) {
      const fileName = command.split(' ')[1];
      const file = simulatedFileSystem[fileName.toLowerCase()];
      if (file) {
        setAttackerHistory(prev => [
          ...prev, { type: 'output', text: file.content }
        ]);
      } else {
        setAttackerHistory(prev => [
          ...prev, { type: 'error', text: `[!] File not found: ${fileName}` }
        ]);
      }
      return; // Do not proceed to step check
    }
    // --- End of new pre-checks ---

    // Standard step validation logic
    const step = currentScenario.steps[currentStep];
    if (!step) {
      setAttackerHistory(prev => [
        ...prev,
        { type: 'error', text: '[!] Simulation complete. Select a new scenario to restart.' }
      ]);
      return;
    }

    const expectedList = Array.isArray(step.expectedCommands) && step.expectedCommands.length > 0
      ? step.expectedCommands
      : step.expectedCommand
        ? [step.expectedCommand]
        : [];

    const isMatch = expectedList.some(cmd => {
      if (!cmd) return false;
      const resolvedCmd = resolveLootVariables(cmd.trim().toLowerCase());
      return normalizedInput === resolvedCmd;
    });

    // If the input does not match any expected command...
    if (!isMatch) {
      setScenarioStats(prev => ({ ...prev, wrongAttempts: prev.wrongAttempts + 1 }));

      const mistakes = Array.isArray(step.commonMistakes) ? step.commonMistakes : [];
      let handledMistake = false;
      for (const mistake of mistakes) {
        if (!mistake || !mistake.pattern) continue;
        try {
          const regex = new RegExp(mistake.pattern, 'i');
          if (regex.test(command)) {
            handledMistake = true;
            setAttackerHistory(prev => [
              ...prev,
              { type: 'error', text: `[!] ${mistake.message}` }
            ]);
            break;
          }
        } catch (err) { /* ignore */ }
      }

      if (!handledMistake) {
        if (tutorialMode) {
          setAttackerHistory(prev => [
            ...prev,
            { type: 'error', text: `[!] Not quite right. Hint: ${step.hintShort || 'Try again'}` }
          ]);
        } else {
          const firstExpectedCmd = expectedList.length > 0 ? resolveLootVariables(expectedList[0]) : '';
          // Don't show the full resolved command if it's a "download" or "note" command
          const suggestion = (firstExpectedCmd && !firstExpectedCmd.startsWith('download') && !firstExpectedCmd.startsWith('note'))
            ? `Did you mean: ${firstExpectedCmd}?` 
            : '';
          setAttackerHistory(prev => [
            ...prev,
            { type: 'error', text: `[!] Command not recognized or incorrect for this step.` },
            ...(suggestion ? [{ type: 'error', text: `[!] ${suggestion}` }] : [])
          ]);
        }
      }
      return;
    }

    // If we reach here, the command was correct
    setIsProcessing(true);
    processStepOutput(step);
  };
  
  const handleShowHint = (stepIndex) => {
    // ... (This function is unchanged)
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
    // ... (This function is unchanged)
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
  
  const handleCloseBriefing = () => {
    setShowMissionBriefing(false);
    safeSetItem(briefingStorageKey, true);
  };

  // --- RENDERING ---
  return (
    <div className="simulator-container full-page">
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
                  onShowBriefing={() => setShowMissionBriefing(true)}
                  progress={progress}
                />
                
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
                  simulatedFiles={simulatedFiles} 
                  onShowHint={() => handleShowHint(currentStep)}
                  hintsAvailable={currentStep < currentScenario.steps.length}
                />
              </div>
            </div>
          </div>

          {/* Modals */}
          <MissionModal
            isOpen={showMissionBriefing}
            onClose={handleCloseBriefing}
            type="briefing"
            scenario={currentScenario}
          />

          <MissionModal
            isOpen={showMissionDebrief}
            onClose={() => {
              setShowMissionDebrief(false);
              if (quizMap[scenarioId]) {
                setShowQuiz(true);
              }
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