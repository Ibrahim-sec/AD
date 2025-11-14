// client/src/components/SimulatorPage.jsx
// Complete version with ALL imports and dependencies

import { useState, useEffect, useRef, useMemo } from 'react';
import { Link } from 'wouter';
import { Activity, AlertTriangle } from 'lucide-react';

// Component imports
import Header from './Header';
import GuidePanel from './GuidePanel';
import AttackerPanel from './AttackerPanel';
import MissionModal from './MissionModal';
import QuizPanel from './QuizPanel';
import AchievementsPanel from './AchievementsPanel';
import SettingsModal from './SettingsModal';
import InteractiveNetworkMap from './InteractiveNetworkMap';
import MachineInfoSheet from './MachineInfoSheet';

// Data imports
import { quizMap } from '../data/quizzes/index.js';
import { achievements, getUnlockedAchievements } from '../data/achievements.js';

// Library imports
import { 
  saveProgress, 
  addScenarioCompletion,
  addQuizScore,
  unlockAchievement
} from '../lib/progressTracker.js';

// UI Component imports - CRITICAL: Check if you have this installed
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "../components/ui/resizable"; // or "@/components/ui/resizable"

// ============================================================================
// CONSTANTS
// ============================================================================

const COMMAND_HISTORY_KEY = 'ad-simulator-command-history';
const MAX_COMMAND_HISTORY = 100;
const SUBSHELL_TIMEOUT = 120000; // 2 minutes
const MAX_COMMAND_LENGTH = 1000;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

const calculateScenarioScore = (wrongAttempts, hintsUsed) => {
  if (wrongAttempts === 0 && hintsUsed === 0) {
    return 10; // Perfect score
  } else if (hintsUsed > 0 && hintsUsed <= 2) {
    return 5; // Used hints
  } else if (wrongAttempts > 0) {
    return Math.max(0, 10 - (wrongAttempts * 2));
  }
  return 0;
};

const formatTime = (seconds) => {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}:${secs.toString().padStart(2, '0')}`;
};

// ============================================================================
// MAIN COMPONENT
// ============================================================================

export default function SimulatorPage({
  scenarioId,
  allScenarios,
  progress,
  setProgress,
  appMode,
  setAppMode
}) {
  const currentScenario = allScenarios[scenarioId];

  // ========== STATE ==========
  const [currentStep, setCurrentStep] = useState(0);
  const [attackerOutput, setAttackerOutput] = useState([]);
  const [serverOutput, setServerOutput] = useState([]);
  const [wrongAttempts, setWrongAttempts] = useState(0);
  const [hintsUsed, setHintsUsed] = useState(0);
  const [showBriefing, setShowBriefing] = useState(true);
  const [showDebrief, setShowDebrief] = useState(false);
  const [isMissionCompleted, setIsMissionCompleted] = useState(false);
  const [tutorialMode, setTutorialMode] = useState(progress?.tutorialMode ?? true);
  const [highlightedMachine, setHighlightedMachine] = useState(null);
  const [highlightedArrow, setHighlightedArrow] = useState(null);
  const [timeElapsed, setTimeElapsed] = useState(0);
  const [showQuiz, setShowQuiz] = useState(false);
  const [quizScore, setQuizScore] = useState(null);
  const [showAchievements, setShowAchievements] = useState(false);
  const [newAchievements, setNewAchievements] = useState([]);
  const [showSettings, setShowSettings] = useState(false);
  const [selectedMachine, setSelectedMachine] = useState(null);

  const timerRef = useRef(null);

  // ========== EFFECTS ==========

  // Timer Effect
  useEffect(() => {
    if (!showBriefing && !isMissionCompleted) {
      timerRef.current = setInterval(() => {
        setTimeElapsed(prev => prev + 1);
      }, 1000);
    }

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
      }
    };
  }, [showBriefing, isMissionCompleted]);

  // Reset on scenario change
  useEffect(() => {
    setCurrentStep(0);
    setAttackerOutput([]);
    setServerOutput([]);
    setWrongAttempts(0);
    setHintsUsed(0);
    setShowBriefing(true);
    setShowDebrief(false);
    setIsMissionCompleted(false);
    setTimeElapsed(0);
    setHighlightedMachine(null);
    setHighlightedArrow(null);
    setShowQuiz(false);
    setQuizScore(null);
    setNewAchievements([]);
    setSelectedMachine(null);
  }, [scenarioId]);

  // Prevent multiple mission complete modals
  useEffect(() => {
    if (isMissionCompleted && !showDebrief) {
      const timer = setTimeout(() => {
        setShowDebrief(true);
      }, 500);
      return () => clearTimeout(timer);
    }
  }, [isMissionCompleted, showDebrief]);

  // ========== HANDLERS ==========

  const handleCommandSubmit = (command) => {
    const step = currentScenario.steps[currentStep];
    
    if (!step) return;

    // Check if command is correct
    const isCorrect = Array.isArray(step.expectedCommands)
      ? step.expectedCommands.some(cmd => command.toLowerCase().includes(cmd.toLowerCase()))
      : command.toLowerCase().includes(step.expectedCommand.toLowerCase());

    if (isCorrect) {
      // Correct command - add output
      const output = step.attackerOutput || ['Command executed successfully'];
      setAttackerOutput(prev => [...prev, `$ ${command}`, ...output]);

      // Add server output if exists
      if (step.serverOutput) {
        setTimeout(() => {
          setServerOutput(prev => [...prev, ...step.serverOutput]);
        }, step.delay || 150);
      }

      // Highlighting
      if (step.highlightMachine) {
        setHighlightedMachine(step.highlightMachine);
      }
      if (step.highlightArrow) {
        setHighlightedArrow(step.highlightArrow);
      }

      // Move to next step or complete
      if (currentStep < currentScenario.steps.length - 1) {
        setTimeout(() => {
          setCurrentStep(prev => prev + 1);
        }, step.delay || 300);
      } else {
        // Scenario complete
        handleScenarioComplete();
      }
    } else {
      // Wrong command
      setWrongAttempts(prev => prev + 1);
      const errorMsg = step.commonMistakes?.[0]?.message || 'Try again or use a hint.';
      setAttackerOutput(prev => [
        ...prev,
        `$ ${command}`,
        `[!] Incorrect command. ${errorMsg}`
      ]);
    }
  };

  const handleScenarioComplete = () => {
    if (isMissionCompleted) return; // Prevent duplicate

    setIsMissionCompleted(true);

    const score = calculateScenarioScore(wrongAttempts, hintsUsed);

    // Update progress
    const updatedProgress = addScenarioCompletion(progress, scenarioId, {
      wrongAttempts,
      hintsUsed,
      timeSpent: timeElapsed
    });

    // Check for new achievements
    const previousAchievements = new Set(progress.unlockedAchievements || []);
    const currentAchievements = getUnlockedAchievements(updatedProgress);
    const newUnlocked = currentAchievements.filter(id => !previousAchievements.has(id));

    if (newUnlocked.length > 0) {
      setNewAchievements(
        newUnlocked.map(id => achievements.find(a => a.id === id)).filter(Boolean)
      );
      
      newUnlocked.forEach(achievementId => {
        unlockAchievement(updatedProgress, achievementId);
      });
    }

    setProgress(updatedProgress);
    saveProgress(updatedProgress);
  };

  const handleHintUsed = () => {
    setHintsUsed(prev => prev + 1);
  };

  const handleQuizComplete = (score, correctAnswers, totalQuestions) => {
    setQuizScore(score);
    
    const updatedProgress = addQuizScore(
      progress,
      scenarioId,
      score,
      correctAnswers,
      totalQuestions
    );
    
    setProgress(updatedProgress);
    saveProgress(updatedProgress);
  };

  const handleNodeClick = (nodeId) => {
    setSelectedMachine(nodeId);
  };

  const handleCloseMissionComplete = () => {
    setShowDebrief(false);
    const quiz = quizMap[scenarioId];
    if (quiz && !quizScore) {
      setShowQuiz(true);
    }
  };

  // ========== NETWORK CONFIGURATION ==========

  const networkNodes = useMemo(() => {
    const nodes = [
      {
        id: 'attacker',
        label: currentScenario.network.attacker.hostname,
        type: 'attacker',
        ip: currentScenario.network.attacker.ip,
        details: {
          os: 'Kali Linux',
          role: 'Attack Machine',
          tools: ['Impacket', 'Mimikatz', 'BloodHound', 'Rubeus']
        }
      },
      {
        id: 'target',
        label: currentScenario.network.target.hostname,
        type: 'target',
        ip: currentScenario.network.target.ip,
        details: {
          os: 'Windows Server 2019',
          role: 'Target Server',
          services: ['SMB', 'HTTP', 'LDAP', 'RDP']
        }
      }
    ];

    if (currentScenario.network.dc) {
      nodes.push({
        id: 'dc',
        label: currentScenario.network.dc.hostname,
        type: 'dc',
        ip: currentScenario.network.dc.ip,
        details: {
          os: 'Windows Server 2019',
          role: 'Domain Controller',
          services: ['Kerberos', 'LDAP', 'DNS', 'NTDS']
        }
      });
    }

    return nodes;
  }, [currentScenario]);

  const networkConnections = useMemo(() => {
    const connections = [
      { from: 'attacker', to: 'target', label: 'Attack Path' }
    ];

    if (currentScenario.network.dc) {
      connections.push(
        { from: 'attacker', to: 'dc', label: 'Auth Request' },
        { from: 'dc', to: 'target', label: 'Domain Trust' }
      );
    }

    return connections;
  }, [currentScenario]);

  // ========== RENDER ==========

  if (!currentScenario) {
    return (
      <div className="min-h-screen bg-[#0a0b0d] flex items-center justify-center">
        <div className="text-center">
          <AlertTriangle className="w-16 h-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-white mb-2">Scenario Not Found</h2>
          <p className="text-white/60 mb-4">The requested scenario does not exist.</p>
          <Link href="/">
            <a className="px-6 py-3 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white font-semibold rounded-lg transition-all inline-block">
              Return Home
            </a>
          </Link>
        </div>
      </div>
    );
  }

  const quiz = quizMap[scenarioId];

  return (
    <div className="h-screen flex flex-col bg-[#0a0b0d] overflow-hidden">
      {/* Header */}
      <Header
        scenario={currentScenario}
        progress={progress}
        timeElapsed={timeElapsed}
        currentStep={currentStep}
        totalSteps={currentScenario.steps.length}
        onSettingsClick={() => setShowSettings(true)}
        onAchievementsClick={() => setShowAchievements(true)}
      />

      {/* Main Content - Three Panel Layout */}
      <div className="flex-1 overflow-hidden">
        <ResizablePanelGroup direction="horizontal" className="h-full">
          {/* LEFT PANEL - Attack Guide */}
          <ResizablePanel defaultSize={25} minSize={20} maxSize={35}>
            <GuidePanel
              scenario={currentScenario}
              currentStep={currentStep}
              tutorialMode={tutorialMode}
              onTutorialToggle={() => setTutorialMode(!tutorialMode)}
              highlightedMachine={highlightedMachine}
              highlightedArrow={highlightedArrow}
              onShowBriefing={() => setShowBriefing(true)}
              progress={progress}
              onNodeClick={handleNodeClick}
            />
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* CENTER PANEL - Network Map */}
          <ResizablePanel defaultSize={35} minSize={25} maxSize={50}>
            <div className="h-full flex flex-col bg-[#0f1419]">
              {/* Network Visualization */}
              <div className="flex-1 flex items-center justify-center p-4 relative">
                <InteractiveNetworkMap
                  nodes={networkNodes}
                  connections={networkConnections}
                  highlightedNode={highlightedMachine}
                  highlightedConnection={highlightedArrow}
                  onNodeClick={handleNodeClick}
                />
              </div>

              {/* Domain Info Bar */}
              <div className="bg-[#1a1b1e] border-t border-white/10 p-3 flex items-center justify-between flex-shrink-0">
                <div className="flex items-center gap-2">
                  <Activity className="w-4 h-4 text-[#2D9CDB]" />
                  <span className="text-xs text-white/60">Domain:</span>
                  <span className="text-xs font-mono text-white">{currentScenario.network.domain}</span>
                </div>
                <div className="flex items-center gap-2 text-xs text-white/60">
                  <span>Network:</span>
                  <span className="font-mono text-white">10.0.1.0/24</span>
                </div>
              </div>
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* RIGHT PANEL - Terminal */}
          <ResizablePanel defaultSize={40} minSize={30}>
            <AttackerPanel
              scenario={currentScenario}
              currentStep={currentStep}
              attackerOutput={attackerOutput}
              serverOutput={serverOutput}
              onCommandSubmit={handleCommandSubmit}
              onHintUsed={handleHintUsed}
              tutorialMode={tutorialMode}
              isMissionCompleted={isMissionCompleted}
            />
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* ========== MODALS ========== */}

      {/* Mission Briefing Modal */}
      {showBriefing && (
        <MissionModal
          isOpen={showBriefing}
          onClose={() => setShowBriefing(false)}
          type="briefing"
          scenario={currentScenario}
        />
      )}

      {/* Mission Debrief Modal */}
      {showDebrief && isMissionCompleted && (
        <MissionModal
          isOpen={showDebrief}
          onClose={handleCloseMissionComplete}
          type="debrief"
          scenario={currentScenario}
          stats={{
            scoreEarned: calculateScenarioScore(wrongAttempts, hintsUsed),
            timeSpent: formatTime(timeElapsed),
            stepsCompleted: currentScenario.steps.length,
            wrongAttempts,
            hintsUsed
          }}
          newAchievements={newAchievements}
        />
      )}

      {/* Quiz Modal */}
      {quiz && showQuiz && (
        <QuizPanel
          quiz={quiz}
          onComplete={handleQuizComplete}
          onClose={() => setShowQuiz(false)}
        />
      )}

      {/* Achievements Panel */}
      {showAchievements && (
        <AchievementsPanel
          progress={progress}
          onClose={() => setShowAchievements(false)}
        />
      )}

      {/* Settings Modal */}
      {showSettings && (
        <SettingsModal
          tutorialMode={tutorialMode}
          onTutorialModeChange={setTutorialMode}
          onClose={() => setShowSettings(false)}
        />
      )}

      {/* Machine Info Sheet */}
      {selectedMachine && (
        <MachineInfoSheet
          machine={networkNodes.find(n => n.id === selectedMachine)}
          onClose={() => setSelectedMachine(null)}
        />
      )}
    </div>
  );
}
