// client/src/components/SimulatorPage/index.jsx

import { useEffect, useMemo } from 'react';
import { Redirect } from 'wouter';
import { Activity } from 'lucide-react';
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";

// Components
import Header from '../Header';
import GuidePanel from '../GuidePanel';
import AttackerPanel from '../AttackerPanel';
import MissionModal from '../MissionModal';
import QuizPanel from '../QuizPanel';
import AchievementsPanel from '../AchievementsPanel';
import SettingsModal from '../SettingsModal';
import MachineInfoSheet from '../MachineInfoSheet';
import DebugPanel from './DebugPanel';

// Hooks
import { useSimulatorState } from './SimulatorState';
import { useScenarioInitialization } from './hooks/useScenarioInitialization';
import { useStepProcessing } from './hooks/useStepProcessing';
import { useScenarioCompletion } from './hooks/useScenarioCompletion';
import { useCommandHandling } from './hooks/useCommandHandling';
import { useModalManagement } from './hooks/useModalManagement';

// Data & Utils
import { quizMap } from '@/data/quizzes/index.js';
import { addQuizScore, saveProgress } from '@/lib/progressTracker';
import { safeSetItem } from '@/lib/safeStorage';
import { getCompromisedNodesMap, SUBSHELL_TIMEOUT } from '@/lib/simulator/constants';

export default function SimulatorPage({ 
  scenarioId, 
  allScenarios,
  progress,
  setProgress,
  appMode, 
  setAppMode,
}) {
  const currentScenario = allScenarios[scenarioId];

  // Initialize all state
  const state = useSimulatorState(scenarioId);
  
  // Initialize scenario
  const {
    isLoadingScenario,
    showMissionBriefing,
    setShowMissionBriefing,
    briefingStorageKey,
    resetScenario
  } = useScenarioInitialization(scenarioId, currentScenario);
  
  // Initialize completion handling
  const {
    isMissionCompleted,
    newAchievements,
    showMissionDebrief,
    setShowMissionDebrief,
    completeScenario,
    completionStats
  } = useScenarioCompletion({
    scenarioId,
    currentScenario,
    progress,
    setProgress,
    scenarioStats: state.scenarioStats
  });
  
  // Initialize step processing
  const {
    processStepOutput,
    processSubCommandOutput,
    processingRef,
    mountedRef
  } = useStepProcessing({
    scenarioId,
    currentScenario,
    currentStep: state.currentStep,
    setAttackerHistory: state.setAttackerHistory,
    setServerHistory: state.setServerHistory,
    setDefenseHistory: state.setDefenseHistory,
    setHighlightedMachine: state.setHighlightedMachine,
    setHighlightedArrow: state.setHighlightedArrow,
    setSubShell: state.setSubShell,
    setIsProcessing: state.setIsProcessing,
    setCurrentStep: state.setCurrentStep,
    setState: state.setState,
    completeScenario,
    scenarioStats: state.scenarioStats
  });
  
  // Initialize command handling
  const {
    handleCommandSubmit
  } = useCommandHandling({
    currentScenario,
    currentStep: state.currentStep,
    subShell: state.subShell,
    tutorialMode: state.tutorialMode,
    credentialInventory: state.credentialInventory,
    simulatedFileSystem: state.simulatedFileSystem,
    setAttackerHistory: state.setAttackerHistory,
    setScenarioStats: state.setScenarioStats,
    processStepOutput,
    processSubCommandOutput,
    setSubShell: state.setSubShell,
    subShellTimeout: state.subShellTimeout
  });
  
  // Initialize modal management
  const {
    isSettingsOpen,
    setIsSettingsOpen,
    showQuiz,
    setShowQuiz,
    showAchievements,
    setShowAchievements,
    inspectingNode,
    setInspectingNode
  } = useModalManagement();

  // Redirect if no scenario
  if (!currentScenario) {
    return <Redirect to="/" />;
  }

  // Reset scenario on mount/change
  useEffect(() => {
    const initialState = resetScenario();
    state.setCurrentStep(initialState.currentStep);
    state.setActiveMachine(initialState.activeMachine);
    state.setHighlightedMachine(initialState.highlightedMachine);
    state.setHighlightedArrow(initialState.highlightedArrow);
    state.setSubShell(initialState.subShell);
    state.setAttackerHistory(initialState.attackerHistory);
    state.setServerHistory(initialState.serverHistory);
    state.setDefenseHistory(initialState.defenseHistory);
    state.setCredentialInventory(initialState.credentialInventory);
    state.setSimulatedFiles(initialState.simulatedFiles);
    state.setSimulatedFileSystem(initialState.simulatedFileSystem);
    setInspectingNode(initialState.inspectingNode);
    state.setProcessedSteps(initialState.processedSteps);
    state.setScenarioStats(initialState.scenarioStats);
    state.setHintsShown(initialState.hintsShown);
    processingRef.current = false;
  }, [scenarioId]);

  // Sub-shell timeout
  useEffect(() => {
    if (state.subShell) {
      const timeout = setTimeout(() => {
        state.setAttackerHistory(prev => [
          ...prev,
          { type: 'warning', text: `[!] Sub-shell timeout after 2 minutes. Type "exit" to return.` }
        ]);
      }, SUBSHELL_TIMEOUT);
      
      state.setSubShellTimeout(timeout);
      
      return () => {
        if (timeout) clearTimeout(timeout);
      };
    }
  }, [state.subShell]);

  // Auto-advance steps with null expected command
  useEffect(() => {
    const step = currentScenario?.steps[state.currentStep];
    const stepKey = `${scenarioId}-${state.currentStep}`;
    
    if (
      step && 
      step.expectedCommand == null && 
      !processingRef.current && 
      !state.isProcessing &&
      !state.subShell &&
      !state.processedSteps.has(stepKey) &&
      mountedRef.current
    ) {
      state.setProcessedSteps(prev => new Set(prev).add(stepKey));
      processingRef.current = true;
      state.setIsProcessing(true);
      processStepOutput(step);
    }
  }, [state.currentStep, currentScenario?.id, state.isProcessing, state.subShell, state.processedSteps]);

  // Cleanup on unmount
  useEffect(() => {
    mountedRef.current = true;
    
    return () => {
      mountedRef.current = false;
      if (state.subShellTimeout) clearTimeout(state.subShellTimeout);
    };
  }, []);

  // Handle hint
  const handleShowHint = (stepIndex) => {
    const step = currentScenario.steps[stepIndex];
    if (!step) return;
    
    const hintLevel = state.hintsShown[stepIndex] || 0;
    if (hintLevel === 0) {
      state.setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Hint: ${step.hintShort || 'No hint available'}` }
      ]);
      state.setHintsShown(prev => ({ ...prev, [stepIndex]: 1 }));
      state.setScenarioStats(prev => ({ ...prev, hintsUsed: prev.hintsUsed + 1 }));
    } else if (hintLevel === 1) {
      state.setAttackerHistory(prev => [
        ...prev,
        { type: 'info', text: `[*] Full Hint: ${step.hintFull || 'No additional hint available'}` }
      ]);
      state.setHintsShown(prev => ({ ...prev, [stepIndex]: 2 }));
    }
  };

  // Handle quiz complete
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

  // Handle briefing close
  const handleCloseBriefing = () => {
    setShowMissionBriefing(false);
    safeSetItem(briefingStorageKey, true);
  };

  // Compromised nodes
  const compromisedNodes = useMemo(() => {
    const nodes = new Set();
    nodes.add('attacker');
    
    const compromiseMap = getCompromisedNodesMap();
    
    if (progress && progress.scenariosCompleted) {
      progress.scenariosCompleted.forEach(id => {
        if (compromiseMap[id]) {
          compromiseMap[id].forEach(node => nodes.add(node));
        }
      });
    }
    
    return Array.from(nodes);
  }, [progress]);

  return (
    <div className="simulator-container full-page relative">
      {/* Loading Overlay */}
      {isLoadingScenario && (
        <div className="absolute inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="text-white text-center">
            <Activity className="w-8 h-8 animate-spin mx-auto mb-2 text-[#2D9CDB]" />
            <p className="text-sm">Loading scenario...</p>
          </div>
        </div>
      )}
      
      <div 
        style={{
          '--terminal-text': state.customTheme.terminalText || '',
          '--accent-color': state.customTheme.accentColor || '',
          '--terminal-bg': state.customTheme.terminalBg || '',
        }}
        className="h-screen w-full flex flex-col overflow-hidden"
      >
        {/* Header */}
        <Header 
          title={currentScenario.title}
          currentStep={state.currentStep + 1}
          totalSteps={currentScenario.steps.length}
          score={progress.totalScore}
          rank={progress.rank}
          onOpenSettings={() => setIsSettingsOpen(true)}
          scenarioId={scenarioId}
          progress={progress}
        />
        
        {/* Main Content */}
        <main className="flex-1 flex overflow-hidden min-h-0">
          <ResizablePanelGroup direction="horizontal" className="w-full">
            <ResizablePanel defaultSize={30} minSize={20}>
              <GuidePanel 
                scenario={currentScenario}
                currentStep={state.currentStep}
                tutorialMode={state.tutorialMode}
                onTutorialToggle={() => {
                  const newTutorialMode = !state.tutorialMode;
                  state.setTutorialMode(newTutorialMode);
                  
                  const updatedProgress = {
                    ...progress,
                    tutorialMode: newTutorialMode,
                    updatedAt: Date.now()
                  };
                  
                  setProgress(updatedProgress);
                  saveProgress(updatedProgress);
                }}
                highlightedMachine={state.highlightedMachine}
                highlightedArrow={state.highlightedArrow}
                onShowBriefing={() => setShowMissionBriefing(true)}
                progress={progress}
                onNodeClick={setInspectingNode}
              />
            </ResizablePanel>

            <ResizableHandle withHandle />

            <ResizablePanel defaultSize={70} minSize={30}>
              <AttackerPanel 
                history={state.attackerHistory}
                onCommandSubmit={handleCommandSubmit}
                isProcessing={state.isProcessing}
                network={currentScenario.network}
                activeMachine={state.activeMachine}
                onMachineChange={state.setActiveMachine}
                serverHistory={state.serverHistory}
                defenseHistory={state.defenseHistory}
                credentialInventory={state.credentialInventory}
                simulatedFiles={state.simulatedFiles}
                onShowHint={() => handleShowHint(state.currentStep)}
                hintsAvailable={state.currentStep < currentScenario.steps.length}
                subShell={state.subShell}
              />
            </ResizablePanel>
          </ResizablePanelGroup>
        </main>

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
          stats={completionStats}
          newAchievements={newAchievements}
          progress={progress}
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
          currentTheme={state.customTheme}
          onUpdateTheme={state.handleUpdateTheme}
        />
        
        <MachineInfoSheet
          nodeName={inspectingNode}
          network={currentScenario.network}
          compromisedNodes={compromisedNodes}
          isOpen={!!inspectingNode}
          onClose={() => setInspectingNode(null)}
        />
        
        {/* Debug Panel */}
        <DebugPanel
          debugMode={state.debugMode}
          scenarioId={scenarioId}
          currentStep={state.currentStep}
          totalSteps={currentScenario?.steps.length}
          isProcessing={state.isProcessing}
          subShell={state.subShell}
          historyLength={state.attackerHistory.length}
          credCount={state.credentialInventory.length}
          filesCount={state.simulatedFiles.length}
          wrongAttempts={state.scenarioStats.wrongAttempts}
          hintsUsed={state.scenarioStats.hintsUsed}
        />
      </div>
    </div>
  );
}
