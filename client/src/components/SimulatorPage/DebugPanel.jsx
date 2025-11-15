// client/src/components/SimulatorPage/DebugPanel.jsx

export default function DebugPanel({
  debugMode,
  scenarioId,
  currentStep,
  totalSteps,
  isProcessing,
  subShell,
  historyLength,
  credCount,
  filesCount,
  wrongAttempts,
  hintsUsed
}) {
  if (!debugMode) return null;

  return (
    <div className="fixed bottom-4 right-4 bg-black/95 text-xs text-green-400 p-4 rounded-lg font-mono max-w-md z-50 border border-green-500/30">
      <div className="text-white font-bold mb-2">🐛 DEBUG MODE</div>
      <div>Scenario: {scenarioId}</div>
      <div>Step: {currentStep + 1}/{totalSteps}</div>
      <div>Processing: {isProcessing.toString()}</div>
      <div>SubShell: {subShell || 'none'}</div>
      <div>History: {historyLength} lines</div>
      <div>Loot: {credCount} creds, {filesCount} files</div>
      <div>Wrong Attempts: {wrongAttempts}</div>
      <div>Hints Used: {hintsUsed}</div>
      <div className="mt-2 text-yellow-400">Press Ctrl+Shift+D to toggle</div>
    </div>
  );
}
