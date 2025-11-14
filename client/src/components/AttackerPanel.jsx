// client/src/components/AttackerPanel.jsx

import { useState, useRef, useEffect } from 'react';
import { Terminal, Server, Send, Lightbulb, RefreshCw } from 'lucide-react';

export default function AttackerPanel({
  scenario,
  currentStep,
  attackerOutput = [],
  serverOutput = [],
  onCommandSubmit,
  onHintUsed,
  tutorialMode = true,
  isMissionCompleted = false
}) {
  const [command, setCommand] = useState('');
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [showHint, setShowHint] = useState(false);
  
  const attackerTerminalRef = useRef(null);
  const serverTerminalRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll terminals
  useEffect(() => {
    if (attackerTerminalRef.current) {
      attackerTerminalRef.current.scrollTop = attackerTerminalRef.current.scrollHeight;
    }
  }, [attackerOutput]);

  useEffect(() => {
    if (serverTerminalRef.current) {
      serverTerminalRef.current.scrollTop = serverTerminalRef.current.scrollHeight;
    }
  }, [serverOutput]);

  // Focus input on mount
  useEffect(() => {
    if (inputRef.current && !isMissionCompleted) {
      inputRef.current.focus();
    }
  }, [currentStep, isMissionCompleted]);

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!command.trim() || isMissionCompleted) return;

    // Add to history
    setCommandHistory(prev => [...prev, command]);
    setHistoryIndex(-1);

    // Submit command
    onCommandSubmit(command);
    
    // Clear input
    setCommand('');
    setShowHint(false);
  };

  const handleKeyDown = (e) => {
    // Command history navigation
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex === -1 
          ? commandHistory.length - 1 
          : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setCommand(commandHistory[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex >= 0) {
        const newIndex = historyIndex + 1;
        if (newIndex >= commandHistory.length) {
          setHistoryIndex(-1);
          setCommand('');
        } else {
          setHistoryIndex(newIndex);
          setCommand(commandHistory[newIndex]);
        }
      }
    }
  };

  const handleShowHint = () => {
    setShowHint(true);
    if (onHintUsed) {
      onHintUsed();
    }
  };

  const step = scenario?.steps?.[currentStep];

  return (
    <div className="h-full flex flex-col bg-[#1a1b1e]">
      {/* Header Tabs */}
      <div className="flex border-b border-white/10 bg-[#0f1419]">
        <div className="flex-1 flex items-center gap-2 px-4 py-3 border-r border-white/10 bg-[#1a1b1e]">
          <Terminal className="w-4 h-4 text-[#2D9CDB]" />
          <span className="text-sm font-semibold text-white">Attacker Machine</span>
          <span className="text-xs text-white/40 ml-auto">{scenario?.network?.attacker?.hostname}</span>
        </div>
        <div className="flex-1 flex items-center gap-2 px-4 py-3">
          <Server className="w-4 h-4 text-red-400" />
          <span className="text-sm font-semibold text-white">Target Server</span>
          <span className="text-xs text-white/40 ml-auto">{scenario?.network?.target?.hostname}</span>
        </div>
      </div>

      {/* Terminals */}
      <div className="flex-1 flex overflow-hidden">
        {/* Attacker Terminal */}
        <div className="flex-1 flex flex-col border-r border-white/10">
          <div 
            ref={attackerTerminalRef}
            className="flex-1 overflow-y-auto p-4 bg-[#0a0b0d] font-mono text-sm scrollbar-thin"
          >
            {attackerOutput.length === 0 ? (
              <div className="text-white/40">
                <p>root@kali-attacker:~# _</p>
                <p className="mt-2 text-xs">Waiting for commands...</p>
              </div>
            ) : (
              attackerOutput.map((line, idx) => (
                <div 
                  key={idx} 
                  className={`mb-1 ${
                    line.startsWith('$') ? 'text-[#2D9CDB]' :
                    line.startsWith('[+]') ? 'text-green-400' :
                    line.startsWith('[!]') ? 'text-red-400' :
                    line.startsWith('[*]') ? 'text-yellow-400' :
                    'text-white/80'
                  }`}
                >
                  {line}
                </div>
              ))
            )}
          </div>

          {/* Command Input */}
          <div className="p-4 bg-[#0f1419] border-t border-white/10">
            <form onSubmit={handleSubmit} className="flex items-center gap-2">
              <span className="text-[#2D9CDB] font-mono text-sm flex-shrink-0">
                root@kali-attacker:~#
              </span>
              <input
                ref={inputRef}
                type="text"
                value={command}
                onChange={(e) => setCommand(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isMissionCompleted}
                placeholder={isMissionCompleted ? "Mission completed!" : "Enter command..."}
                className="flex-1 bg-transparent border-none outline-none text-white font-mono text-sm placeholder:text-white/30 disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                type="submit"
                disabled={!command.trim() || isMissionCompleted}
                className="p-2 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 disabled:bg-white/10 disabled:cursor-not-allowed rounded transition-all"
              >
                <Send className="w-4 h-4 text-white" />
              </button>
            </form>

            {/* Hint Button */}
            {tutorialMode && step && !isMissionCompleted && (
              <div className="mt-3 flex items-center gap-2">
                {!showHint ? (
                  <button
                    onClick={handleShowHint}
                    className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/30 rounded-lg text-xs text-yellow-400 transition-all"
                  >
                    <Lightbulb className="w-3 h-3" />
                    Show Hint
                  </button>
                ) : (
                  <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-2 flex-1">
                    <div className="flex items-start gap-2">
                      <Lightbulb className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <div className="text-xs font-semibold text-yellow-400 mb-1">Hint:</div>
                        <p className="text-xs text-yellow-300/80">{step.hintShort || step.hintFull}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Server Terminal */}
        <div className="flex-1 flex flex-col">
          <div 
            ref={serverTerminalRef}
            className="flex-1 overflow-y-auto p-4 bg-[#0a0b0d] font-mono text-sm scrollbar-thin"
          >
            {serverOutput.length === 0 ? (
              <div className="text-white/40">
                <p>[Server Logs]</p>
                <p className="mt-2 text-xs">Monitoring for activity...</p>
              </div>
            ) : (
              serverOutput.map((line, idx) => (
                <div 
                  key={idx} 
                  className={`mb-1 ${
                    line.includes('ALERT') || line.includes('CRITICAL') ? 'text-red-400' :
                    line.includes('WARNING') ? 'text-yellow-400' :
                    line.includes('SUCCESS') || line.includes('AUTHENTICATED') ? 'text-green-400' :
                    'text-white/70'
                  }`}
                >
                  {line}
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Status Bar */}
      <div className="flex items-center justify-between px-4 py-2 bg-[#0f1419] border-t border-white/10 text-xs">
        <div className="flex items-center gap-4">
          <span className="text-white/60">
            Step: <span className="text-white font-semibold">{currentStep + 1}</span>/{scenario?.steps?.length || 0}
          </span>
          <span className="text-white/60">
            Commands: <span className="text-white font-semibold">{commandHistory.length}</span>
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isMissionCompleted ? (
            <span className="text-green-400 font-semibold flex items-center gap-1">
              ✓ Mission Complete
            </span>
          ) : (
            <span className="text-[#2D9CDB]">Ready</span>
          )}
        </div>
      </div>
    </div>
  );
}
