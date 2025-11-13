import { useState, useRef, useEffect } from 'react';
import { Terminal, Server, Shield } from 'lucide-react';

export default function AttackerPanel({ 
  history, 
  onCommandSubmit, 
  isProcessing, 
  network,
  activeMachine,
  onMachineChange,
  serverHistory,
  onShowHint,
  hintsAvailable = false
}) {
  const [currentCommand, setCurrentCommand] = useState('');
  const terminalEndRef = useRef(null);
  const inputRef = useRef(null);

  // Auto-scroll to bottom when history updates
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history, serverHistory]);

  // Focus input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!currentCommand.trim() || isProcessing) {
      return;
    }

    onCommandSubmit(currentCommand);
    setCurrentCommand('');
  };

  const handleTerminalClick = () => {
    inputRef.current?.focus();
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      // Cycle through machines
      const machines = ['attacker', 'internal', 'dc'];
      const currentIndex = machines.indexOf(activeMachine);
      const nextIndex = (currentIndex + 1) % machines.length;
      onMachineChange(machines[nextIndex]);
    }
  };

  const getMachineInfo = () => {
    switch (activeMachine) {
      case 'internal':
        return {
          hostname: network.target.hostname,
          ip: network.target.ip,
          role: 'Internal Server'
        };
      case 'dc':
        return {
          hostname: 'DC01.contoso.local',
          ip: '10.0.1.10',
          role: 'Domain Controller'
        };
      default:
        return {
          hostname: network.attacker.hostname,
          ip: network.attacker.ip,
          role: 'Attacker Machine'
        };
    }
  };

  const machineInfo = getMachineInfo();
  const displayHistory = activeMachine === 'internal' ? serverHistory : history;

  return (
    <div className="panel attacker-panel">
      <div className="panel-header">
        <Terminal size={20} />
        <h2>Machine Terminal</h2>
        {/* DESIGN FIX APPLIED: Removed dynamic color classes (red/blue/green) */}
        <span className="panel-badge">
          {machineInfo.ip}
        </span>
        {activeMachine === 'attacker' && hintsAvailable && onShowHint && (
          <button className="hint-button" onClick={onShowHint} title="Get a hint for the current step">
            Hint
          </button>
        )}
      </div>

      {/* Machine Tabs */}
      <div className="machine-tabs">
        <button 
          className={`machine-tab ${activeMachine === 'attacker' ? 'active' : ''}`}
          onClick={() => onMachineChange('attacker')}
          title="Press Tab to cycle"
        >
          <Terminal size={16} />
          <span>Attacker</span>
        </button>
        <button 
          className={`machine-tab ${activeMachine === 'internal' ? 'active' : ''}`}
          onClick={() => onMachineChange('internal')}
          title="Press Tab to cycle"
        >
          <Server size={16} />
          <span>Internal Server</span>
        </button>
        <button 
          className={`machine-tab ${activeMachine === 'dc' ? 'active' : ''}`}
          onClick={() => onMachineChange('dc')}
          title="Press Tab to cycle"
        >
          <Shield size={16} />
          <span>Domain Controller</span>
        </button>
      </div>
      
      <div className="panel-content terminal-content" onClick={handleTerminalClick}>
        <div className="terminal-output">
          {displayHistory.map((entry, index) => (
            <div key={index} className={`terminal-line ${entry.type}`}>
              {entry.type === 'command' && <span className="prompt-symbol">$</span>}
              <span className="terminal-text">{entry.text}</span>
            </div>
          ))}
          
          {/* Command input line - only show on attacker machine */}
          {activeMachine === 'attacker' && !isProcessing && (
            <form onSubmit={handleSubmit} className="terminal-input-line">
              <span className="prompt">root@{network.attacker.hostname}:~#</span>
              <input
                ref={inputRef}
                type="text"
                value={currentCommand}
                onChange={(e) => setCurrentCommand(e.target.value)}
                onKeyDown={handleKeyDown}
                className="terminal-input"
                disabled={isProcessing}
                autoComplete="off"
                spellCheck="false"
              />
              <span className="cursor">_</span>
            </form>
          )}
          
          {activeMachine === 'attacker' && isProcessing && (
            <div className="terminal-line processing">
              <span className="processing-indicator">Processing...</span>
            </div>
          )}
          
          {activeMachine !== 'attacker' && (
            <div className="terminal-line info">
              <span className="terminal-text">[Read-only logs from {machineInfo.role}]</span>
            </div>
          )}
          
          <div ref={terminalEndRef} />
        </div>
      </div>
    </div>
  );
}