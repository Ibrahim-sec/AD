import { useState, useRef, useEffect, useCallback } from 'react';
import { Terminal, Server, Shield } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

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
  const [commandHistory, setCommandHistory] = useState([]); // NEW STATE: Stores successful commands
  const [historyIndex, setHistoryIndex] = useState(0); // NEW STATE: Tracks position in history (0 to commandHistory.length)
  
  // Create separate refs for each scrollable area and its end-point
  const terminalScrollRef = useRef(null);
  const terminalEndRef = useRef(null);
  const logsScrollRef = useRef(null);
  const logsEndRef = useRef(null);
  const inputRef = useRef(null);

  const currentTab = activeMachine === 'attacker' ? 'attacker-console' : 'logs-view';
  
  // Internal state for selected machine when on the 'logs-view' tab
  const [logMachine, setLogMachine] = useState(activeMachine === 'dc' ? 'dc' : 'internal');

  // Logic to add command to history and reset index
  const updateCommandHistory = useCallback((command) => {
    const trimmedCommand = command.trim();
    if (trimmedCommand) {
        setCommandHistory(prev => {
            if (prev.length > 0 && prev[prev.length - 1] === trimmedCommand) {
                return prev;
            }
            // Only store commands typed in the terminal
            return [...prev, trimmedCommand];
        });
        // When a new command is added, reset the index to the end (new input line position)
        setHistoryIndex(prev => prev + 1);
    }
  }, []);

  // --- SCROLL LOGIC ---
  
  // Smart scroll for Attacker Terminal
  useEffect(() => {
    const element = terminalScrollRef.current;
    if (element) {
      const isScrolledToBottom = 
        element.scrollHeight - element.scrollTop <= element.clientHeight + 50;
      if (isProcessing || isScrolledToBottom) {
        terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [history, isProcessing]);

  // Smart scroll for Server Logs
  useEffect(() => {
    const element = logsScrollRef.current;
    if (element) {
      const isScrolledToBottom = 
        element.scrollHeight - element.scrollTop <= element.clientHeight + 50;
      if (isScrolledToBottom) {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [serverHistory]);
  
  // Focus input on mount/tab change
  useEffect(() => {
    if (currentTab === 'attacker-console') {
      inputRef.current?.focus();
    }
  }, [currentTab]);

  // --- COMMAND INPUT LOGIC ---

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!currentCommand.trim() || isProcessing) return;
    
    updateCommandHistory(currentCommand); // Update history here
    onCommandSubmit(currentCommand);
    setCurrentCommand('');
  };

  const handleTerminalClick = () => {
    inputRef.current?.focus();
  };
  
  // NEW: Handle Arrow Key navigation for Command History
  const handleKeyDown = (e) => {
    // Intercept Tab key for machine switching (keeps old functionality)
    if (e.key === 'Tab') {
      e.preventDefault();
      const machines = ['attacker', 'internal', 'dc'];
      const currentIndex = machines.indexOf(activeMachine);
      const nextIndex = (currentIndex + 1) % machines.length;
      onMachineChange(machines[nextIndex]);
      return;
    }

    // Command History Navigation (only for attacker machine)
    if (activeMachine !== 'attacker' || isProcessing) return;
    
    let newIndex = historyIndex;
    let command = '';

    if (e.key === 'ArrowUp') {
        e.preventDefault();
        newIndex = Math.max(0, historyIndex - 1);
        command = commandHistory[newIndex] || '';
    } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        newIndex = Math.min(commandHistory.length, historyIndex + 1);
        
        if (newIndex === commandHistory.length) {
            // If moving past the last entry, clear command (new input line)
            command = '';
        } else {
            command = commandHistory[newIndex];
        }
    } else {
        // If user starts typing a new command, reset the index to the end
        if (historyIndex < commandHistory.length) {
            setHistoryIndex(commandHistory.length);
        }
        return;
    }

    setHistoryIndex(newIndex);
    setCurrentCommand(command);
  };
  
  // When user clicks the main "Logs" tab, update the active machine
  const handleTabChange = (value) => {
      if (value === 'attacker-console') {
          onMachineChange('attacker');
      } else {
          // If switching to logs tab, keep the last viewed log machine active
          onMachineChange(logMachine);
      }
  };

  // When user clicks a sub-tab (e.g., DC), update both log view and active machine
  const handleLogMachineChange = (machine) => {
    setLogMachine(machine);
    onMachineChange(machine);
  };

  // --- DATA MAPPING ---

  const getMachineInfo = (machine) => {
    switch (machine) {
      case 'internal':
        return {
          hostname: network.target.hostname,
          ip: network.target.ip,
          role: 'Internal Server',
          logs: serverHistory
        };
      case 'dc':
        return {
          hostname: 'DC01.contoso.local',
          ip: '10.0.1.10',
          role: 'Domain Controller',
          logs: serverHistory
        };
      default:
        return {
          hostname: network.attacker.hostname,
          ip: network.attacker.ip,
          role: 'Attacker Machine',
          logs: history
        };
    }
  };

  // --- RENDERING SUB-COMPONENTS ---
  
  const renderLogOutput = (logEntries) => (
    <div className="server-output">
      {logEntries.map((entry, index) => (
        <div key={index} className={`server-line ${entry.type}`}>
          <span className="server-text">{entry.text}</span>
        </div>
      ))}
      <div ref={logsEndRef} />
    </div>
  );

  const renderTerminalConsole = () => {
    const attackerInfo = getMachineInfo('attacker');
    
    return (
      <div className="terminal-output" ref={terminalScrollRef}>
        {attackerInfo.logs.map((entry, index) => (
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
              onKeyDown={handleKeyDown} // ATTACHED ARROW KEY HANDLER
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
        <div ref={terminalEndRef} />
      </div>
    );
  };
  
  const currentLogInfo = getMachineInfo(logMachine);
  const activeIp = (currentTab === 'attacker-console' || activeMachine === 'attacker') 
    ? network.attacker.ip 
    : currentLogInfo.ip;

  return (
    <div className="panel attacker-panel">
      <Tabs 
        defaultValue="attacker-console" 
        className="h-full w-full flex flex-col" 
        value={currentTab} 
        onValueChange={handleTabChange}
      >
        
        {/* Panel Header/TabsList - Always visible */}
        <div className="panel-header">
          <Terminal size={20} />
          <h2>Machine Terminal</h2>
          <TabsList className="ml-4">
            <TabsTrigger value="attacker-console">
                <Terminal size={16} /> Attacker
            </TabsTrigger>
            <TabsTrigger value="logs-view">
                <Server size={16} /> Logs
            </TabsTrigger>
          </TabsList>
          
          <span className="panel-badge ml-auto">
            {activeIp}
          </span>
          {activeMachine === 'attacker' && hintsAvailable && onShowHint && (
            <button className="hint-button" onClick={onShowHint} title="Get a hint for the current step">
              Hint
            </button>
          )}
        </div>
        
        <div 
          className="panel-content terminal-content" 
          onClick={handleTerminalClick}
        >
          {/* TAB CONTENT: Attacker Terminal */}
          <TabsContent value="attacker-console" className="p-0 h-full">
            {renderTerminalConsole()}
          </TabsContent>
          
          {/* TAB CONTENT: Logs Viewer (Internal Server & DC) */}
          <TabsContent value="logs-view" className="p-0 h-full flex flex-col">
            
            {/* Machine Tabs/Selector for Logs View */}
            <div className="machine-tabs bg-transparent">
                <button 
                  className={cn("machine-tab", logMachine === 'internal' && 'active')}
                  onClick={() => handleLogMachineChange('internal')}
                  title="View Internal Server Logs"
                >
                  <Server size={16} />
                  <span>Internal Server</span>
                </button>
                <button 
                  className={cn("machine-tab", logMachine === 'dc' && 'active')}
                  onClick={() => handleLogMachineChange('dc')}
                  title="View Domain Controller Logs"
                >
                  <Shield size={16} />
                  <span>Domain Controller</span>
                </button>
            </div>
            
            {/* Log Output */}
            <div 
              className="server-content flex-1 overflow-y-auto" 
              ref={logsScrollRef}
            >
                {renderLogOutput(currentLogInfo.logs)}
            </div>
            
          </TabsContent>
        </div>
        
      </Tabs>
    </div>
  );
}