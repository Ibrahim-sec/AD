import { useState, useRef, useEffect } from 'react';
import { Terminal, Server, Shield } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";

export default function AttackerPanel({ 
  history, 
  onCommandSubmit, 
  isProcessing, 
  network,
  activeMachine, // This props now represents the currently selected console (attacker, internal, dc)
  onMachineChange,
  serverHistory,
  onShowHint,
  hintsAvailable = false
}) {
  const [currentCommand, setCurrentCommand] = useState('');
  
  // Create separate refs for each scrollable area and its end-point
  const terminalScrollRef = useRef(null);
  const terminalEndRef = useRef(null);
  const logsScrollRef = useRef(null);
  const logsEndRef = useRef(null);

  const inputRef = useRef(null);

  // Determine the primary view to display in the main panel
  const currentTab = activeMachine === 'attacker' ? 'attacker-console' : 'logs-view';
  
  // Internal state for selected machine when on the 'logs-view' tab
  // Default to 'internal' when switching to logs, unless it's already 'dc'
  const [logMachine, setLogMachine] = useState(activeMachine === 'dc' ? 'dc' : 'internal');

  // FIX: Smart scroll for Attacker Terminal
  useEffect(() => {
    const element = terminalScrollRef.current;
    if (element) {
      const isScrolledToBottom = 
        element.scrollHeight - element.scrollTop <= element.clientHeight + 50;
      if (isProcessing || isScrolledToBottom) {
        terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [history, isProcessing]); // Only depends on attacker history

  // FIX: Smart scroll for Server Logs
  useEffect(() => {
    const element = logsScrollRef.current;
    if (element) {
      const isScrolledToBottom = 
        element.scrollHeight - element.scrollTop <= element.clientHeight + 50;
      // Logs only auto-scroll if user is already at the bottom
      if (isScrolledToBottom) {
        logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [serverHistory]); // Only depends on server history

  // Focus input on mount/tab change
  useEffect(() => {
    if (currentTab === 'attacker-console') {
      inputRef.current?.focus();
    }
  }, [currentTab]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!currentCommand.trim() || isProcessing) return;
    onCommandSubmit(currentCommand);
    setCurrentCommand('');
  };

  const handleTerminalClick = () => {
    inputRef.current?.focus();
  };
  
  // When user clicks the main "Logs" tab, update the active machine
  const handleTabChange = (value) => {
      if (value === 'attacker-console') {
          onMachineChange('attacker');
      } else {
          onMachineChange(logMachine);
      }
  };

  // When user clicks a sub-tab (e.g., DC), update both log view and active machine
  const handleLogMachineChange = (machine) => {
    setLogMachine(machine);
    onMachineChange(machine);
  };

  const getMachineInfo = (machine) => {
    switch (machine) {
      case 'internal':
        return {
          hostname: network.target.hostname,
          ip: network.target.ip,
          role: 'Internal Server',
          logs: serverHistory // Assuming serverHistory contains all non-attacker logs
        };
      case 'dc':
        return {
          hostname: 'DC01.contoso.local',
          ip: '10.0.1.10',
          role: 'Domain Controller',
          logs: serverHistory // Both internal and DC logs share serverHistory
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
      <div ref={logsEndRef} /> {/* Attach end ref for log scrolling */}
    </div>
  );

  const renderTerminalConsole = () => {
    const attackerInfo = getMachineInfo('attacker');
    
    return (
      <div className="terminal-output" ref={terminalScrollRef}> {/* Attach scroll ref */}
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
        <div ref={terminalEndRef} /> {/* Attach end ref for terminal scrolling */}
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
          // This ref is no longer needed as scrolling is on the children
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
              ref={logsScrollRef} /* Attach scroll ref for logs */
            >
                {renderLogOutput(currentLogInfo.logs)}
            </div>
            
          </TabsContent>
        </div>
        
      </Tabs>
    </div>
  );
}