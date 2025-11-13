import { useState, useRef, useEffect } from 'react';
import { Terminal, Server, Shield } from 'lucide-react';
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils"; // Assuming you have cn utility

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
  const terminalEndRef = useRef(null);
  const scrollContainerRef = useRef(null);
  const inputRef = useRef(null);

  // Determine the primary view to display in the main panel
  const currentTab = activeMachine === 'attacker' ? 'attacker-console' : 'logs-view';
  
  // Internal state for selected machine when on the 'logs-view' tab
  const [logMachine, setLogMachine] = useState('internal');

  // Auto-scroll logic (updated to use new scrollContainerRef)
  useEffect(() => {
    const element = scrollContainerRef.current;

    if (element) {
      // Only auto-scroll if actively processing OR if user is near the bottom
      const isScrolledToBottom = 
        element.scrollHeight - element.scrollTop <= element.clientHeight + 50;

      if (isProcessing || isScrolledToBottom) {
        terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
      }
    }
  }, [history, serverHistory, isProcessing]);

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

  const getMachineInfo = (machine) => {
    switch (machine) {
      case 'internal':
        return {
          hostname: network.target.hostname,
          ip: network.target.ip,
          role: 'Internal Server',
          logs: serverHistory.filter(e => e.type !== 'system')
        };
      case 'dc':
        return {
          hostname: 'DC01.contoso.local',
          ip: '10.0.1.10',
          role: 'Domain Controller',
          // Assuming DC logs are mixed into serverHistory, we filter specifically for DC entries
          // A more robust app would have separate DC logs. For now, we reuse the history and clarify the source.
          logs: serverHistory.filter(e => e.type !== 'system') 
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
      <div ref={terminalEndRef} />
    </div>
  );

  const renderTerminalConsole = () => {
    const attackerInfo = getMachineInfo('attacker');
    
    return (
      <div className="terminal-output">
        {attackerInfo.logs.map((entry, index) => (
          <div key={index} className={`terminal-line ${entry.type}`}>
            {entry.type === 'command' && <span className="prompt-symbol">$</span>}
            <span className="terminal-text">{entry.text}</span>
          </div>
        ))}
        
        {/* Command input line */}
        {activeMachine === 'attacker' && !isProcessing && (
          <form onSubmit={handleSubmit} className="terminal-input-line">
            <span className="prompt">root@{network.attacker.hostname}:~#</span>
            <input
              ref={inputRef}
              type="text"
              value={currentCommand}
              onChange={(e) => setCurrentCommand(e.target.value)}
              // onKeyDown={handleKeyDown} - Removed here as Tab is for machine switching now done in logs
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

  return (
    <div className="panel attacker-panel">
      <Tabs defaultValue="attacker-console" className="h-full w-full flex flex-col" value={currentTab} onValueChange={(v) => onMachineChange(v === 'attacker-console' ? 'attacker' : logMachine)}>
        
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
            {currentTab === 'attacker-console' ? network.attacker.ip : currentLogInfo.ip}
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
          ref={scrollContainerRef}
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
                  onClick={() => setLogMachine('internal')}
                  title="View Internal Server Logs"
                >
                  <Server size={16} />
                  <span>Internal Server</span>
                </button>
                <button 
                  className={cn("machine-tab", logMachine === 'dc' && 'active')}
                  onClick={() => setLogMachine('dc')}
                  title="View Domain Controller Logs"
                >
                  <Shield size={16} />
                  <span>Domain Controller</span>
                </button>
            </div>
            
            {/* Log Output */}
            <div className="server-content flex-1 overflow-y-auto">
                {renderLogOutput(currentLogInfo.logs)}
            </div>
            
          </TabsContent>
        </div>
        
      </Tabs>
    </div>
  );
}