import { useState, useRef, useEffect, useCallback } from 'react';
// [1] IMPORT NEW ICONS
import { Terminal, Server, Shield, Lock, Key, ChevronDown, FolderArchive, FileText } from 'lucide-react'; 
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { cn } from "@/lib/utils";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible';

export default function AttackerPanel({ 
  history, 
  onCommandSubmit, 
  isProcessing, 
  network,
  activeMachine,
  onMachineChange,
  serverHistory,
  onShowHint,
  hintsAvailable = false,
  defenseHistory = [], // Defense logs
  credentialInventory = [], // Credential list
  simulatedFiles = [] // NEW: Files list
}) {
  const [currentCommand, setCurrentCommand] = useState('');
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(0);
  
  // Refs for Scrollable Areas (used for Smart Scrolling)
  const terminalScrollRef = useRef(null);
  const terminalEndRef = useRef(null);
  const logsScrollRef = useRef(null);
  const logsEndRef = useRef(null);
  const defenseScrollRef = useRef(null);
  const defenseEndRef = useRef(null);
  const lootScrollRef = useRef(null); // NEW: Ref for loot tab
  const lootEndRef = useRef(null); // NEW: Ref for loot tab
  const inputRef = useRef(null);

  const currentTab = activeMachine === 'attacker' 
    ? 'attacker-console' 
    : activeMachine === 'defense' 
      ? 'defense-view' 
      : activeMachine === 'loot'
        ? 'loot-view'
        : 'logs-view';
  
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
            return [...prev, trimmedCommand];
        });
        setHistoryIndex(prev => prev + 1);
    }
  }, []);

  // --- SMART SCROLL LOGIC ---
  
  const createSmartScrollEffect = (scrollRef, endRef, dependencyArray) => {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    useEffect(() => {
        const element = scrollRef.current;
        if (element) {
            // Check if the user is already scrolled near the bottom (within 50px threshold)
            const isScrolledToBottom = 
                element.scrollHeight - element.scrollTop <= element.clientHeight + 50;
            
            // Only auto-scroll if actively processing OR if user is near the bottom
            if (isProcessing || isScrolledToBottom) {
                endRef.current?.scrollIntoView({ behavior: 'smooth' });
            }
        }
    }, dependencyArray);
  };

  // Apply smart scroll to all views
  createSmartScrollEffect(terminalScrollRef, terminalEndRef, [history, isProcessing]);
  createSmartScrollEffect(logsScrollRef, logsEndRef, [serverHistory]);
  createSmartScrollEffect(defenseScrollRef, defenseEndRef, [defenseHistory]);
  createSmartScrollEffect(lootScrollRef, lootEndRef, [simulatedFiles, credentialInventory]); // NEW

  // Focus input on mount/tab change
  useEffect(() => {
    if (currentTab === 'attacker-console') {
      inputRef.current?.focus();
    }
  }, [currentTab]);

  // --- COMMAND INPUT / HISTORY LOGIC ---

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!currentCommand.trim() || isProcessing) return;
    
    updateCommandHistory(currentCommand);
    onCommandSubmit(currentCommand);
    setCurrentCommand('');
  };

  const handleTerminalClick = () => {
    inputRef.current?.focus();
  };
  
  // Handle Arrow Key navigation for Command History
  const handleKeyDown = (e) => {
    if (e.key === 'Tab') {
      e.preventDefault();
      // NEW: Added 'loot' to tab cycle
      const machines = ['attacker', 'internal', 'dc', 'defense', 'loot']; 
      const currentIndex = machines.indexOf(activeMachine);
      const nextIndex = (currentIndex + 1) % machines.length;
      onMachineChange(machines[nextIndex]);
      return;
    }

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
            command = '';
        } else {
            command = commandHistory[newIndex];
        }
    } else {
        if (historyIndex < commandHistory.length) {
            setHistoryIndex(commandHistory.length);
        }
        return;
    }

    setHistoryIndex(newIndex);
    setCurrentCommand(command);
  };
  
  // NEW: Updated tab change handler
  const handleTabChange = (value) => {
      if (value === 'attacker-console') {
          onMachineChange('attacker');
      } else if (value === 'defense-view') {
          onMachineChange('defense');
      } else if (value === 'loot-view') {
          onMachineChange('loot');
      } else {
          onMachineChange(logMachine);
      }
  };

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
      case 'defense':
        return {
          hostname: 'DEFENSE-GRID',
          ip: '0.0.0.0',
          role: 'Blue Team Console',
          logs: defenseHistory
        };
      case 'loot': // NEW
        return {
            hostname: 'LOOT-INVENTORY',
            ip: '127.0.0.1',
            role: 'Collected Assets',
            logs: []
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
  
  const renderDefenseOutput = () => (
    <div className="server-output defense-output">
      <h3 className="defense-title">Active Indicators of Compromise (IOCs)</h3>
      {defenseHistory.map((entry, index) => (
        <div key={index} className={`server-line ${entry.type}`}>
          <span className="server-text">{entry.text}</span>
        </div>
      ))}
      <div ref={defenseEndRef} />
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
        <div ref={terminalEndRef} />
      </div>
    );
  };
  
  const currentLogInfo = getMachineInfo(logMachine);
  // NEW: Updated IP logic
  const activeIp = currentTab === 'attacker-console' 
    ? network.attacker.ip 
    : currentTab === 'defense-view'
      ? getMachineInfo('defense').ip
      : currentTab === 'loot-view'
        ? getMachineInfo('loot').ip
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
            <TabsTrigger value="defense-view">
                <Lock size={16} /> Defense
            </TabsTrigger>
            {/* [2] NEW TAB TRIGGER */}
            <TabsTrigger value="loot-view">
                <FolderArchive size={16} /> Files
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
          {/* TAB CONTENT 1: Attacker Terminal */}
          <TabsContent value="attacker-console" className="p-0 h-full flex flex-col">
            <div className="flex-1 overflow-y-auto min-h-0" ref={terminalScrollRef}>
                {renderTerminalConsole()}
            </div>
            
            {/* [4] REMOVED Collapsible Credential Inventory from here */}

          </TabsContent>
          
          {/* TAB CONTENT 2: Logs Viewer (Internal Server & DC) */}
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

          {/* TAB CONTENT 3: Defense / Mitigation Panel */}
          <TabsContent value="defense-view" className="p-0 h-full flex flex-col">
            <div 
                className="server-content flex-1 overflow-y-auto defense-content" 
                ref={defenseScrollRef}
            >
                {renderDefenseOutput()}
            </div>
          </TabsContent>

          {/* [3] NEW TAB CONTENT FOR LOOT */}
          <TabsContent value="loot-view" className="p-0 h-full flex flex-col">
            <div 
              className="server-content flex-1 overflow-y-auto p-4" 
              ref={lootScrollRef}
            >
              <h3 className="guide-section-title">Collected Files</h3>
              {simulatedFiles.length === 0 ? (
                <p className="text-server-text text-sm">No files collected yet.</p>
              ) : (
                <div className="bg-terminal-bg border border-border-color rounded-md overflow-hidden">
                  {simulatedFiles.map(file => (
                    <div key={file.id} className="p-3 border-b border-border-color last:border-b-0 text-sm flex items-center gap-3">
                      <FileText size={16} className="text-accent-color" />
                      <span className="font-bold text-terminal-text">{file.name}</span>
                      <span className="text-server-text ml-auto">({file.size})</span>
                    </div>
                  ))}
                </div>
              )}

              <h3 className="guide-section-title mt-6">Compromised Credentials</h3>
              {credentialInventory.length === 0 ? (
                <p className="text-server-text text-sm">No credentials harvested yet.</p>
              ) : (
                <div className="bg-terminal-bg border border-border-color rounded-md overflow-hidden">
                  {credentialInventory.map(cred => (
                    <div key={cred.id} className="p-3 border-b border-border-color last:border-b-0 text-sm">
                        <span className="font-bold text-terminal-text">{cred.username}</span> 
                        <span className="text-server-text"> ({cred.type})</span>: 
                        <code className="text-terminal-green break-all ml-2">{cred.secret}</code>
                    </div>
                  ))}
                </div>
              )}
              <div ref={lootEndRef} />
            </div>
          </TabsContent>

        </div>
        
      </Tabs>
    </div>
  );
}