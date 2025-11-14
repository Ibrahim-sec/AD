import { useState, useEffect, useRef, useCallback } from 'react';
import { 
  Terminal, 
  Server, 
  Shield, 
  Wifi, 
  AlertTriangle,
  CheckCircle,
  XCircle,
  Zap,
  Eye,
  EyeOff,
  Download,
  FileText,
  Key,
  Package,
  Clock,
  Activity,
  HelpCircle,
  Copy,
  Trash2,
  Settings,
  Maximize2,
  Minimize2,
  Volume2,
  VolumeX
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function AttackerPanel({
  history,
  onCommandSubmit,
  isProcessing,
  network,
  activeMachine,
  onMachineChange,
  serverHistory,
  defenseHistory,
  credentialInventory,
  simulatedFiles,
  onShowHint,
  hintsAvailable,
  subShell
}) {
  const [inputValue, setInputValue] = useState('');
  const [commandHistory, setCommandHistory] = useState([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [activeTab, setActiveTab] = useState('attacker'); // attacker, target, defense, loot
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [showTimestamps, setShowTimestamps] = useState(false);
  const [fontSize, setFontSize] = useState('text-sm');
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [filterLevel, setFilterLevel] = useState('all'); // all, errors, commands, output
  const [searchTerm, setSearchTerm] = useState('');
  const [showSearch, setShowSearch] = useState(false);
  
  const terminalRef = useRef(null);
  const inputRef = useRef(null);
  const bottomRef = useRef(null);

  // Auto-scroll to bottom when history changes
  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [history, serverHistory, defenseHistory]);

  // Focus input when clicking terminal
  useEffect(() => {
    const handleTerminalClick = () => {
      inputRef.current?.focus();
    };
    
    const terminal = terminalRef.current;
    terminal?.addEventListener('click', handleTerminalClick);
    
    return () => terminal?.removeEventListener('click', handleTerminalClick);
  }, []);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e) => {
      // Ctrl/Cmd + L: Clear terminal
      if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
        e.preventDefault();
        // Add clear functionality
      }
      
      // Ctrl/Cmd + K: Focus search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        setShowSearch(prev => !prev);
      }
      
      // Ctrl/Cmd + F: Toggle fullscreen
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        setIsFullscreen(prev => !prev);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!inputValue.trim() || isProcessing) return;

    // Play sound effect
    if (soundEnabled) {
      playCommandSound();
    }

    // Add to command history
    setCommandHistory(prev => [...prev, inputValue]);
    setHistoryIndex(-1);

    onCommandSubmit(inputValue);
    setInputValue('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (commandHistory.length > 0) {
        const newIndex = historyIndex === -1 
          ? commandHistory.length - 1 
          : Math.max(0, historyIndex - 1);
        setHistoryIndex(newIndex);
        setInputValue(commandHistory[newIndex]);
      }
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (historyIndex >= 0) {
        const newIndex = historyIndex + 1;
        if (newIndex >= commandHistory.length) {
          setHistoryIndex(-1);
          setInputValue('');
        } else {
          setHistoryIndex(newIndex);
          setInputValue(commandHistory[newIndex]);
        }
      }
    } else if (e.key === 'Tab') {
      e.preventDefault();
      // Tab completion logic
      handleTabCompletion();
    }
  };

  const handleTabCompletion = () => {
    // Simple tab completion for common commands
    const commonCommands = [
      'nmap', 'impacket-GetNPUsers', 'impacket-GetUserSPNs', 
      'hashcat', 'mimikatz', 'bloodhound', 'crackmapexec',
      'ls', 'cat', 'cd', 'pwd', 'whoami', 'exit'
    ];
    
    const matches = commonCommands.filter(cmd => 
      cmd.startsWith(inputValue.toLowerCase())
    );
    
    if (matches.length === 1) {
      setInputValue(matches[0] + ' ');
    }
  };

  const playCommandSound = () => {
    // Create simple beep sound
    const audioContext = new (window.AudioContext || window.webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();
    
    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);
    
    oscillator.frequency.value = 800;
    oscillator.type = 'sine';
    
    gainNode.gain.setValueAtTime(0.1, audioContext.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.1);
    
    oscillator.start(audioContext.currentTime);
    oscillator.stop(audioContext.currentTime + 0.1);
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // Show toast notification
  };

  const filterHistory = (historyArray) => {
    if (filterLevel === 'all') return historyArray;
    return historyArray.filter(entry => {
      if (filterLevel === 'commands') return entry.type === 'command';
      if (filterLevel === 'errors') return entry.type === 'error';
      if (filterLevel === 'output') return entry.type === 'output';
      return true;
    });
  };

  const searchHistory = (historyArray) => {
    if (!searchTerm) return historyArray;
    return historyArray.filter(entry => 
      entry.text?.toLowerCase().includes(searchTerm.toLowerCase())
    );
  };

  const getPrompt = () => {
    if (subShell) {
      return `${subShell} # `;
    }
    switch (activeTab) {
      case 'attacker':
        return `root@${network.attacker.hostname}:~# `;
      case 'target':
        return `C:\\Users\\Administrator> `;
      case 'defense':
        return `[SIEM] # `;
      default:
        return '> ';
    }
  };

  const getLinePrefix = (entry) => {
    const time = showTimestamps ? `[${new Date().toLocaleTimeString()}] ` : '';
    
    switch (entry.type) {
      case 'command':
        return time;
      case 'error':
        return time + '[!] ';
      case 'success':
        return time + '[✓] ';
      case 'info':
        return time + '[*] ';
      case 'warning':
        return time + '[⚠] ';
      default:
        return time;
    }
  };

  const getLineColor = (entry) => {
    switch (entry.type) {
      case 'command':
        return 'text-[#2D9CDB]';
      case 'error':
        return 'text-red-400';
      case 'success':
        return 'text-green-400';
      case 'info':
        return 'text-cyan-400';
      case 'warning':
        return 'text-yellow-400';
      case 'system':
        return 'text-purple-400';
      default:
        return 'text-white/80';
    }
  };

  const renderHistory = () => {
    let historyToRender = history;
    
    if (activeTab === 'target') {
      historyToRender = serverHistory;
    } else if (activeTab === 'defense') {
      historyToRender = defenseHistory;
    }

    historyToRender = filterHistory(historyToRender);
    historyToRender = searchHistory(historyToRender);

    return historyToRender.map((entry, index) => (
      <motion.div
        key={index}
        initial={{ opacity: 0, x: -10 }}
        animate={{ opacity: 1, x: 0 }}
        transition={{ duration: 0.2 }}
        className={`font-mono leading-relaxed group hover:bg-white/5 px-2 py-0.5 rounded transition-colors ${getLineColor(entry)}`}
      >
        <div className="flex items-start justify-between gap-2">
          <span className="flex-1 whitespace-pre-wrap break-words">
            {getLinePrefix(entry)}
            {entry.text}
          </span>
          <button
            onClick={() => copyToClipboard(entry.text)}
            className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-white/10 rounded"
            title="Copy to clipboard"
          >
            <Copy className="w-3 h-3" />
          </button>
        </div>
      </motion.div>
    ));
  };

  return (
    <div className={`flex flex-col h-full bg-[#0a0b0d] ${isFullscreen ? 'fixed inset-0 z-50' : ''}`}>
      {/* Enhanced Header */}
      <div className="flex-shrink-0 bg-[#101214] border-b border-white/10">
        {/* Machine Tabs */}
        <div className="flex items-center justify-between px-4 pt-3 pb-2">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-[#2D9CDB]" />
            <h2 className="text-sm font-bold text-white">Machine Terminal</h2>
          </div>
          
          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            {/* Search Toggle */}
            <button
              onClick={() => setShowSearch(!showSearch)}
              className={`p-1.5 rounded transition-all ${
                showSearch ? 'bg-[#2D9CDB] text-white' : 'text-white/60 hover:text-white hover:bg-white/5'
              }`}
              title="Search (Ctrl+K)"
            >
              <Eye className="w-4 h-4" />
            </button>

            {/* Timestamp Toggle */}
            <button
              onClick={() => setShowTimestamps(!showTimestamps)}
              className={`p-1.5 rounded transition-all ${
                showTimestamps ? 'bg-[#2D9CDB] text-white' : 'text-white/60 hover:text-white hover:bg-white/5'
              }`}
              title="Show Timestamps"
            >
              <Clock className="w-4 h-4" />
            </button>

            {/* Sound Toggle */}
            <button
              onClick={() => setSoundEnabled(!soundEnabled)}
              className={`p-1.5 rounded transition-all ${
                soundEnabled ? 'text-white/60 hover:text-white' : 'text-red-400'
              } hover:bg-white/5`}
              title="Toggle Sound"
            >
              {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
            </button>

            {/* Font Size */}
            <select
              value={fontSize}
              onChange={(e) => setFontSize(e.target.value)}
              className="bg-white/5 text-white/80 text-xs px-2 py-1 rounded border border-white/10 focus:border-[#2D9CDB] focus:outline-none"
            >
              <option value="text-xs">Small</option>
              <option value="text-sm">Medium</option>
              <option value="text-base">Large</option>
            </select>

            {/* Fullscreen Toggle */}
            <button
              onClick={() => setIsFullscreen(!isFullscreen)}
              className="p-1.5 text-white/60 hover:text-white hover:bg-white/5 rounded transition-all"
              title="Fullscreen (Ctrl+F)"
            >
              {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Machine Selector Tabs */}
        <div className="flex items-center gap-2 px-4 pb-2">
          <button
            onClick={() => setActiveTab('attacker')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
              activeTab === 'attacker'
                ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/20'
                : 'bg-[#1a1b1e] text-white/60 hover:text-white hover:bg-[#1a1b1e]/80'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <div className="text-left">
              <div className="text-xs font-semibold">Attacker</div>
              <div className="text-[10px] opacity-70 font-mono">{network.attacker.ip}</div>
            </div>
          </button>

          <button
            onClick={() => setActiveTab('target')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
              activeTab === 'target'
                ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/20'
                : 'bg-[#1a1b1e] text-white/60 hover:text-white hover:bg-[#1a1b1e]/80'
            }`}
          >
            <Server className="w-4 h-4" />
            <div className="text-left">
              <div className="text-xs font-semibold">Target Server</div>
              <div className="text-[10px] opacity-70 font-mono">{network.target.ip}</div>
            </div>
          </button>

          <button
            onClick={() => setActiveTab('defense')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
              activeTab === 'defense'
                ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/20'
                : 'bg-[#1a1b1e] text-white/60 hover:text-white hover:bg-[#1a1b1e]/80'
            }`}
          >
            <Shield className="w-4 h-4" />
            <div className="text-left">
              <div className="text-xs font-semibold">Blue Team</div>
              <div className="text-[10px] opacity-70">SIEM Console</div>
            </div>
          </button>

          <button
            onClick={() => setActiveTab('loot')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all relative ${
              activeTab === 'loot'
                ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/20'
                : 'bg-[#1a1b1e] text-white/60 hover:text-white hover:bg-[#1a1b1e]/80'
            }`}
          >
            <Package className="w-4 h-4" />
            <div className="text-left">
              <div className="text-xs font-semibold">Loot</div>
              <div className="text-[10px] opacity-70">
                {credentialInventory.length + simulatedFiles.length} items
              </div>
            </div>
            {(credentialInventory.length > 0 || simulatedFiles.length > 0) && (
              <div className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full flex items-center justify-center text-[10px] font-bold">
                {credentialInventory.length + simulatedFiles.length}
              </div>
            )}
          </button>
        </div>

        {/* Search Bar */}
        <AnimatePresence>
          {showSearch && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="px-4 pb-2 overflow-hidden"
            >
              <div className="flex items-center gap-2 bg-[#1a1b1e] rounded-lg px-3 py-2 border border-white/10">
                <Eye className="w-4 h-4 text-white/40" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search terminal output..."
                  className="flex-1 bg-transparent text-sm text-white placeholder:text-white/40 focus:outline-none"
                />
                {searchTerm && (
                  <button
                    onClick={() => setSearchTerm('')}
                    className="text-white/40 hover:text-white"
                  >
                    <XCircle className="w-4 h-4" />
                  </button>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Filter Bar */}
        <div className="flex items-center gap-2 px-4 pb-3">
          <span className="text-xs text-white/40">Filter:</span>
          {['all', 'commands', 'errors', 'output'].map((filter) => (
            <button
              key={filter}
              onClick={() => setFilterLevel(filter)}
              className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                filterLevel === filter
                  ? 'bg-[#2D9CDB] text-white'
                  : 'bg-white/5 text-white/60 hover:text-white hover:bg-white/10'
              }`}
            >
              {filter.charAt(0).toUpperCase() + filter.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Terminal Content */}
      <div 
        ref={terminalRef}
        className={`flex-1 overflow-y-auto p-4 ${fontSize} font-mono scrollbar-thin scrollbar-thumb-white/10 scrollbar-track-transparent`}
        style={{
          backgroundImage: `
            linear-gradient(rgba(45, 156, 219, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(45, 156, 219, 0.03) 1px, transparent 1px)
          `,
          backgroundSize: '20px 20px'
        }}
      >
        {activeTab === 'loot' ? (
          // Loot View
          <div className="space-y-4">
            {/* Credentials Section */}
            {credentialInventory.length > 0 && (
              <div className="bg-[#101214] rounded-lg border border-white/10 p-4">
                <div className="flex items-center gap-2 mb-3">
                  <Key className="w-5 h-5 text-yellow-400" />
                  <h3 className="text-sm font-bold text-white">Harvested Credentials</h3>
                  <span className="ml-auto text-xs bg-yellow-400/20 text-yellow-400 px-2 py-1 rounded">
                    {credentialInventory.length} found
                  </span>
                </div>
                <div className="space-y-2">
                  {credentialInventory.map((cred, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="bg-[#1a1b1e] rounded p-3 border border-white/5 hover:border-yellow-400/30 transition-colors group"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-yellow-400 uppercase">
                          {cred.type}
                        </span>
                        <button
                          onClick={() => copyToClipboard(`${cred.username}:${cred.secret}`)}
                          className="opacity-0 group-hover:opacity-100 transition-opacity text-white/60 hover:text-white"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                      <div className="text-sm text-white/90 font-mono">
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-white/50">User:</span>
                          <span className="text-cyan-400">{cred.username}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-white/50">Secret:</span>
                          <span className="text-green-400 break-all">{cred.secret}</span>
                        </div>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
            )}

            {/* Files Section */}
            {simulatedFiles.length > 0 && (
              <div className="bg-[#101214] rounded-lg border border-white/10 p-4">
                <div className="flex items-center gap-2 mb-3">
                  <FileText className="w-5 h-5 text-blue-400" />
                  <h3 className="text-sm font-bold text-white">Downloaded Files</h3>
                  <span className="ml-auto text-xs bg-blue-400/20 text-blue-400 px-2 py-1 rounded">
                    {simulatedFiles.length} files
                  </span>
                </div>
                <div className="space-y-2">
                  {simulatedFiles.map((file, idx) => (
                    <motion.div
                      key={idx}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      className="bg-[#1a1b1e] rounded p-3 border border-white/5 hover:border-blue-400/30 transition-colors group"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                          <Download className="w-4 h-4 text-blue-400" />
                          <div>
                            <div className="text-sm text-white/90 font-mono">{file.name || file}</div>
                            <div className="text-xs text-white/50">Simulated download</div>
                          </div>
                        </div>
                        <button className="opacity-0 group-hover:opacity-100 transition-opacity text-white/60 hover:text-white">
                          <Eye className="w-4 h-4" />
                        </button>
                      </div>
                    </motion.div>
                  ))}
                </div>
              </div>
            )}

            {/* Empty State */}
            {credentialInventory.length === 0 && simulatedFiles.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center py-12">
                <Package className="w-16 h-16 text-white/20 mb-4" />
                <h3 className="text-lg font-bold text-white/40 mb-2">No Loot Collected Yet</h3>
                <p className="text-sm text-white/30">
                  Credentials and files you collect during the attack will appear here
                </p>
              </div>
            )}
          </div>
        ) : (
          // Terminal View
          <div className="space-y-1">
            {renderHistory()}
            <div ref={bottomRef} />
          </div>
        )}
      </div>

      {/* Command Input Area */}
      {activeTab !== 'loot' && (
        <div className="flex-shrink-0 bg-[#101214] border-t border-white/10 p-4">
          {/* Hint Button */}
          {hintsAvailable && activeTab === 'attacker' && (
            <div className="mb-2">
              <button
                onClick={onShowHint}
                className="flex items-center gap-2 px-3 py-1.5 bg-yellow-500/10 hover:bg-yellow-500/20 border border-yellow-500/30 rounded text-xs text-yellow-400 transition-all"
              >
                <HelpCircle className="w-3 h-3" />
                Show Hint
              </button>
            </div>
          )}

          {/* Command Input */}
          <form onSubmit={handleSubmit} className="flex items-center gap-2">
            <div className="flex-1 flex items-center bg-[#1a1b1e] rounded-lg border border-white/10 focus-within:border-[#2D9CDB] transition-colors overflow-hidden">
              <span className="px-3 text-[#2D9CDB] font-mono text-sm whitespace-nowrap">
                {getPrompt()}
              </span>
              <input
                ref={inputRef}
                type="text"
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={isProcessing || activeTab !== 'attacker'}
                placeholder={
                  activeTab === 'attacker' 
                    ? 'Enter command...' 
                    : 'Read-only view'
                }
                className="flex-1 bg-transparent py-3 pr-3 text-white font-mono text-sm focus:outline-none disabled:opacity-50 disabled:cursor-not-allowed"
                autoComplete="off"
                spellCheck="false"
              />
            </div>
            
            {activeTab === 'attacker' && (
              <button
                type="submit"
                disabled={isProcessing || !inputValue.trim()}
                className="px-4 py-3 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 disabled:bg-white/10 disabled:cursor-not-allowed text-white rounded-lg transition-all font-medium text-sm flex items-center gap-2"
              >
                {isProcessing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin" />
                    Processing...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    Execute
                  </>
                )}
              </button>
            )}
          </form>

          {/* Status Bar */}
          <div className="flex items-center justify-between mt-3 text-xs text-white/40">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${isProcessing ? 'bg-yellow-400 animate-pulse' : 'bg-green-400'}`} />
                <span>{isProcessing ? 'Executing' : 'Ready'}</span>
              </div>
              {subShell && (
                <div className="flex items-center gap-1">
                  <Terminal className="w-3 h-3" />
                  <span>Sub-shell: {subShell}</span>
                </div>
              )}
              <div>Lines: {history.length}</div>
            </div>
            <div className="flex items-center gap-3">
              <span>↑↓ History</span>
              <span>Tab Complete</span>
              <span>Ctrl+K Search</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
