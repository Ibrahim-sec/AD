// client/src/components/SettingsModal.jsx

import { useState } from 'react';
import { X, Palette, RotateCcw, Check, Eye, Sparkles } from 'lucide-react';

// Preset themes
const PRESET_THEMES = [
  {
    name: 'Default (Cyan)',
    accentColor: '#2D9CDB',
    terminalText: '#ffffff',
    terminalBg: '#0a0b0d'
  },
  {
    name: 'Matrix Green',
    accentColor: '#00ff41',
    terminalText: '#00ff41',
    terminalBg: '#0d0208'
  },
  {
    name: 'Cyberpunk Purple',
    accentColor: '#bd00ff',
    terminalText: '#ff00ff',
    terminalBg: '#1a0033'
  },
  {
    name: 'Hacker Red',
    accentColor: '#ff3864',
    terminalText: '#ff6b9d',
    terminalBg: '#1a0a0e'
  },
  {
    name: 'Ocean Blue',
    accentColor: '#00d4ff',
    terminalText: '#a6e3ff',
    terminalBg: '#0a1929'
  },
  {
    name: 'Amber Terminal',
    accentColor: '#ffb000',
    terminalText: '#ffd966',
    terminalBg: '#1a1100'
  },
  {
    name: 'Nord Dark',
    accentColor: '#88c0d0',
    terminalText: '#d8dee9',
    terminalBg: '#2e3440'
  },
  {
    name: 'Dracula',
    accentColor: '#bd93f9',
    terminalText: '#f8f8f2',
    terminalBg: '#282a36'
  }
];

export default function SettingsModal({ isOpen, onClose, currentTheme, onUpdateTheme }) {
  const [localTheme, setLocalTheme] = useState(currentTheme || {});
  const [showResetConfirm, setShowResetConfirm] = useState(false);
  const [appliedTheme, setAppliedTheme] = useState(null);

  if (!isOpen) return null;

  const handleColorChange = (key, value) => {
    setLocalTheme(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handlePresetSelect = (preset) => {
    setLocalTheme({
      accentColor: preset.accentColor,
      terminalText: preset.terminalText,
      terminalBg: preset.terminalBg
    });
  };

  const handleApply = () => {
    onUpdateTheme(localTheme);
    setAppliedTheme({ ...localTheme });
  };

  const handleReset = () => {
    if (!showResetConfirm) {
      setShowResetConfirm(true);
      setTimeout(() => setShowResetConfirm(false), 3000);
      return;
    }
    
    const defaultTheme = {
      accentColor: '#2D9CDB',
      terminalText: '#ffffff',
      terminalBg: '#0a0b0d'
    };
    
    setLocalTheme(defaultTheme);
    onUpdateTheme(defaultTheme);
    setAppliedTheme(defaultTheme);
    setShowResetConfirm(false);
  };

  const isModified = JSON.stringify(localTheme) !== JSON.stringify(appliedTheme || currentTheme);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
      <div className="bg-[#101214] border-2 border-[#2D9CDB]/30 rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="bg-gradient-to-r from-[#2D9CDB]/20 to-purple-500/20 px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-[#2D9CDB]/20 flex items-center justify-center">
              <Palette className="w-5 h-5 text-[#2D9CDB]" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Settings & Appearance</h2>
              <p className="text-xs text-white/50">Customize your terminal theme</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-white/10 rounded-lg transition-colors text-white/70 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Quick Presets */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Sparkles className="w-4 h-4 text-[#2D9CDB]" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Quick Themes</h3>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              {PRESET_THEMES.map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => handlePresetSelect(preset)}
                  className="group relative p-3 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-[#2D9CDB]/50 rounded-lg transition-all"
                  title={preset.name}
                >
                  <div className="flex flex-col items-center gap-2">
                    <div className="flex gap-1">
                      <div 
                        className="w-6 h-6 rounded border border-white/20"
                        style={{ backgroundColor: preset.accentColor }}
                      />
                      <div 
                        className="w-6 h-6 rounded border border-white/20"
                        style={{ backgroundColor: preset.terminalBg }}
                      />
                    </div>
                    <span className="text-[10px] text-white/70 group-hover:text-white text-center line-clamp-1">
                      {preset.name}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Custom Colors */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Palette className="w-4 h-4 text-[#2D9CDB]" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Custom Colors</h3>
            </div>

            <div className="space-y-4">
              {/* Accent Color */}
              <div>
                <label className="block text-sm font-semibold text-green-400 mb-2">
                  Accent Color
                </label>
                <div className="flex gap-3">
                  <input
                    type="color"
                    value={localTheme.accentColor || '#2D9CDB'}
                    onChange={(e) => handleColorChange('accentColor', e.target.value)}
                    className="w-16 h-12 rounded-lg border-2 border-white/20 cursor-pointer"
                  />
                  <input
                    type="text"
                    value={localTheme.accentColor || ''}
                    onChange={(e) => handleColorChange('accentColor', e.target.value)}
                    placeholder="#2D9CDB"
                    className="flex-1 px-4 py-3 bg-[#0a0b0d] border-2 border-white/20 focus:border-[#2D9CDB] rounded-lg text-white font-mono text-sm outline-none transition-colors"
                  />
                </div>
                <div 
                  className="mt-2 px-3 py-2 rounded-lg text-xs font-semibold"
                  style={{ 
                    backgroundColor: `${localTheme.accentColor || '#2D9CDB'}20`,
                    color: localTheme.accentColor || '#2D9CDB',
                    border: `1px solid ${localTheme.accentColor || '#2D9CDB'}50`
                  }}
                >
                  Preview: Buttons, highlights, and interactive elements
                </div>
              </div>

              {/* Text Color */}
              <div>
                <label className="block text-sm font-semibold text-green-400 mb-2">
                  Text Color
                </label>
                <div className="flex gap-3">
                  <input
                    type="color"
                    value={localTheme.terminalText || '#ffffff'}
                    onChange={(e) => handleColorChange('terminalText', e.target.value)}
                    className="w-16 h-12 rounded-lg border-2 border-white/20 cursor-pointer"
                  />
                  <input
                    type="text"
                    value={localTheme.terminalText || ''}
                    onChange={(e) => handleColorChange('terminalText', e.target.value)}
                    placeholder="#ffffff"
                    className="flex-1 px-4 py-3 bg-[#0a0b0d] border-2 border-white/20 focus:border-[#2D9CDB] rounded-lg text-white font-mono text-sm outline-none transition-colors"
                  />
                </div>
                <div 
                  className="mt-2 px-3 py-2 rounded-lg bg-[#0a0b0d] border border-white/10 text-xs font-mono"
                  style={{ color: localTheme.terminalText || '#ffffff' }}
                >
                  Preview: root@kali:~# echo "Terminal text preview"
                </div>
              </div>

              {/* Terminal Background */}
              <div>
                <label className="block text-sm font-semibold text-green-400 mb-2">
                  Terminal Background
                </label>
                <div className="flex gap-3">
                  <input
                    type="color"
                    value={localTheme.terminalBg || '#0a0b0d'}
                    onChange={(e) => handleColorChange('terminalBg', e.target.value)}
                    className="w-16 h-12 rounded-lg border-2 border-white/20 cursor-pointer"
                  />
                  <input
                    type="text"
                    value={localTheme.terminalBg || ''}
                    onChange={(e) => handleColorChange('terminalBg', e.target.value)}
                    placeholder="#0a0b0d"
                    className="flex-1 px-4 py-3 bg-[#0a0b0d] border-2 border-white/20 focus:border-[#2D9CDB] rounded-lg text-white font-mono text-sm outline-none transition-colors"
                  />
                </div>
                <div 
                  className="mt-2 px-4 py-3 rounded-lg border border-white/10"
                  style={{ backgroundColor: localTheme.terminalBg || '#0a0b0d' }}
                >
                  <div className="text-xs font-mono" style={{ color: localTheme.terminalText || '#ffffff' }}>
                    <div className="opacity-60">Welcome to Kali Linux</div>
                    <div className="mt-1">root@kali:~# <span className="animate-pulse">_</span></div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Live Preview Panel */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Eye className="w-4 h-4 text-[#2D9CDB]" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">Live Preview</h3>
            </div>
            <div 
              className="p-4 rounded-xl border-2"
              style={{ 
                backgroundColor: localTheme.terminalBg || '#0a0b0d',
                borderColor: `${localTheme.accentColor || '#2D9CDB'}50`
              }}
            >
              <div className="space-y-3">
                <div 
                  className="text-sm font-bold"
                  style={{ color: localTheme.accentColor || '#2D9CDB' }}
                >
                  Terminal Output Preview
                </div>
                <div 
                  className="text-xs font-mono space-y-1"
                  style={{ color: localTheme.terminalText || '#ffffff' }}
                >
                  <div className="opacity-60">[*] Starting nmap scan...</div>
                  <div className="opacity-90">PORT    STATE SERVICE</div>
                  <div className="opacity-90">22/tcp  open  ssh</div>
                  <div className="opacity-90">80/tcp  open  http</div>
                  <div className="opacity-60">[+] Scan complete!</div>
                </div>
                <button
                  className="px-4 py-2 rounded-lg font-semibold text-sm transition-all"
                  style={{
                    backgroundColor: localTheme.accentColor || '#2D9CDB',
                    color: '#ffffff'
                  }}
                >
                  Example Button
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 bg-[#0a0b0d] border-t border-white/10 flex items-center justify-between gap-3">
          <button
            onClick={handleReset}
            className={`px-4 py-2.5 rounded-lg font-semibold text-sm transition-all flex items-center gap-2 ${
              showResetConfirm
                ? 'bg-red-500 text-white'
                : 'bg-white/5 hover:bg-white/10 text-white/70 hover:text-white'
            }`}
          >
            <RotateCcw className="w-4 h-4" />
            {showResetConfirm ? 'Click again to confirm' : 'Reset to Default'}
          </button>

          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-5 py-2.5 bg-white/5 hover:bg-white/10 rounded-lg text-white/70 hover:text-white font-semibold text-sm transition-all"
            >
              Cancel
            </button>
            <button
              onClick={handleApply}
              disabled={!isModified}
              className={`px-5 py-2.5 rounded-lg font-semibold text-sm transition-all flex items-center gap-2 ${
                isModified
                  ? 'bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white'
                  : 'bg-white/5 text-white/30 cursor-not-allowed'
              }`}
            >
              <Check className="w-4 h-4" />
              Apply & Save
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
