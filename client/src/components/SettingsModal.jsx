import { X, Palette } from 'lucide-react';
import { useState } from 'react';

// Define the customizable fields and default values
const themeOptions = [
    { key: 'accentColor', label: 'Accent Color', default: '#8b5cf6' },
    { key: 'terminalText', label: 'Text Color', default: '#f1f5f9' },
    { key: 'terminalBg', label: 'Terminal Background', default: '#0f172a' },
];

export default function SettingsModal({ isOpen, onClose, currentTheme, onUpdateTheme }) {
    if (!isOpen) return null;

    // Use internal state for editing
    const [theme, setTheme] = useState(currentTheme);

    const handleColorChange = (key, value) => {
        setTheme(prev => ({ ...prev, [key]: value }));
    };

    const handleSave = () => {
        onUpdateTheme(theme);
        onClose();
    };

    const handleReset = () => {
        const defaultTheme = themeOptions.reduce((acc, opt) => {
            acc[opt.key] = opt.default;
            return acc;
        }, {});
        onUpdateTheme(defaultTheme);
        setTheme(defaultTheme);
        onClose();
    }

    return (
        <div className="modal-backdrop" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <button className="modal-close" onClick={onClose}>
                    <X size={24} />
                </button>
                
                <div className="settings-panel">
                    <div className="settings-header">
                        <Palette size={28} />
                        <h2>Settings & Appearance</h2>
                    </div>

                    <section className="settings-section">
                        <h3>Custom Terminal Theme</h3>
                        
                        {themeOptions.map(option => (
                            <div key={option.key} className="form-group theme-input">
                                <label>{option.label}</label>
                                <input
                                    type="color"
                                    value={theme[option.key] || option.default}
                                    onChange={(e) => handleColorChange(option.key, e.target.value)}
                                />
                                <span className="color-value">{theme[option.key] || option.default}</span>
                            </div>
                        ))}
                    </section>
                    
                    <div className="settings-footer">
                        <button onClick={handleReset} className="btn-secondary btn-reset">
                            Reset to Default
                        </button>
                        <button onClick={handleSave} className="btn-primary">
                            Apply & Save
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}