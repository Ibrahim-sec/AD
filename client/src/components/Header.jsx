import { Shield, Trophy, Zap, Target, Settings } from 'lucide-react';

// Helper functions moved from PlayerHUD.jsx
const getRankColor = (rank) => {
  switch (rank) {
    case 'Operator':
      return '#ff4444'; // This color is mapped via CSS variable for the new theme
    case 'Junior Red Teamer':
      return '#8b5cf6'; // Violet accent
    default:
      return '#94a3b8'; // Slate mute
  }
};

const getRankIcon = (rank) => {
  switch (rank) {
    case 'Operator':
      return '🔴';
    case 'Junior Red Teamer':
      return '🟡';
    default:
      return '⚪';
  }
};

// Added onOpenSettings prop to trigger the settings modal
export default function Header({ title, currentStep, totalSteps, score, rank, onOpenSettings }) {
  const rankColor = getRankColor(rank);
  const rankIcon = getRankIcon(rank);

  return (
    <header className="simulator-header">
      <div className="header-content">
        <div className="header-left">
          <Shield className="header-icon" size={32} />
          <div className="header-title">
            <h1>AD Attack Simulator</h1>
            <p className="header-subtitle">{title}</p>
          </div>
        </div>
        
        {/* PlayerHUD content is now integrated here */}
        <div className="header-right hud-section">
          
          {/* NEW: Settings Button */}
          {onOpenSettings && (
            <button onClick={onOpenSettings} className="btn-icon">
                <Settings size={20} className="text-server-text hover:text-terminal-text" />
            </button>
          )}

          {/* Score */}
          <div className="hud-item">
            <Trophy size={18} />
            <div className="hud-content">
              <span className="hud-label">Score</span>
              <span className="hud-value">{score}</span>
            </div>
          </div>

          {/* Rank */}
          <div className="hud-item">
            <Zap size={18} />
            <div className="hud-content">
              <span className="hud-label">Rank</span>
              <span className="hud-value" style={{ color: rankColor }}>
                {rankIcon} {rank}
              </span>
            </div>
          </div>

          {/* Progress */}
          <div className="hud-item">
            <Target size={18} />
            <div className="hud-content">
              <span className="hud-label">Progress</span>
              <span className="hud-value">{currentStep} / {totalSteps}</span>
            </div>
          </div>
        </div>
      </div>
      
      {/* The progress bar now visually matches the Step/Progress text */}
      <div className="progress-bar">
        <div 
          className="progress-fill" 
          style={{ width: `${(currentStep / totalSteps) * 100}%` }}
        />
      </div>
    </header>
  );
}