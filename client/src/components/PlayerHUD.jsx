import { Trophy, Zap, Target } from 'lucide-react';

export default function PlayerHUD({ score, rank, currentStep, totalSteps, scenario }) {
  const getRankColor = () => {
    switch (rank) {
      case 'Operator':
        return '#ff4444'; // Red
      case 'Junior Red Teamer':
        return '#58a6ff'; // Blue
      default:
        return '#8b949e'; // Gray
    }
  };

  const getRankIcon = () => {
    switch (rank) {
      case 'Operator':
        return '🔴';
      case 'Junior Red Teamer':
        return '🟡';
      default:
        return '⚪';
    }
  };

  return (
    <div className="player-hud">
      <div className="hud-section">
        <div className="hud-item">
          <Trophy size={18} />
          <div className="hud-content">
            <span className="hud-label">Score</span>
            <span className="hud-value">{score}</span>
          </div>
        </div>

        <div className="hud-item">
          <Zap size={18} />
          <div className="hud-content">
            <span className="hud-label">Rank</span>
            <span className="hud-value" style={{ color: getRankColor() }}>
              {getRankIcon()} {rank}
            </span>
          </div>
        </div>

        <div className="hud-item">
          <Target size={18} />
          <div className="hud-content">
            <span className="hud-label">Progress</span>
            <span className="hud-value">{currentStep} / {totalSteps}</span>
          </div>
        </div>
      </div>

      {scenario && (
        <div className="hud-scenario">
          <span className="scenario-name">{scenario.title}</span>
        </div>
      )}
    </div>
  );
}
