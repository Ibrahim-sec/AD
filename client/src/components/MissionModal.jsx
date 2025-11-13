import { X, CheckCircle2, AlertCircle } from 'lucide-react';

export default function MissionModal({ 
  isOpen, 
  onClose, 
  type = 'briefing', 
  scenario, 
  stats,
  newAchievements 
}) {
  if (!isOpen) return null;

  const handleBackdropClick = (e) => {
    if (e.target === e.currentTarget) {
      onClose();
    }
  };

  return (
    <div className="modal-backdrop" onClick={handleBackdropClick}>
      <div className="modal-content mission-modal">
        <button className="modal-close" onClick={onClose}>
          <X size={24} />
        </button>

        {type === 'briefing' && scenario && (
          <div className="mission-briefing">
            <div className="mission-header">
              <h2>🎯 Mission Briefing</h2>
            </div>

            <div className="mission-section">
              <h3>Target</h3>
              <p className="mission-target">{scenario.network.domain}</p>
            </div>

            <div className="mission-section">
              <h3>Objective</h3>
              <p className="mission-objective">
                {scenario.guide.overview.split('\n')[0]}
              </p>
            </div>

            <div className="mission-section">
              <h3>Attack Flow</h3>
              <ul className="mission-flow">
                {scenario.guide.steps.map((step, idx) => (
                  <li key={idx}>
                    <span className="flow-number">{step.number}</span>
                    <span className="flow-title">{step.title}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div className="mission-section">
              <h3>Recommended Tools</h3>
              <div className="tools-list">
                {scenario.guide.steps.map((step, idx) => (
                  <div key={idx} className="tool-item">
                    <code>{step.command}</code>
                  </div>
                ))}
              </div>
            </div>

            <button className="mission-button" onClick={onClose}>
              Begin Mission
            </button>
          </div>
        )}

        {type === 'debrief' && stats && scenario && (
          <div className="mission-debrief">
            <div className="mission-header success">
              <CheckCircle2 size={32} />
              <h2>🎖️ Mission Complete!</h2>
            </div>

            <div className="debrief-stats">
              <div className="stat-item">
                <span className="stat-label">Score Earned</span>
                <span className="stat-value">{stats.scoreEarned} pts</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Steps Completed</span>
                <span className="stat-value">{stats.stepsCompleted}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Hints Used</span>
                <span className="stat-value">{stats.hintsUsed}</span>
              </div>
              <div className="stat-item">
                <span className="stat-label">Time Spent</span>
                <span className="stat-value">{stats.timeSpent}</span>
              </div>
            </div>

            <div className="mission-section">
              <h3>Key Learning Points</h3>
              <ul className="learning-points">
                <li>✓ Understand the attack methodology</li>
                <li>✓ Learn tool usage and syntax</li>
                <li>✓ Recognize attack indicators</li>
              </ul>
            </div>

            {newAchievements && newAchievements.length > 0 && (
              <div className="mission-section achievements-unlocked">
                <h3>🏆 Achievements Unlocked</h3>
                <div className="achievements-list">
                  {newAchievements.map((achievement) => (
                    <div key={achievement.id} className="achievement-item">
                      <span className="achievement-icon">{achievement.icon}</span>
                      <div className="achievement-info">
                        <span className="achievement-title">{achievement.title}</span>
                        <span className="achievement-desc">{achievement.description}</span>
                      </div>
                      <span className="achievement-points">+{achievement.points}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <button className="mission-button" onClick={onClose}>
              Continue to Quiz
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
