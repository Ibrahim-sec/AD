import { Lock, Unlock } from 'lucide-react';
import { achievements } from '../data/achievements.js';

export default function AchievementsPanel({ unlockedAchievements = [], newAchievements = [] }) {
  const isNewAchievement = (id) => newAchievements.includes(id);

  return (
    <div className="achievements-panel">
      <div className="achievements-header">
        <h2>🏆 Achievements</h2>
        <span className="achievements-count">
          {unlockedAchievements.length} / {achievements.length}
        </span>
      </div>

      <div className="achievements-grid">
        {achievements.map((achievement) => {
          const isUnlocked = unlockedAchievements.includes(achievement.id);
          const isNew = isNewAchievement(achievement.id);

          return (
            <div
              key={achievement.id}
              className={`achievement-card ${isUnlocked ? 'unlocked' : 'locked'} ${
                isNew ? 'new' : ''
              }`}
            >
              {isNew && <div className="new-badge">NEW!</div>}

              <div className="achievement-icon-large">
                {isUnlocked ? (
                  <>
                    <span className="achievement-emoji">{achievement.icon}</span>
                  </>
                ) : (
                  <Lock size={32} className="lock-icon" />
                )}
              </div>

              <h3 className="achievement-title">{achievement.title}</h3>
              <p className="achievement-description">{achievement.description}</p>

              <div className="achievement-points">
                {isUnlocked ? (
                  <>
                    <Unlock size={14} />
                    <span>+{achievement.points} pts</span>
                  </>
                ) : (
                  <>
                    <Lock size={14} />
                    <span>Locked</span>
                  </>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
