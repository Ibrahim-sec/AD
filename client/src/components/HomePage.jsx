// client/src/components/HomePage.jsx

import { useState, useMemo } from 'react';
import { Link } from 'wouter';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Target,
  Shield,
  Trophy,
  CheckCircle,
  ChevronRight,
  Filter,
  Search,
  Star,
  TrendingUp,
  Award,
  Clock
} from 'lucide-react';

export default function HomePage({ scenarios, progress, appMode, setAppMode }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [showFilters, setShowFilters] = useState(false);

  // Calculate statistics
  const stats = useMemo(() => {
    const completed = progress?.scenariosCompleted?.length || 0;
    const total = scenarios.length;
    const completionRate = Math.round((completed / total) * 100);
    
    return {
      totalScore: progress?.totalScore || 0,
      rank: progress?.rank || 'Novice',
      completed,
      total,
      completionRate,
      achievements: progress?.unlockedAchievements?.length || 0
    };
  }, [progress, scenarios]);

  // Filter scenarios
  const filteredScenarios = useMemo(() => {
    return scenarios.filter(scenario => {
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch = 
          scenario.title.toLowerCase().includes(query) ||
          scenario.description.toLowerCase().includes(query);
        if (!matchesSearch) return false;
      }

      if (selectedDifficulty !== 'all' && scenario.difficulty !== selectedDifficulty) {
        return false;
      }

      return true;
    });
  }, [scenarios, searchQuery, selectedDifficulty]);

  // Group scenarios by phase
  const scenariosByPhase = useMemo(() => {
    const phases = {
      'Phase 1: Reconnaissance': [],
      'Phase 2: Initial Access': [],
      'Phase 3: Credential Access': [],
      'Phase 4: Discovery': [],
      'Phase 5: Lateral Movement': [],
      'Phase 6: Privilege Escalation': [],
      'Phase 7: Domain Dominance': []
    };

    filteredScenarios.forEach(scenario => {
      if (scenario.id === 'nmap-recon') {
        phases['Phase 1: Reconnaissance'].push(scenario);
      } else if (['asrep-roasting', 'password-spraying', 'llmnr-poisoning', 'bruteforce-lockout', 'ntlm-relay'].includes(scenario.id)) {
        phases['Phase 2: Initial Access'].push(scenario);
      } else if (['gpp-passwords', 'kerberoasting', 'credential-dumping-advanced'].includes(scenario.id)) {
        phases['Phase 3: Credential Access'].push(scenario);
      } else if (scenario.id === 'bloodhound') {
        phases['Phase 4: Discovery'].push(scenario);
      } else if (scenario.id === 'pass-the-hash') {
        phases['Phase 5: Lateral Movement'].push(scenario);
      } else if (['gpo-abuse', 'adcs-esc1', 'rbcd-attack'].includes(scenario.id)) {
        phases['Phase 6: Privilege Escalation'].push(scenario);
      } else {
        phases['Phase 7: Domain Dominance'].push(scenario);
      }
    });

    return phases;
  }, [filteredScenarios]);

  return (
    <div style={{ width: '100%', minHeight: '100vh', overflowY: 'auto' }} className="bg-[#0a0b0d] text-white">
      {/* Header Section */}
      <div className="bg-gradient-to-br from-[#0a0b0d] via-[#0f1419] to-[#0a0b0d] border-b border-white/5">
        <div style={{ 
          backgroundImage: `
            linear-gradient(rgba(45, 156, 219, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(45, 156, 219, 0.05) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '400px',
          opacity: 0.2,
          pointerEvents: 'none'
        }} />

        <div style={{ position: 'relative', maxWidth: '1280px', margin: '0 auto', padding: '24px' }}>
          {/* Header */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                width: '48px',
                height: '48px',
                background: 'linear-gradient(to bottom right, #2D9CDB, #1e6a8f)',
                borderRadius: '12px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                boxShadow: '0 10px 25px rgba(45, 156, 219, 0.3)'
              }}>
                <Shield style={{ width: '24px', height: '24px', color: 'white' }} />
              </div>
              <div>
                <h1 style={{ fontSize: '24px', fontWeight: 'bold', margin: 0 }}>AD Attack Simulator</h1>
                <p style={{ fontSize: '12px', color: 'rgba(255,255,255,0.6)', margin: 0 }}>Master Active Directory Exploitation</p>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={() => setAppMode('simulator')}
                style={{
                  padding: '8px 20px',
                  borderRadius: '8px',
                  fontWeight: '600',
                  fontSize: '14px',
                  border: 'none',
                  cursor: 'pointer',
                  background: appMode === 'simulator' ? '#2D9CDB' : 'rgba(255,255,255,0.05)',
                  color: appMode === 'simulator' ? 'white' : 'rgba(255,255,255,0.6)',
                  boxShadow: appMode === 'simulator' ? '0 10px 25px rgba(45, 156, 219, 0.3)' : 'none'
                }}
              >
                Play Scenarios
              </button>
              <Link href="/editor">
                <button style={{
                  padding: '8px 20px',
                  borderRadius: '8px',
                  fontWeight: '600',
                  fontSize: '14px',
                  cursor: 'pointer',
                  background: 'rgba(255,255,255,0.05)',
                  color: 'rgba(255,255,255,0.6)',
                  border: '1px solid rgba(255,255,255,0.1)'
                }}>
                  Scenario Editor
                </button>
              </Link>
            </div>
          </div>

          {/* Stats */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px', marginBottom: '16px' }}>
            <StatCard icon={<Trophy />} label="Total Score" value={stats.totalScore} />
            <StatCard icon={<Award />} label="Current Rank" value={stats.rank} />
            <StatCard icon={<Target />} label="Scenarios Completed" value={`${stats.completed}/${stats.total}`} />
            <StatCard icon={<Star />} label="Achievements" value={stats.achievements} />
          </div>

          {/* Progress */}
          <div style={{
            background: 'rgba(255,255,255,0.05)',
            backdropFilter: 'blur(10px)',
            borderRadius: '12px',
            padding: '16px',
            border: '1px solid rgba(255,255,255,0.1)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <TrendingUp style={{ width: '16px', height: '16px', color: '#2D9CDB' }} />
                <span style={{ fontSize: '12px', fontWeight: '600' }}>Overall Progress</span>
              </div>
              <span style={{ fontSize: '20px', fontWeight: 'bold', color: '#2D9CDB' }}>{stats.completionRate}%</span>
            </div>
            <div style={{ height: '8px', background: 'rgba(255,255,255,0.05)', borderRadius: '999px', overflow: 'hidden' }}>
              <div style={{
                height: '100%',
                width: `${stats.completionRate}%`,
                background: 'linear-gradient(to right, #2D9CDB, #22d3ee)',
                transition: 'width 1s'
              }} />
            </div>
            <p style={{ fontSize: '10px', color: 'rgba(255,255,255,0.4)', margin: '4px 0 0 0' }}>
              {stats.total - stats.completed} scenarios remaining to become a Cyber Ninja!
            </p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div style={{ maxWidth: '1280px', margin: '0 auto', padding: '24px' }}>
        {/* Search & Filters */}
        <div style={{ marginBottom: '24px' }}>
          <div style={{ display: 'flex', gap: '12px', marginBottom: '12px' }}>
            <div style={{ flex: 1, position: 'relative' }}>
              <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '16px', height: '16px', color: 'rgba(255,255,255,0.4)' }} />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scenarios..."
                style={{
                  width: '100%',
                  padding: '10px 12px 10px 36px',
                  background: 'rgba(255,255,255,0.05)',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: '8px',
                  color: 'white',
                  fontSize: '14px',
                  outline: 'none'
                }}
              />
            </div>
            <button
              onClick={() => setShowFilters(!showFilters)}
              style={{
                padding: '10px 20px',
                borderRadius: '8px',
                fontSize: '14px',
                fontWeight: '500',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                background: showFilters ? '#2D9CDB' : 'rgba(255,255,255,0.05)',
                color: showFilters ? 'white' : 'rgba(255,255,255,0.6)',
                border: showFilters ? 'none' : '1px solid rgba(255,255,255,0.1)'
              }}
            >
              <Filter style={{ width: '16px', height: '16px' }} />
              Filters
            </button>
          </div>

          {showFilters && (
            <div style={{
              background: 'rgba(255,255,255,0.05)',
              borderRadius: '8px',
              padding: '12px',
              border: '1px solid rgba(255,255,255,0.1)',
              display: 'flex',
              gap: '8px',
              flexWrap: 'wrap'
            }}>
              {['all', 'Beginner', 'Intermediate', 'Advanced', 'Expert'].map(diff => (
                <button
                  key={diff}
                  onClick={() => setSelectedDifficulty(diff)}
                  style={{
                    padding: '6px 12px',
                    borderRadius: '6px',
                    fontSize: '12px',
                    fontWeight: '500',
                    cursor: 'pointer',
                    background: selectedDifficulty === diff ? '#2D9CDB' : 'rgba(255,255,255,0.05)',
                    color: selectedDifficulty === diff ? 'white' : 'rgba(255,255,255,0.6)',
                    border: 'none'
                  }}
                >
                  {diff === 'all' ? 'All' : diff}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
          <Target style={{ width: '20px', height: '20px', color: '#2D9CDB' }} />
          <h2 style={{ fontSize: '20px', fontWeight: 'bold', margin: 0 }}>Select Your Attack Scenario</h2>
        </div>
        <div style={{ fontSize: '12px', color: '#2D9CDB', fontWeight: '500', marginBottom: '24px' }}>Campaign Attack Path</div>

        {/* Scenarios */}
        {Object.entries(scenariosByPhase).map(([phase, phaseScenarios]) => {
          if (phaseScenarios.length === 0) return null;
          return (
            <div key={phase} style={{ marginBottom: '32px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 'bold', color: '#a78bfa', marginBottom: '12px' }}>{phase}</h3>
              <div style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
                gap: '12px'
              }}>
                {phaseScenarios.map((scenario) => (
                  <ScenarioCard
                    key={scenario.id}
                    scenario={scenario}
                    isCompleted={progress?.scenariosCompleted?.includes(scenario.id)}
                  />
                ))}
              </div>
            </div>
          );
        })}

        {/* No Results */}
        {filteredScenarios.length === 0 && (
          <div style={{ textAlign: 'center', padding: '48px 0' }}>
            <Search style={{ width: '48px', height: '48px', color: 'rgba(255,255,255,0.2)', margin: '0 auto 12px' }} />
            <p style={{ color: 'rgba(255,255,255,0.4)', fontSize: '14px', marginBottom: '12px' }}>No scenarios found</p>
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedDifficulty('all');
              }}
              style={{
                padding: '8px 16px',
                background: 'rgba(255,255,255,0.05)',
                border: 'none',
                borderRadius: '8px',
                fontSize: '12px',
                color: 'white',
                cursor: 'pointer'
              }}
            >
              Clear Filters
            </button>
          </div>
        )}

        {/* Extra bottom padding */}
        <div style={{ height: '80px' }} />
      </div>
    </div>
  );
}

function StatCard({ icon, label, value }) {
  return (
    <div style={{
      background: 'rgba(255,255,255,0.05)',
      backdropFilter: 'blur(10px)',
      borderRadius: '12px',
      padding: '16px',
      border: '1px solid rgba(255,255,255,0.1)'
    }}>
      <div style={{ marginBottom: '8px' }}>
        {icon}
      </div>
      <div style={{ fontSize: '10px', color: 'rgba(255,255,255,0.6)', marginBottom: '4px' }}>{label}</div>
      <div style={{ fontSize: '20px', fontWeight: 'bold' }}>{value}</div>
    </div>
  );
}

function ScenarioCard({ scenario, isCompleted }) {
  const getDifficultyColor = (difficulty) => {
    switch (difficulty) {
      case 'Beginner': return { bg: 'rgba(34, 197, 94, 0.2)', text: '#22c55e', border: 'rgba(34, 197, 94, 0.3)' };
      case 'Intermediate': return { bg: 'rgba(234, 179, 8, 0.2)', text: '#eab308', border: 'rgba(234, 179, 8, 0.3)' };
      case 'Advanced': return { bg: 'rgba(239, 68, 68, 0.2)', text: '#ef4444', border: 'rgba(239, 68, 68, 0.3)' };
      case 'Expert': return { bg: 'rgba(168, 85, 247, 0.2)', text: '#a855f7', border: 'rgba(168, 85, 247, 0.3)' };
      default: return { bg: 'rgba(156, 163, 175, 0.2)', text: '#9ca3af', border: 'rgba(156, 163, 175, 0.3)' };
    }
  };

  const colors = getDifficultyColor(scenario.difficulty);

  return (
    <Link href={`/scenario/${scenario.id}`}>
      <a style={{ textDecoration: 'none', display: 'block' }}>
        <div style={{
          position: 'relative',
          background: '#1a1d24',
          borderRadius: '12px',
          padding: '16px',
          border: '1px solid rgba(255,255,255,0.1)',
          cursor: 'pointer',
          transition: 'all 0.2s',
          height: '100%'
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = '#1f2229';
          e.currentTarget.style.borderColor = 'rgba(45, 156, 219, 0.5)';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = '#1a1d24';
          e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)';
        }}>
          {isCompleted && (
            <div style={{
              position: 'absolute',
              top: '12px',
              right: '12px',
              width: '24px',
              height: '24px',
              background: '#22c55e',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center'
            }}>
              <CheckCircle style={{ width: '16px', height: '16px', color: 'white' }} />
            </div>
          )}
          <div style={{ display: 'flex', alignItems: 'start', gap: '8px', marginBottom: '8px' }}>
            <div style={{
              width: '32px',
              height: '32px',
              borderRadius: '8px',
              background: 'rgba(45, 156, 219, 0.2)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              flexShrink: 0
            }}>
              <Target style={{ width: '16px', height: '16px', color: '#2D9CDB' }} />
            </div>
            <h3 style={{
              fontSize: '14px',
              fontWeight: 'bold',
              color: 'white',
              margin: 0,
              lineHeight: '1.4',
              display: '-webkit-box',
              WebkitLineClamp: 2,
              WebkitBoxOrient: 'vertical',
              overflow: 'hidden'
            }}>
              {scenario.title}
            </h3>
          </div>
          <p style={{
            fontSize: '11px',
            color: 'rgba(255,255,255,0.6)',
            lineHeight: '1.5',
            marginBottom: '12px',
            display: '-webkit-box',
            WebkitLineClamp: 2,
            WebkitBoxOrient: 'vertical',
            overflow: 'hidden'
          }}>
            {scenario.description}
          </p>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{
              padding: '4px 8px',
              borderRadius: '4px',
              fontSize: '10px',
              fontWeight: '600',
              background: colors.bg,
              color: colors.text,
              border: `1px solid ${colors.border}`
            }}>
              {scenario.difficulty}
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '10px', color: 'rgba(255,255,255,0.4)' }}>
              <Clock style={{ width: '12px', height: '12px' }} />
              <span>Steps: {scenario.steps?.length || 0}</span>
            </div>
          </div>
        </div>
      </a>
    </Link>
  );
}
