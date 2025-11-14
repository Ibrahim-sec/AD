// client/src/components/HomePage.jsx

import { useState, useMemo } from 'react';
import { Link } from 'wouter';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Target,
  Shield,
  Zap,
  Trophy,
  CheckCircle,
  Lock,
  Unlock,
  ChevronRight,
  Filter,
  Search,
  Star,
  TrendingUp,
  Award,
  Clock,
  Activity,
  Users,
  Code,
  Cpu,
  Database,
  Network,
  Globe
} from 'lucide-react';

export default function HomePage({ scenarios, progress, appMode, setAppMode }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [selectedPhase, setSelectedPhase] = useState('all');
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
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesSearch = 
          scenario.title.toLowerCase().includes(query) ||
          scenario.description.toLowerCase().includes(query) ||
          scenario.id.toLowerCase().includes(query);
        
        if (!matchesSearch) return false;
      }

      // Difficulty filter
      if (selectedDifficulty !== 'all' && scenario.difficulty !== selectedDifficulty) {
        return false;
      }

      // Phase filter (simplified - you can enhance this)
      if (selectedPhase !== 'all') {
        // Map scenarios to phases based on their type
        const phaseMap = {
          reconnaissance: ['nmap-recon'],
          'initial-access': ['asrep-roasting', 'password-spraying', 'llmnr-poisoning', 'bruteforce-lockout', 'ntlm-relay'],
          'credential-access': ['gpp-passwords', 'kerberoasting', 'credential-dumping-advanced'],
          discovery: ['bloodhound'],
          'lateral-movement': ['pass-the-hash'],
          'privilege-escalation': ['gpo-abuse', 'adcs-esc1', 'rbcd-attack'],
          'domain-dominance': ['dcsync', 'golden-ticket', 'trust-abuse']
        };

        if (!phaseMap[selectedPhase]?.includes(scenario.id)) {
          return false;
        }
      }

      return true;
    });
  }, [scenarios, searchQuery, selectedDifficulty, selectedPhase]);

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
    <div className="min-h-screen bg-[#0a0b0d] text-white">
      {/* Hero Section */}
      <div className="relative overflow-hidden bg-gradient-to-br from-[#0a0b0d] via-[#0f1419] to-[#0a0b0d] border-b border-white/5">
        {/* Animated Background */}
        <div className="absolute inset-0 opacity-30">
          <div className="absolute inset-0" style={{
            backgroundImage: `
              linear-gradient(rgba(45, 156, 219, 0.05) 1px, transparent 1px),
              linear-gradient(90deg, rgba(45, 156, 219, 0.05) 1px, transparent 1px)
            `,
            backgroundSize: '50px 50px'
          }} />
        </div>

        <div className="relative max-w-7xl mx-auto px-6 py-12">
          {/* Header */}
          <div className="flex items-center justify-between mb-12">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center gap-4"
            >
              <div className="w-16 h-16 bg-gradient-to-br from-[#2D9CDB] to-[#1e6a8f] rounded-2xl flex items-center justify-center shadow-lg shadow-[#2D9CDB]/30">
                <Shield className="w-8 h-8 text-white" />
              </div>
              <div>
                <h1 className="text-3xl font-bold bg-gradient-to-r from-white to-white/60 bg-clip-text text-transparent">
                  AD Attack Simulator
                </h1>
                <p className="text-white/60 text-sm">Master Active Directory Exploitation</p>
              </div>
            </motion.div>

            {/* Mode Toggle */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex gap-3"
            >
              <button
                onClick={() => setAppMode('simulator')}
                className={`px-6 py-3 rounded-xl font-semibold transition-all ${
                  appMode === 'simulator'
                    ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/30'
                    : 'bg-white/5 text-white/60 hover:bg-white/10 hover:text-white'
                }`}
              >
                Play Scenarios
              </button>
              <Link href="/editor">
                <button
                  className="px-6 py-3 rounded-xl font-semibold bg-white/5 text-white/60 hover:bg-white/10 hover:text-white border border-white/10 transition-all"
                >
                  Scenario Editor
                </button>
              </Link>
            </motion.div>
          </div>

          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard
              icon={<Trophy className="w-6 h-6" />}
              label="Total Score"
              value={stats.totalScore}
              color="from-yellow-500 to-orange-500"
              delay={0.1}
            />
            <StatCard
              icon={<Award className="w-6 h-6" />}
              label="Current Rank"
              value={stats.rank}
              color="from-purple-500 to-pink-500"
              delay={0.2}
            />
            <StatCard
              icon={<Target className="w-6 h-6" />}
              label="Scenarios Completed"
              value={`${stats.completed}/${stats.total}`}
              color="from-cyan-500 to-blue-500"
              delay={0.3}
            />
            <StatCard
              icon={<Star className="w-6 h-6" />}
              label="Achievements"
              value={stats.achievements}
              color="from-green-500 to-emerald-500"
              delay={0.4}
            />
          </div>

          {/* Progress Bar */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/10"
          >
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-[#2D9CDB]" />
                <span className="text-sm font-semibold text-white">Overall Progress</span>
              </div>
              <span className="text-2xl font-bold text-[#2D9CDB]">{stats.completionRate}%</span>
            </div>
            <div className="h-3 bg-white/5 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${stats.completionRate}%` }}
                transition={{ duration: 1, delay: 0.6 }}
                className="h-full bg-gradient-to-r from-[#2D9CDB] via-cyan-400 to-[#2D9CDB] relative"
              >
                <motion.div
                  className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent"
                  animate={{ x: ['-100%', '200%'] }}
                  transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                />
              </motion.div>
            </div>
            <p className="text-xs text-white/40 mt-2">
              {stats.total - stats.completed} scenarios remaining to become a Cyber Ninja!
            </p>
          </motion.div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        {/* Search and Filters */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.7 }}
          className="mb-8"
        >
          <div className="flex flex-col md:flex-row gap-4 mb-4">
            {/* Search */}
            <div className="flex-1 relative">
              <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-white/40" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scenarios..."
                className="w-full pl-12 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder:text-white/40 focus:border-[#2D9CDB] focus:outline-none transition-all"
              />
            </div>

            {/* Filter Toggle */}
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`px-6 py-3 rounded-xl font-medium transition-all flex items-center gap-2 ${
                showFilters
                  ? 'bg-[#2D9CDB] text-white'
                  : 'bg-white/5 text-white/60 hover:bg-white/10 hover:text-white border border-white/10'
              }`}
            >
              <Filter className="w-5 h-5" />
              Filters
            </button>
          </div>

          {/* Filter Options */}
          <AnimatePresence>
            {showFilters && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="bg-white/5 backdrop-blur-sm rounded-xl p-4 border border-white/10">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Difficulty Filter */}
                    <div>
                      <label className="text-xs text-white/60 mb-2 block">Difficulty</label>
                      <div className="flex gap-2">
                        {['all', 'Beginner', 'Intermediate', 'Advanced', 'Expert'].map(diff => (
                          <button
                            key={diff}
                            onClick={() => setSelectedDifficulty(diff)}
                            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                              selectedDifficulty === diff
                                ? 'bg-[#2D9CDB] text-white'
                                : 'bg-white/5 text-white/60 hover:bg-white/10 hover:text-white'
                            }`}
                          >
                            {diff === 'all' ? 'All' : diff}
                          </button>
                        ))}
                      </div>
                    </div>

                    {/* Phase Filter */}
                    <div>
                      <label className="text-xs text-white/60 mb-2 block">Attack Phase</label>
                      <select
                        value={selectedPhase}
                        onChange={(e) => setSelectedPhase(e.target.value)}
                        className="w-full px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-white focus:border-[#2D9CDB] focus:outline-none"
                      >
                        <option value="all">All Phases</option>
                        <option value="reconnaissance">Reconnaissance</option>
                        <option value="initial-access">Initial Access</option>
                        <option value="credential-access">Credential Access</option>
                        <option value="discovery">Discovery</option>
                        <option value="lateral-movement">Lateral Movement</option>
                        <option value="privilege-escalation">Privilege Escalation</option>
                        <option value="domain-dominance">Domain Dominance</option>
                      </select>
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Campaign Attack Path Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.8 }}
          className="mb-6 flex items-center gap-3"
        >
          <Target className="w-6 h-6 text-[#2D9CDB]" />
          <h2 className="text-2xl font-bold text-white">Select Your Attack Scenario</h2>
        </motion.div>

        <div className="text-sm text-[#2D9CDB] mb-8 font-medium">Campaign Attack Path</div>

        {/* Scenarios by Phase */}
        <div className="space-y-8">
          {Object.entries(scenariosByPhase).map(([phase, phaseScenarios], phaseIndex) => {
            if (phaseScenarios.length === 0) return null;

            return (
              <motion.div
                key={phase}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.9 + phaseIndex * 0.1 }}
              >
                <h3 className="text-lg font-bold text-purple-400 mb-4">{phase}</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {phaseScenarios.map((scenario, index) => (
                    <ScenarioCard
                      key={scenario.id}
                      scenario={scenario}
                      isCompleted={progress?.scenariosCompleted?.includes(scenario.id)}
                      delay={0.1 * index}
                    />
                  ))}
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* No Results */}
        {filteredScenarios.length === 0 && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="text-center py-16"
          >
            <Search className="w-16 h-16 text-white/20 mx-auto mb-4" />
            <p className="text-white/40">No scenarios found matching your filters</p>
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedDifficulty('all');
                setSelectedPhase('all');
              }}
              className="mt-4 px-6 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-sm transition-all"
            >
              Clear Filters
            </button>
          </motion.div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// HELPER COMPONENTS
// ============================================================================

function StatCard({ icon, label, value, color, delay }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      whileHover={{ scale: 1.05, y: -5 }}
      className="relative bg-white/5 backdrop-blur-sm rounded-xl p-6 border border-white/10 overflow-hidden group cursor-pointer"
    >
      {/* Gradient Background */}
      <div className={`absolute inset-0 bg-gradient-to-br ${color} opacity-0 group-hover:opacity-10 transition-opacity duration-300`} />
      
      <div className="relative">
        <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} opacity-20 flex items-center justify-center mb-3`}>
          <div className="text-white">{icon}</div>
        </div>
        <div className="text-xs text-white/60 mb-1">{label}</div>
        <div className="text-2xl font-bold text-white">{value}</div>
      </div>
    </motion.div>
  );
}

function ScenarioCard({ scenario, isCompleted, delay }) {
  const getDifficultyColor = (difficulty) => {
    switch (difficulty) {
      case 'Beginner': return 'bg-green-500/20 text-green-400 border-green-500/30';
      case 'Intermediate': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'Advanced': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'Expert': return 'bg-purple-500/20 text-purple-400 border-purple-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay }}
      whileHover={{ scale: 1.03, y: -5 }}
    >
      <Link href={`/scenario/${scenario.id}`}>
        <a className="block group">
          <div className="relative bg-[#1a1d24] hover:bg-[#1f2229] rounded-xl p-5 border border-white/10 hover:border-[#2D9CDB]/50 transition-all h-full overflow-hidden">
            {/* Completion Badge */}
            {isCompleted && (
              <motion.div
                initial={{ scale: 0, rotate: -180 }}
                animate={{ scale: 1, rotate: 0 }}
                className="absolute top-3 right-3 w-8 h-8 bg-green-500 rounded-full flex items-center justify-center shadow-lg shadow-green-500/50"
              >
                <CheckCircle className="w-5 h-5 text-white" />
              </motion.div>
            )}

            {/* Header */}
            <div className="flex items-start gap-3 mb-3">
              <div className="w-10 h-10 rounded-lg bg-[#2D9CDB]/20 flex items-center justify-center flex-shrink-0 group-hover:bg-[#2D9CDB]/30 transition-colors">
                <Target className="w-5 h-5 text-[#2D9CDB]" />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-base font-bold text-white mb-1 line-clamp-2 group-hover:text-[#2D9CDB] transition-colors">
                  {scenario.title}
                </h3>
              </div>
            </div>

            {/* Description */}
            <p className="text-xs text-white/60 leading-relaxed mb-4 line-clamp-3">
              {scenario.description}
            </p>

            {/* Footer */}
            <div className="flex items-center justify-between">
              <span className={`px-2 py-1 rounded text-xs font-semibold border ${getDifficultyColor(scenario.difficulty)}`}>
                {scenario.difficulty}
              </span>
              
              <div className="flex items-center gap-2 text-xs text-white/40">
                <Clock className="w-3 h-3" />
                <span>Steps: {scenario.steps?.length || 0}</span>
              </div>
            </div>

            {/* Hover Arrow */}
            <div className="absolute bottom-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity">
              <ChevronRight className="w-5 h-5 text-[#2D9CDB]" />
            </div>
          </div>
        </a>
      </Link>
    </motion.div>
  );
}
