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
  Clock,
  Book,
  Network
} from 'lucide-react';
import { hasTheoryModule, getTheoryModule } from '../data/theory/index.js';
import TheoryModal from './TheoryModal';
import { NetworkDiagram } from './diagrams';
import NodeInfoModal from './diagrams/NodeInfoModal';
import { adTopologyDiagram } from '@/data/diagrams';
import '@/styles/diagrams.css';

export default function HomePage({ scenarios, progress, appMode, setAppMode }) {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedDifficulty, setSelectedDifficulty] = useState('all');
  const [showFilters, setShowFilters] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);

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
    <div className="bg-[#0a0b0d] text-white">
      {/* Hero Section */}
      <div className="bg-gradient-to-br from-[#0a0b0d] via-[#0f1419] to-[#0a0b0d] border-b border-white/5">
        <div className="absolute inset-0 opacity-20 pointer-events-none" style={{
          backgroundImage: `
            linear-gradient(rgba(45, 156, 219, 0.05) 1px, transparent 1px),
            linear-gradient(90deg, rgba(45, 156, 219, 0.05) 1px, transparent 1px)
          `,
          backgroundSize: '50px 50px',
          height: '400px'
        }} />

        <div className="relative max-w-7xl mx-auto px-6 py-8">
          <div className="flex items-center justify-between mb-8">
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex items-center gap-3"
            >
              <div className="w-12 h-12 bg-gradient-to-br from-[#2D9CDB] to-[#1e6a8f] rounded-xl flex items-center justify-center shadow-lg shadow-[#2D9CDB]/30">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold">AD Attack Simulator</h1>
                <p className="text-white/60 text-xs">Master Active Directory Exploitation</p>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="flex gap-3"
            >
              <button
                onClick={() => setAppMode('simulator')}
                className={`px-5 py-2 rounded-lg text-sm font-semibold transition-all ${
                  appMode === 'simulator'
                    ? 'bg-[#2D9CDB] text-white shadow-lg shadow-[#2D9CDB]/30'
                    : 'bg-white/5 text-white/60 hover:bg-white/10'
                }`}
              >
                Play Scenarios
              </button>
              <Link href="/knowledge">
                <button className="px-5 py-2 rounded-lg text-sm font-semibold bg-white/5 text-white/60 hover:bg-white/10 border border-white/10 transition-all flex items-center gap-2">
                  <Book className="w-4 h-4" />
                  Knowledge Base
                </button>
              </Link>
              <Link href="/editor">
                <button className="px-5 py-2 rounded-lg text-sm font-semibold bg-white/5 text-white/60 hover:bg-white/10 border border-white/10 transition-all">
                  Scenario Editor
                </button>
              </Link>
            </motion.div>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-4 gap-3 mb-4">
            <StatCard icon={<Trophy className="w-5 h-5" />} label="Total Score" value={stats.totalScore} color="from-yellow-500 to-orange-500" />
            <StatCard icon={<Award className="w-5 h-5" />} label="Current Rank" value={stats.rank} color="from-purple-500 to-pink-500" />
            <StatCard icon={<Target className="w-5 h-5" />} label="Scenarios Completed" value={`${stats.completed}/${stats.total}`} color="from-cyan-500 to-blue-500" />
            <StatCard icon={<Star className="w-5 h-5" />} label="Achievements" value={stats.achievements} color="from-green-500 to-emerald-500" />
          </div>

          {/* Progress */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="bg-white/5 backdrop-blur-sm rounded-lg p-4 border border-white/10"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-[#2D9CDB]" />
                <span className="text-xs font-semibold">Overall Progress</span>
              </div>
              <span className="text-xl font-bold text-[#2D9CDB]">{stats.completionRate}%</span>
            </div>
            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
              <motion.div
                initial={{ width: 0 }}
                animate={{ width: `${stats.completionRate}%` }}
                transition={{ duration: 1 }}
                className="h-full bg-gradient-to-r from-[#2D9CDB] to-cyan-400"
              />
            </div>
            <p className="text-[10px] text-white/40 mt-1.5">
              {stats.total - stats.completed} scenarios remaining to become a Cyber Ninja!
            </p>
          </motion.div>
        </div>
      </div>

      {/* AD Network Topology Overview */}
      <div className="max-w-7xl mx-auto px-6 py-12">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <div className="text-center mb-6">
            <div className="flex items-center justify-center gap-3 mb-3">
              <div className="w-10 h-10 rounded-xl bg-purple-500/20 flex items-center justify-center">
                <Network className="w-5 h-5 text-purple-400" />
              </div>
              <h2 className="text-2xl font-bold text-white">
                Active Directory Network Overview
              </h2>
            </div>
            <p className="text-white/60 max-w-2xl mx-auto text-sm">
              Explore a visual representation of an enterprise AD environment. 
              <strong className="text-[#2D9CDB]"> Click any node</strong> to learn about its role, attack vectors, and defenses.
            </p>
          </div>

          <div className="bg-[#1a1d24] rounded-xl border border-white/10 overflow-hidden">
            <NetworkDiagram 
              diagramData={adTopologyDiagram}
              height="550px"
              showMiniMap={true}
              interactive={true}
              onNodeClick={(node) => setSelectedNode(node)}
            />
          </div>
        </motion.div>

        {/* Node Info Modal */}
        <NodeInfoModal
          isOpen={!!selectedNode}
          onClose={() => setSelectedNode(null)}
          node={selectedNode}
        />
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-6 py-6 pb-20">
        {/* Search & Filters */}
        <div className="mb-6">
          <div className="flex gap-3 mb-3">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-white/40" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search scenarios..."
                className="w-full pl-10 pr-4 py-2.5 bg-white/5 border border-white/10 rounded-lg text-sm text-white placeholder:text-white/40 focus:border-[#2D9CDB] focus:outline-none"
              />
            </div>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`px-5 py-2.5 rounded-lg text-sm font-medium flex items-center gap-2 ${
                showFilters ? 'bg-[#2D9CDB] text-white' : 'bg-white/5 text-white/60 hover:bg-white/10 border border-white/10'
              }`}
            >
              <Filter className="w-4 h-4" />
              Filters
            </button>
          </div>

          <AnimatePresence>
            {showFilters && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="bg-white/5 rounded-lg p-3 border border-white/10 overflow-hidden"
              >
                <div className="flex flex-wrap gap-2">
                  {['all', 'Beginner', 'Intermediate', 'Advanced', 'Expert'].map(diff => (
                    <button
                      key={diff}
                      onClick={() => setSelectedDifficulty(diff)}
                      className={`px-3 py-1.5 rounded text-xs font-medium transition-all ${
                        selectedDifficulty === diff
                          ? 'bg-[#2D9CDB] text-white'
                          : 'bg-white/5 text-white/60 hover:bg-white/10'
                      }`}
                    >
                      {diff === 'all' ? 'All' : diff}
                    </button>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Header */}
        <div className="mb-4 flex items-center gap-2">
          <Target className="w-5 h-5 text-[#2D9CDB]" />
          <h2 className="text-xl font-bold">Select Your Attack Scenario</h2>
        </div>
        <div className="text-xs text-[#2D9CDB] mb-6 font-medium">Campaign Attack Path</div>

        {/* Scenarios */}
        <div className="space-y-6">
          {Object.entries(scenariosByPhase).map(([phase, phaseScenarios]) => {
            if (phaseScenarios.length === 0) return null;
            return (
              <div key={phase}>
                <h3 className="text-base font-bold text-purple-400 mb-3">{phase}</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
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
        </div>

        {/* No Results */}
        {filteredScenarios.length === 0 && (
          <div className="text-center py-12">
            <Search className="w-12 h-12 text-white/20 mx-auto mb-3" />
            <p className="text-white/40 text-sm mb-3">No scenarios found</p>
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedDifficulty('all');
              }}
              className="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-xs"
            >
              Clear Filters
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// HELPER COMPONENTS
// ============================================================================

function StatCard({ icon, label, value, color }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: 1.02 }}
      className="bg-white/5 backdrop-blur-sm rounded-lg p-3 border border-white/10 group cursor-pointer"
    >
      <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${color} opacity-20 flex items-center justify-center mb-2`}>
        {icon}
      </div>
      <div className="text-[10px] text-white/60 mb-0.5">{label}</div>
      <div className="text-lg font-bold text-white">{value}</div>
    </motion.div>
  );
}

function ScenarioCard({ scenario, isCompleted }) {
  const [showTheoryModal, setShowTheoryModal] = useState(false);
  const hasTheory = hasTheoryModule(scenario.id);
  const theoryModule = hasTheory ? getTheoryModule(scenario.id) : null;

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
    <>
      <motion.div whileHover={{ scale: 1.02, y: -2 }}>
        <div className="relative bg-[#1a1d24] hover:bg-[#1f2229] rounded-lg p-4 border border-white/10 hover:border-[#2D9CDB]/50 transition-all h-full">
          {/* Completion Badge */}
          {isCompleted && (
            <div className="absolute top-2 right-2 w-6 h-6 bg-green-500 rounded-full flex items-center justify-center z-10">
              <CheckCircle className="w-4 h-4 text-white" />
            </div>
          )}

          {/* Theory Badge */}
          {hasTheory && (
            <button
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setShowTheoryModal(true);
              }}
              className="absolute top-2 left-2 px-2 py-1 bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/50 rounded-md flex items-center gap-1 text-xs font-semibold text-blue-400 transition-all z-10 group"
              title="Learn theory before attempting"
            >
              <Book className="w-3 h-3" />
              <span className="hidden group-hover:inline">Learn</span>
            </button>
          )}

          <Link href={`/scenario/${scenario.id}`}>
            <div className="block cursor-pointer">
              <div className="flex items-start gap-2 mb-2">
                <div className="w-8 h-8 rounded-lg bg-[#2D9CDB]/20 flex items-center justify-center flex-shrink-0">
                  <Target className="w-4 h-4 text-[#2D9CDB]" />
                </div>
                <h3 className="text-sm font-bold line-clamp-2 hover:text-[#2D9CDB] transition-colors leading-tight">
                  {scenario.title}
                </h3>
              </div>
              <p className="text-[11px] text-white/60 mb-3 line-clamp-2 leading-relaxed">{scenario.description}</p>
              <div className="flex items-center justify-between">
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getDifficultyColor(scenario.difficulty)}`}>
                  {scenario.difficulty}
                </span>
                <div className="flex items-center gap-1 text-[10px] text-white/40">
                  <Clock className="w-3 h-3" />
                  <span>Steps: {scenario.steps?.length || 0}</span>
                </div>
              </div>
            </div>
          </Link>
        </div>
      </motion.div>

      {/* Theory Modal */}
      {showTheoryModal && theoryModule && (
        <TheoryModal
          isOpen={showTheoryModal}
          onClose={() => setShowTheoryModal(false)}
          module={theoryModule}
          onComplete={() => {
            setShowTheoryModal(false);
            // Optional: Track theory completion in progress
          }}
        />
      )}
    </>
  );
}
