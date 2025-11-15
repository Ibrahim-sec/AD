// client/src/components/KnowledgeBase.jsx

import { useState } from 'react';
import { Link } from 'wouter';
import { Book, Search, Clock, Award, ArrowLeft } from 'lucide-react';
import { theoryModules } from '../data/theory/index.js';
import TheoryModal from './TheoryModal';
import { NetworkDiagram } from './diagrams';
import { kerberoastingDiagram, asrepRoastingDiagram, adTopologyDiagram } from '@/data/diagrams';
import '@/styles/diagrams.css';

export default function KnowledgeBase() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedModule, setSelectedModule] = useState(null);

  const modules = Object.values(theoryModules);
  
  const filteredModules = modules.filter(module =>
    module.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    module.subtitle?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#0a0b0d] text-white">
      {/* Header */}
      <div className="bg-gradient-to-br from-[#0a0b0d] via-[#0f1419] to-[#0a0b0d] border-b border-white/5">
        <div className="max-w-6xl mx-auto px-6 py-8">
          <Link href="/">
            <a className="flex items-center gap-2 text-white/60 hover:text-white mb-6 transition-colors">
              <ArrowLeft className="w-4 h-4" />
              Back to Home
            </a>
          </Link>

          <div className="flex items-center gap-4 mb-6">
            <div className="w-16 h-16 rounded-2xl bg-blue-500/20 flex items-center justify-center">
              <Book className="w-8 h-8 text-blue-400" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">Knowledge Base</h1>
              <p className="text-white/60">Interactive learning modules for AD attacks</p>
            </div>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-white/40" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search modules..."
              className="w-full pl-12 pr-4 py-3 bg-white/5 border border-white/10 rounded-xl text-white placeholder:text-white/40 focus:border-[#2D9CDB] focus:outline-none"
            />
          </div>
        </div>
      </div>

      {/* Modules Grid */}
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredModules.map(module => (
            <button
              key={module.id}
              onClick={() => setSelectedModule(module)}
              className="bg-[#1a1d24] hover:bg-[#1f2229] rounded-xl p-6 border border-white/10 hover:border-[#2D9CDB]/50 transition-all text-left"
            >
              <div className="flex items-start gap-3 mb-3">
                <div className="w-12 h-12 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
                  <Book className="w-6 h-6 text-blue-400" />
                </div>
                <div className="flex-1">
                  <h3 className="font-bold text-white mb-1">{module.title}</h3>
                  {module.subtitle && (
                    <p className="text-xs text-white/60">{module.subtitle}</p>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-3 text-xs text-white/60">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {module.estimatedTime}
                </span>
                <span className={`px-2 py-0.5 rounded ${
                  module.difficulty === 'Beginner' ? 'bg-green-500/20 text-green-400' :
                  module.difficulty === 'Intermediate' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-red-500/20 text-red-400'
                }`}>
                  {module.difficulty}
                </span>
              </div>

              {module.xpReward && (
                <div className="mt-3 flex items-center gap-1 text-xs text-yellow-400">
                  <Award className="w-3 h-3" />
                  +{module.xpReward} XP
                </div>
              )}
            </button>
          ))}
        </div>

        {/* Visual Diagrams Section - NEW! */}
        <div className="mt-12">
          <h2 className="text-2xl font-bold mb-6 flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-purple-500/20 flex items-center justify-center">
              <Book className="w-5 h-5 text-purple-400" />
            </div>
            Visual Attack Diagrams
          </h2>

          <div className="space-y-8">
            {/* Kerberoasting Diagram */}
            <div className="bg-[#1a1d24] rounded-xl p-6 border border-white/10">
              <h3 className="text-xl font-bold mb-2">Kerberoasting Attack Flow</h3>
              <p className="text-white/60 text-sm mb-4">
                Visual representation of how Kerberoasting exploits service account tickets to extract password hashes.
              </p>
              <NetworkDiagram 
                diagramData={kerberoastingDiagram}
                onNodeClick={(node) => console.log('Clicked:', node)}
                height="500px"
              />
            </div>

            {/* AS-REP Roasting Diagram */}
            <div className="bg-[#1a1d24] rounded-xl p-6 border border-white/10">
              <h3 className="text-xl font-bold mb-2">AS-REP Roasting Attack Flow</h3>
              <p className="text-white/60 text-sm mb-4">
                Exploiting accounts with "Do not require Kerberos preauthentication" enabled.
              </p>
              <NetworkDiagram 
                diagramData={asrepRoastingDiagram}
                height="500px"
              />
            </div>

            {/* AD Topology Diagram */}
            <div className="bg-[#1a1d24] rounded-xl p-6 border border-white/10">
              <h3 className="text-xl font-bold mb-2">Active Directory Network Topology</h3>
              <p className="text-white/60 text-sm mb-4">
                Enterprise AD environment with domain controllers, trust relationships, and network segments.
              </p>
              <NetworkDiagram 
                diagramData={adTopologyDiagram}
                showMiniMap={true}
                interactive={true}
                height="600px"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Theory Modal */}
      {selectedModule && (
        <TheoryModal
          isOpen={!!selectedModule}
          onClose={() => setSelectedModule(null)}
          module={selectedModule}
          onComplete={() => setSelectedModule(null)}
        />
      )}
    </div>
  );
}
