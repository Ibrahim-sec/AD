// client/src/components/MachineInfoSheet.jsx - CREATE THIS

import { X, Server, Shield, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

export default function MachineInfoSheet({ machine, onClose }) {
  if (!machine) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      >
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 20 }}
          onClick={(e) => e.stopPropagation()}
          className="absolute right-0 top-0 h-full w-96 bg-[#101214] border-l border-white/10 shadow-2xl overflow-y-auto"
        >
          {/* Header */}
          <div className="flex items-center justify-between p-6 border-b border-white/10">
            <div className="flex items-center gap-3">
              {machine.type === 'attacker' && <Activity className="w-6 h-6 text-[#2D9CDB]" />}
              {machine.type === 'target' && <Server className="w-6 h-6 text-red-400" />}
              {machine.type === 'dc' && <Shield className="w-6 h-6 text-purple-400" />}
              <div>
                <h3 className="text-lg font-bold text-white">{machine.label}</h3>
                <p className="text-xs text-white/60">{machine.ip}</p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/5 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-white/60" />
            </button>
          </div>

          {/* Details */}
          <div className="p-6 space-y-6">
            {/* OS Info */}
            <div>
              <h4 className="text-sm font-semibold text-white/80 mb-2">Operating System</h4>
              <p className="text-sm text-white/60">{machine.details?.os || 'Unknown'}</p>
            </div>

            {/* Role */}
            <div>
              <h4 className="text-sm font-semibold text-white/80 mb-2">Role</h4>
              <p className="text-sm text-white/60">{machine.details?.role || 'Unknown'}</p>
            </div>

            {/* Services */}
            {machine.details?.services && (
              <div>
                <h4 className="text-sm font-semibold text-white/80 mb-2">Running Services</h4>
                <div className="space-y-1">
                  {machine.details.services.map((service, idx) => (
                    <div key={idx} className="text-sm text-white/60 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-400"></span>
                      {service}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Tools */}
            {machine.details?.tools && (
              <div>
                <h4 className="text-sm font-semibold text-white/80 mb-2">Installed Tools</h4>
                <div className="flex flex-wrap gap-2">
                  {machine.details.tools.map((tool, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-1 bg-[#2D9CDB]/20 text-[#2D9CDB] text-xs rounded border border-[#2D9CDB]/30"
                    >
                      {tool}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
