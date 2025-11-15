// client/src/components/diagrams/NodeInfoModal.jsx

import { motion, AnimatePresence } from 'framer-motion';
import { X, Server, Monitor, Database, Shield, Network, Key, Info, AlertTriangle, CheckCircle } from 'lucide-react';

const iconMap = {
  dc: Server,
  workstation: Monitor,
  server: Database,
  attacker: Shield,
  firewall: Shield,
  network: Network,
  kdc: Key,
};

// Detailed information about each node type/role
const nodeDetailedInfo = {
  'Domain Controller': {
    description: 'The central authority in Active Directory that authenticates users and enforces security policies.',
    functions: [
      'User authentication and authorization',
      'Stores AD database (NTDS.dit)',
      'Issues Kerberos tickets (TGT/TGS)',
      'Replicates changes to other DCs',
      'Enforces Group Policy Objects (GPOs)'
    ],
    attackVectors: [
      'DCSync - Extract password hashes via replication',
      'Golden Ticket - Forge Kerberos tickets with krbtgt hash',
      'Zerologon - Exploit authentication vulnerability',
      'DCShadow - Inject malicious objects into AD'
    ],
    defenses: [
      'Implement tiered admin model',
      'Enable advanced auditing (Event ID 4662)',
      'Restrict replication permissions',
      'Use Protected Users security group'
    ],
    services: ['Active Directory Domain Services', 'DNS', 'Kerberos KDC', 'LDAP', 'SMB'],
    criticalLevel: 'CRITICAL'
  },
  'Workstation': {
    description: 'End-user computers where employees perform daily tasks. Common initial compromise targets.',
    functions: [
      'User workstations for daily operations',
      'Domain-joined machines',
      'Execute GPO policies',
      'Cache user credentials locally'
    ],
    attackVectors: [
      'Credential harvesting via Mimikatz',
      'Pass-the-Hash lateral movement',
      'LLMNR/NBT-NS poisoning',
      'Phishing and malware delivery'
    ],
    defenses: [
      'Enable Credential Guard',
      'Implement Local Admin Password Solution (LAPS)',
      'Disable LLMNR and NBT-NS',
      'Use Application Whitelisting'
    ],
    services: ['Windows Defender', 'SMB', 'RDP (if enabled)'],
    criticalLevel: 'MEDIUM'
  },
  'File Server': {
    description: 'Centralized storage for organizational files and data, often contains sensitive information.',
    functions: [
      'Centralized file storage',
      'Share access via SMB/CIFS',
      'NTFS permission enforcement',
      'Shadow copy/backup services'
    ],
    attackVectors: [
      'SMB relay attacks',
      'Privilege escalation via file permissions',
      'Data exfiltration',
      'GPP password extraction from SYSVOL'
    ],
    defenses: [
      'Enable SMB signing',
      'Audit file access (Event ID 4663)',
      'Implement least-privilege file permissions',
      'Encrypt sensitive data at rest'
    ],
    services: ['SMB/CIFS', 'DFS', 'File Server Resource Manager'],
    criticalLevel: 'HIGH'
  },
  'SQL Server': {
    description: 'Database server running Microsoft SQL Server, often used by business applications.',
    functions: [
      'Database management and storage',
      'Business application backend',
      'Data processing and reporting',
      'Linked server connections'
    ],
    attackVectors: [
      'Kerberoasting service accounts',
      'SQL injection attacks',
      'Linked server abuse',
      'xp_cmdshell command execution'
    ],
    defenses: [
      'Use strong service account passwords or gMSA',
      'Disable xp_cmdshell',
      'Implement SQL auditing',
      'Principle of least privilege for SQL logins'
    ],
    services: ['SQL Server Database Engine', 'SQL Server Agent', 'SSRS', 'SSAS'],
    criticalLevel: 'HIGH'
  },
  'Attacker': {
    description: 'External or internal threat actor attempting to compromise the Active Directory environment.',
    capabilities: [
      'Network reconnaissance (nmap, BloodHound)',
      'Credential harvesting',
      'Lateral movement',
      'Privilege escalation',
      'Persistence mechanisms'
    ],
    commonTools: [
      'Mimikatz - Credential extraction',
      'Rubeus - Kerberos attacks',
      'BloodHound - AD enumeration',
      'Impacket - Protocol exploitation',
      'CrackMapExec - Network scanning'
    ],
    attackChain: [
      '1. Reconnaissance - Map the network',
      '2. Initial Access - Phishing, credential stuffing',
      '3. Execution - Deploy malware/tools',
      '4. Persistence - Create backdoors',
      '5. Privilege Escalation - Gain admin rights',
      '6. Lateral Movement - Spread across network',
      '7. Domain Dominance - Compromise DC'
    ],
    criticalLevel: 'THREAT'
  }
};

export default function NodeInfoModal({ isOpen, onClose, node }) {
  if (!isOpen || !node) return null;

  const nodeData = node.data;
  const Icon = iconMap[nodeData?.type] || Server;
  const detailedInfo = nodeDetailedInfo[nodeData?.role] || {};

  const getCriticalityBadge = (level) => {
    const styles = {
      'CRITICAL': 'bg-red-500/20 text-red-400 border-red-500/50',
      'HIGH': 'bg-orange-500/20 text-orange-400 border-orange-500/50',
      'MEDIUM': 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
      'THREAT': 'bg-purple-500/20 text-purple-400 border-purple-500/50'
    };
    return styles[level] || styles['MEDIUM'];
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
            className="relative bg-[#101214] rounded-xl border border-white/10 shadow-2xl w-full max-w-2xl max-h-[85vh] overflow-hidden flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-white/10 bg-gradient-to-br from-[#1a1d24] to-[#101214]">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-[#2D9CDB]/20 flex items-center justify-center">
                  <Icon className="w-6 h-6 text-[#2D9CDB]" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">{nodeData?.label}</h2>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-white/60">{nodeData?.role}</span>
                    {detailedInfo.criticalLevel && (
                      <span className={`text-xs px-2 py-0.5 rounded border ${getCriticalityBadge(detailedInfo.criticalLevel)}`}>
                        {detailedInfo.criticalLevel}
                      </span>
                    )}
                  </div>
                </div>
              </div>
              
              <button
                onClick={onClose}
                className="p-2 hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-5 h-5 text-white/60" />
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {/* Basic Info */}
              <div className="grid grid-cols-2 gap-4">
                {nodeData?.ip && (
                  <div className="bg-white/5 rounded-lg p-3 border border-white/10">
                    <div className="text-xs text-white/40 mb-1">IP Address</div>
                    <div className="text-sm font-mono text-[#2D9CDB]">{nodeData.ip}</div>
                  </div>
                )}
                {nodeData?.os && (
                  <div className="bg-white/5 rounded-lg p-3 border border-white/10">
                    <div className="text-xs text-white/40 mb-1">Operating System</div>
                    <div className="text-sm text-white">{nodeData.os}</div>
                  </div>
                )}
              </div>

              {/* Description */}
              {detailedInfo.description && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <Info className="w-4 h-4 text-blue-400" />
                    <h3 className="text-sm font-bold text-white">Overview</h3>
                  </div>
                  <p className="text-sm text-white/70 leading-relaxed">
                    {detailedInfo.description}
                  </p>
                </div>
              )}

              {/* Functions */}
              {detailedInfo.functions && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <CheckCircle className="w-4 h-4 text-green-400" />
                    <h3 className="text-sm font-bold text-white">Key Functions</h3>
                  </div>
                  <ul className="space-y-2">
                    {detailedInfo.functions.map((func, idx) => (
                      <li key={idx} className="text-sm text-white/70 flex items-start gap-2">
                        <span className="text-green-400 mt-1">•</span>
                        <span>{func}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Capabilities (for Attacker) */}
              {detailedInfo.capabilities && (
                <div>
                  <div className="flex items-center gap-2 mb-3">
                    <Shield className="w-4 h-4 text-purple-400" />
                    <h3 className="text-sm font-bold text-white">Capabilities</h3>
                  </div>
                  <ul className="space-y-2">
                    {detailedInfo.capabilities.map((cap, idx) => (
                      <li key={idx} className="text-sm text-white/70 flex items-start gap-2">
                        <span className="text-purple-400 mt-1">•</span>
                        <span>{cap}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Attack Vectors */}
              {detailedInfo.attackVectors && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <h3 className="text-sm font-bold text-red-400">Common Attack Vectors</h3>
                  </div>
                  <ul className="space-y-2">
                    {detailedInfo.attackVectors.map((attack, idx) => (
                      <li key={idx} className="text-sm text-red-300/80 flex items-start gap-2">
                        <span className="text-red-400 mt-1">⚠</span>
                        <span>{attack}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Attack Chain (for Attacker) */}
              {detailedInfo.attackChain && (
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Target className="w-4 h-4 text-purple-400" />
                    <h3 className="text-sm font-bold text-purple-400">Typical Attack Chain</h3>
                  </div>
                  <div className="space-y-2">
                    {detailedInfo.attackChain.map((step, idx) => (
                      <div key={idx} className="text-sm text-purple-300/80">
                        {step}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Common Tools (for Attacker) */}
              {detailedInfo.commonTools && (
                <div>
                  <h3 className="text-sm font-bold text-white mb-3">Common Tools</h3>
                  <div className="grid grid-cols-2 gap-2">
                    {detailedInfo.commonTools.map((tool, idx) => (
                      <div key={idx} className="bg-white/5 rounded p-2 border border-white/10">
                        <div className="text-xs text-white/90 font-mono">{tool}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Defenses */}
              {detailedInfo.defenses && (
                <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <Shield className="w-4 h-4 text-green-400" />
                    <h3 className="text-sm font-bold text-green-400">Defense Strategies</h3>
                  </div>
                  <ul className="space-y-2">
                    {detailedInfo.defenses.map((defense, idx) => (
                      <li key={idx} className="text-sm text-green-300/80 flex items-start gap-2">
                        <span className="text-green-400 mt-1">✓</span>
                        <span>{defense}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Services */}
              {detailedInfo.services && (
                <div>
                  <h3 className="text-sm font-bold text-white mb-3">Running Services</h3>
                  <div className="flex flex-wrap gap-2">
                    {detailedInfo.services.map((service, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 bg-blue-500/20 text-blue-400 border border-blue-500/30 rounded text-xs"
                      >
                        {service}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-4 border-t border-white/10 bg-[#0a0b0d]">
              <button
                onClick={onClose}
                className="w-full px-4 py-2 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 rounded-lg font-semibold transition-all"
              >
                Close
              </button>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
