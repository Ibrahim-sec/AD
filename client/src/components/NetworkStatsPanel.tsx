import { Activity, Zap, Shield } from 'lucide-react';

interface NetworkStatsPanelProps {
  packetsTransmitted: number;
  alertsTriggered: number;
  detectionRisk: number; // 0-100
}

export default function NetworkStatsPanel({
  packetsTransmitted,
  alertsTriggered,
  detectionRisk
}: NetworkStatsPanelProps) {
  const getRiskColor = (risk: number) => {
    if (risk < 30) return 'text-green-500';
    if (risk < 70) return 'text-yellow-500';
    return 'text-red-500';
  };

  return (
    <div className="flex gap-4 p-3 bg-[#101214] rounded-lg border border-white/5">
      <div className="flex items-center gap-2">
        <Activity className="w-4 h-4 text-cyan-400" />
        <div>
          <div className="text-xs text-white/40">Packets</div>
          <div className="text-sm font-semibold text-white">{packetsTransmitted}</div>
        </div>
      </div>
      
      <div className="flex items-center gap-2">
        <Shield className="w-4 h-4 text-blue-400" />
        <div>
          <div className="text-xs text-white/40">Alerts</div>
          <div className="text-sm font-semibold text-white">{alertsTriggered}</div>
        </div>
      </div>
      
      <div className="flex items-center gap-2">
        <Zap className={`w-4 h-4 ${getRiskColor(detectionRisk)}`} />
        <div>
          <div className="text-xs text-white/40">Detection Risk</div>
          <div className={`text-sm font-semibold ${getRiskColor(detectionRisk)}`}>
            {detectionRisk}%
          </div>
        </div>
      </div>
    </div>
  );
}
