import { useState, useEffect } from 'react';

interface TrafficPacket {
  id: string;
  from: string;
  to: string;
  protocol: string;
  size: number;
  timestamp: number;
}

export const useNetworkTraffic = (isActive: boolean) => {
  const [packets, setPackets] = useState<TrafficPacket[]>([]);

  useEffect(() => {
    if (!isActive) return;

    const interval = setInterval(() => {
      const newPacket: TrafficPacket = {
        id: `pkt-${Date.now()}`,
        from: 'attacker',
        to: 'target',
        protocol: ['TCP', 'UDP', 'ICMP'][Math.floor(Math.random() * 3)],
        size: Math.floor(Math.random() * 1500),
        timestamp: Date.now()
      };

      setPackets(prev => [...prev.slice(-50), newPacket]);
    }, 500);

    return () => clearInterval(interval);
  }, [isActive]);

  return packets;
};
