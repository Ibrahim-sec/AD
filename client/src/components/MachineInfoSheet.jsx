import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Server, Shield, User, CheckCircle2, XCircle } from "lucide-react";

// This map defines the static data for each node
const machineDetailsMap = {
  attacker: {
    title: 'Attacker Machine',
    role: 'Red Team Machine',
    icon: <User size={48} className="text-accent-color" />,
    baseIp: '10.0.0.5',
    baseHostname: 'kali-attacker',
  },
  target: {
    title: 'Internal Server',
    role: 'File / Application Server',
    icon: <Server size={48} className="text-accent-color" />,
    baseIp: '10.0.1.10',
    baseHostname: 'SRV-APP01.contoso.local',
  },
  dc: {
    title: 'Domain Controller',
    role: 'Authentication & Certificate Server',
    icon: <Shield size={48} className="text-accent-color" />,
    baseIp: '10.0.1.10',
    baseHostname: 'DC01.contoso.local',
  }
};

export default function MachineInfoSheet({ nodeName, network, compromisedNodes, isOpen, onClose }) {
  if (!nodeName || !machineDetailsMap[nodeName]) {
    return null;
  }

  const details = machineDetailsMap[nodeName];
  const isCompromised = compromisedNodes.includes(nodeName);

  // Use dynamic network info if available, otherwise fall back to base
  const ip = (nodeName === 'attacker' ? network.attacker?.ip : (nodeName === 'target' ? network.target?.ip : network.dc?.ip)) || details.baseIp;
  const hostname = (nodeName === 'attacker' ? network.attacker?.hostname : (nodeName === 'target' ? network.target?.hostname : network.dc?.hostname)) || details.baseHostname;


  return (
    <Sheet open={isOpen} onOpenChange={onClose}>
      <SheetContent className="sheet-content-override">
        <SheetHeader>
          <div className="sheet-icon">{details.icon}</div>
          <SheetTitle className="sheet-title-override">{details.title}</SheetTitle>
          <SheetDescription className="sheet-description-override">
            {details.role}
          </SheetDescription>
        </SheetHeader>
        <div className="sheet-body">
          <div className="info-group">
            <h4 className="info-title">Network Identity</h4>
            <div className="info-item">
              <span>Hostname</span>
              <code>{hostname}</code>
            </div>
            <div className="info-item">
              <span>IP Address</span>
              <code>{ip}</code>
            </div>
          </div>
          
          <div className="info-group">
            <h4 className="info-title">Status</h4>
            <div className="info-item status">
              <span>Compromised</span>
              {isCompromised ? (
                <code className="status-compromised">
                  <CheckCircle2 size={16} /> YES
                </code>
              ) : (
                <code className="status-safe">
                  <XCircle size={16} /> NO
                </code>
              )}
            </div>
          </div>
          
          {/* We could add a "Loot Found" section here in the future */}
          
        </div>
      </SheetContent>
    </Sheet>
  );
}