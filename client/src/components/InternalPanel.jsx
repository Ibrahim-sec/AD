import { useRef, useEffect } from 'react';
import { Server } from 'lucide-react';

export default function InternalPanel({ history, network }) {
  const logEndRef = useRef(null);

  // Auto-scroll to bottom when history updates
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  return (
    <div className="panel internal-panel">
      <div className="panel-header">
        <Server size={20} />
        <h2>Internal Server</h2>
        <span className="panel-badge blue">{network.target.ip}</span>
      </div>
      
      <div className="panel-content server-content">
        <div className="server-output">
          {history.map((entry, index) => (
            <div key={index} className={`server-line ${entry.type}`}>
              <span className="server-text">{entry.text}</span>
            </div>
          ))}
          <div ref={logEndRef} />
        </div>
      </div>
    </div>
  );
}
