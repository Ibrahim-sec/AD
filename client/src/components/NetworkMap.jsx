export default function NetworkMap({ highlightedMachine, highlightedArrow }) {
  return (
    <div className="network-map-container">
      <svg 
        viewBox="0 0 800 120" 
        className="network-map"
        preserveAspectRatio="xMidYMid meet"
      >
        {/* Attacker Machine */}
        <g className={`machine ${highlightedMachine === 'attacker' ? 'highlighted' : ''}`}>
          <rect x="50" y="30" width="120" height="60" rx="8" />
          <text x="110" y="65" textAnchor="middle" className="machine-label">
            Attacker
          </text>
          <text x="110" y="80" textAnchor="middle" className="machine-ip">
            10.0.0.5
          </text>
        </g>

        {/* Arrow: Attacker to Internal Server */}
        <g className={`arrow ${highlightedArrow === 'attacker-to-target' ? 'highlighted' : ''}`}>
          <line x1="170" y1="60" x2="280" y2="60" />
          <polygon points="280,60 270,55 270,65" />
          <text x="225" y="50" textAnchor="middle" className="arrow-label">
            Attack
          </text>
        </g>

        {/* Internal Server */}
        <g className={`machine ${highlightedMachine === 'target' ? 'highlighted' : ''}`}>
          <rect x="280" y="30" width="120" height="60" rx="8" />
          <text x="340" y="65" textAnchor="middle" className="machine-label">
            Internal Server
          </text>
          <text x="340" y="80" textAnchor="middle" className="machine-ip">
            10.0.1.10
          </text>
        </g>

        {/* Arrow: Internal Server to Domain Controller */}
        <g className={`arrow ${highlightedArrow === 'target-to-dc' ? 'highlighted' : ''}`}>
          <line x1="400" y1="60" x2="510" y2="60" />
          <polygon points="510,60 500,55 500,65" />
          <text x="455" y="50" textAnchor="middle" className="arrow-label">
            Auth
          </text>
        </g>

        {/* Domain Controller */}
        <g className={`machine ${highlightedMachine === 'dc' ? 'highlighted' : ''}`}>
          <rect x="510" y="30" width="120" height="60" rx="8" />
          <text x="570" y="65" textAnchor="middle" className="machine-label">
            Domain Controller
          </text>
          <text x="570" y="80" textAnchor="middle" className="machine-ip">
            10.0.1.10
          </text>
        </g>
      </svg>
    </div>
  );
}