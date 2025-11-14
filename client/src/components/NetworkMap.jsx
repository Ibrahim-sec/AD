export default function NetworkMap({ highlightedMachine, highlightedArrow, network }) {
  
  // Fallback to default values if network prop is not provided
  const attacker = network?.attacker || { hostname: 'Attacker', ip: '10.0.0.5' };
  const target = network?.target || { hostname: 'Target Server', ip: '10.0.1.10' };

  return (
    <div className="network-map-container">
      <svg 
        viewBox="0 0 500 120" // Adjusted viewBox for a 2-node layout
        className="network-map"
        preserveAspectRatio="xMidYMid meet"
      >
        {/* Attacker Machine */}
        <g className={`machine ${highlightedMachine === 'attacker' ? 'highlighted' : ''}`}>
          <rect x="50" y="30" width="150" height="60" rx="8" />
          <text x="125" y="60" textAnchor="middle" className="machine-label">
            {attacker.hostname}
          </text>
          <text x="125" y="80" textAnchor="middle" className="machine-ip">
            {attacker.ip}
          </text>
        </g>

        {/* Arrow: Attacker to Target */}
        <g className={`arrow ${highlightedArrow === 'attacker-to-target' ? 'highlighted' : ''}`}>
          <line x1="200" y1="60" x2="300" y2="60" />
          <polygon points="300,60 290,55 290,65" />
          <text x="250" y="50" textAnchor="middle" className="arrow-label">
            Attack
          </text>
        </g>

        {/* Target Machine (DC, Internal Server, etc.) */}
        <g className={`machine ${highlightedMachine === 'target' ? 'highlighted' : ''}`}>
          <rect x="300" y="30" width="150" height="60" rx="8" />
          <text x="375" y="60" textAnchor="middle" className="machine-label">
            {target.hostname}
          </text>
          <text x="375" y="80" textAnchor="middle" className="machine-ip">
            {target.ip}
          </text>
        </g>
      </svg>
    </div>
  );
}