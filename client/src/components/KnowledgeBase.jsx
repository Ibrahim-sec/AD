// Example: How to use in KnowledgeBase.jsx

import { NetworkDiagram } from './diagrams';
import { kerberoastingDiagram, asrepRoastingDiagram, adTopologyDiagram } from '@/data/diagrams';
import '@/styles/diagrams.css';

export default function KnowledgeBase() {
  return (
    <div className="knowledge-base">
      <h1>Active Directory Attack Knowledge Base</h1>

      {/* Kerberoasting Article */}
      <section>
        <h2>Kerberoasting Attack</h2>
        <p>
          Kerberoasting is a post-exploitation attack technique that attempts to crack 
          the password hashes of service accounts within Active Directory...
        </p>

        <NetworkDiagram 
          diagramData={kerberoastingDiagram}
          onNodeClick={(node) => console.log('Clicked:', node)}
          height="500px"
        />

        <h3>How It Works</h3>
        <p>...</p>
      </section>

      {/* AS-REP Roasting */}
      <section>
        <h2>AS-REP Roasting</h2>
        <NetworkDiagram diagramData={asrepRoastingDiagram} />
      </section>

      {/* AD Topology */}
      <section>
        <h2>Active Directory Topology</h2>
        <NetworkDiagram 
          diagramData={adTopologyDiagram}
          showMiniMap={true}
          interactive={true}
        />
      </section>
    </div>
  );
}
