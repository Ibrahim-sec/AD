// client/src/data/diagrams/index.js

export { kerberoastingDiagram } from './kerberoastingDiagram';
export { asrepRoastingDiagram } from './asrepRoastingDiagram';
export { adTopologyDiagram } from './adTopologyDiagram';

// Central registry for easy access
export const diagramRegistry = {
  kerberoasting: () => import('./kerberoastingDiagram').then(m => m.kerberoastingDiagram),
  asrepRoasting: () => import('./asrepRoastingDiagram').then(m => m.asrepRoastingDiagram),
  adTopology: () => import('./adTopologyDiagram').then(m => m.adTopologyDiagram),
};
