export { kerberoastingDiagram } from './kerberoastingDiagram';
export { asrepRoastingDiagram } from './asrepRoastingDiagram';
export { adTopologyDiagram } from './adTopologyDiagram';

export { ntlmRelayDiagram } from './ntlmRelayDiagram';
export { gppPasswordsDiagram } from './gppPasswordsDiagram';
export { zerologonDiagram } from './zerologonDiagram';
export { printNightmareDiagram } from './printNightmareDiagram';
export { skeletonKeyDiagram } from './skeletonKeyDiagram';

// Central registry for easy async import access
export const diagramRegistry = {
  kerberoasting: () => import('./kerberoastingDiagram').then(m => m.kerberoastingDiagram),
  asrepRoasting: () => import('./asrepRoastingDiagram').then(m => m.asrepRoastingDiagram),
  adTopology: () => import('./adTopologyDiagram').then(m => m.adTopologyDiagram),
  
  ntlmRelay: () => import('./ntlmRelayDiagram').then(m => m.ntlmRelayDiagram),
  gppPasswords: () => import('./gppPasswordsDiagram').then(m => m.gppPasswordsDiagram),
  zerologon: () => import('./zerologonDiagram').then(m => m.zerologonDiagram),
  printNightmare: () => import('./printNightmareDiagram').then(m => m.printNightmareDiagram),
  skeletonKey: () => import('./skeletonKeyDiagram').then(m => m.skeletonKeyDiagram),
};
