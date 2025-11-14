import { scenarioMap } from '../data/scenarios/index.js';
import { CheckCircle2, Circle, Swords, Lock, ChevronRight } from 'lucide-react';
import { Link } from 'wouter';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"; // We need this for locked scenarios

// This defines the logical attack chain.
// To unlock a scenario (key), the user must have completed the prerequisite (value).
const scenarioPrerequisites = {
  'asrep-roasting': 'nmap-recon',
  'kerberoasting': 'asrep-roasting',
  'bloodhound': 'kerberoasting',
  'pass-the-hash': 'bloodhound',
  'dcsync': 'pass-the-hash',
};

// --- Helper Component to Render a Single Scenario Card ---
// This avoids duplicating code and keeps the main component clean
function RenderScenarioCard({ scenario, allScenarios, progress, onScenarioSelect }) {
  if (!scenario) return null;

  const isCompleted = progress.scenariosCompleted?.includes(scenario.id);
  const prerequisiteId = scenarioPrerequisites[scenario.id];
  const prerequisiteScenario = prerequisiteId ? allScenarios[prerequisiteId] : null;

  const isLocked = prerequisiteId && !progress.scenariosCompleted?.includes(prerequisiteId);
  const difficultyClass = `difficulty-${scenario.difficulty?.toLowerCase() || 'beginner'}`;

  // This is the card's visual content
  const cardContent = (
    <div
      className={`scenario-card ${difficultyClass} ${isLocked ? 'is-locked' : ''}`}
    >
      <div className="scenario-header">
        <h3 className="scenario-title">{scenario.name || scenario.title}</h3>
        <span className={`difficulty-badge ${difficultyClass}`}>
          {scenario.difficulty || 'Beginner'}
        </span>
      </div>
      
      <p className="scenario-description">{scenario.description || scenario.mission.objective}</p>

      <div className="scenario-footer">
          <span className="step-count">
              Steps: {scenario.steps.length}
          </span>
          
          {isLocked ? (
            <span className="completion-status locked">
              <Lock size={16} />
              Locked
            </span>
          ) : isCompleted ? (
            <span className="completion-status completed">
              <CheckCircle2 size={16} />
              Completed
            </span>
          ) : (
            <span className="completion-status">
              <Circle size={16} />
              New
            </span>
          )}
      </div>
    </div>
  );

  // Render a non-clickable, grayed-out card with a tooltip if locked
  if (isLocked) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="locked-card-wrapper">
            {cardContent}
          </div>
        </TooltipTrigger>
        <TooltipContent>
          <p>Requires completion of: **{prerequisiteScenario?.title || prerequisiteId}**</p>
        </TooltipContent>
      </Tooltip>
    );
  }

  // Render a clickable Link if unlocked
  return (
    <Link 
      href={`/scenario/${scenario.id}`}
      onClick={() => onScenarioSelect(scenario)}
      className="scenario-card-link"
    >
      {cardContent}
    </Link>
  );
}
// --- End Helper Component ---


export default function ScenarioSelectionPage({ allScenarios, progress, customScenarios, onScenarioSelect }) {
  const customScenariosList = customScenarios || [];
  
  return (
    <div className="scenario-selection-page">
      <div className="selector-header">
        <Swords size={28} className="text-accent-color" />
        <h1>Select Your Attack Scenario</h1>
      </div>
      
      <div className="scenarios-grid-container">
        
        {/* --- NEW CAMPAIGN PATH UI --- */}
        <div className="scenarios-section">
          <h2 className="section-title">Campaign Attack Path</h2>
          <div className="campaign-container">
            
            {/* TIER 1: RECONNAISSANCE */}
            <div className="campaign-tier">
              <h3 className="tier-title">Phase 1: Reconnaissance</h3>
              <RenderScenarioCard
                scenario={allScenarios['nmap-recon']}
                allScenarios={allScenarios}
                progress={progress}
                onScenarioSelect={onScenarioSelect}
              />
            </div>
            
            <div className="campaign-connector">
              <ChevronRight size={48} />
            </div>

            {/* TIER 2: INITIAL ACCESS */}
            <div className="campaign-tier">
              <h3 className="tier-title">Phase 2: Initial Access</h3>
              <RenderScenarioCard
                scenario={allScenarios['asrep-roasting']}
                allScenarios={allScenarios}
                progress={progress}
                onScenarioSelect={onScenarioSelect}
              />
              {/* You could add "LLMNR Poisoning" here later and it would unlock automatically */}
            </div>
            
            <div className="campaign-connector">
              <ChevronRight size={48} />
            </div>

            {/* TIER 3: ESCALATION */}
            <div className="campaign-tier">
              <h3 className="tier-title">Phase 3: Escalation</h3>
              <RenderScenarioCard
                scenario={allScenarios['kerberoasting']}
                allScenarios={allScenarios}
                progress={progress}
                onScenarioSelect={onScenarioSelect}
              />
              <RenderScenarioCard
                scenario={allScenarios['bloodhound']}
                allScenarios={allScenarios}
                progress={progress}
                onScenarioSelect={onScenarioSelect}
              />
            </div>

            <div className="campaign-connector">
              <ChevronRight size={48} />
            </div>

            {/* TIER 4: LATERAL MOVEMENT */}
            <div className="campaign-tier">
              <h3 className="tier-title">Phase 4: Lateral Movement</h3>
              <RenderScenarioCard
                scenario={allScenarios['pass-the-hash']}
                allScenarios={allScenarios}
                progress={progress}
                onScenarioSelect={onScenarioSelect}
              />
            </div>

            <div className="campaign-connector">
              <ChevronRight size={48} />
            </div>

            {/* TIER 5: DOMAIN DOMINANCE */}
            <div className="campaign-tier">
              <h3 className="tier-title">Phase 5: Domain Dominance</h3>
              <RenderScenarioCard
                scenario={allScenarios['dcsync']}
                allScenarios={allScenarios}
                progress={progress}
                onScenarioSelect={onScenarioSelect}
              />
              {/* You can add "Golden Ticket" here later */}
            </div>

          </div>
        </div>
        {/* --- END CAMPAIGN PATH UI --- */}


        {/* --- CUSTOM SCENARIOS (Still in a grid) --- */}
        {customScenariosList.length > 0 && (
          <div className="scenarios-section">
            <h2 className="section-title">Custom Scenarios</h2>
            <div className="scenarios-list-grid">
              {customScenariosList.map((scenario) => (
                // Custom scenarios are always unlocked
                <RenderScenarioCard
                  key={scenario.id}
                  scenario={scenario}
                  allScenarios={allScenarios}
                  progress={progress}
                  onScenarioSelect={onScenarioSelect}
                />
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}