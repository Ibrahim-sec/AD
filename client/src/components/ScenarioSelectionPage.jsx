import { scenarioMap } from '../data/scenarios/index.js';
import { CheckCircle2, Circle, Swords, Lock } from 'lucide-react';
import { Link } from 'wouter';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"; // Import the Tooltip components

// This defines the logical attack chain.
// To unlock a scenario (key), the user must have completed the prerequisite (value).
const scenarioPrerequisites = {
  'asrep-roasting': 'nmap-recon',
  'kerberoasting': 'asrep-roasting',
  'bloodhound': 'kerberoasting',
  'pass-the-hash': 'bloodhound',
  'dcsync': 'pass-the-hash',
  // You can add your new "Golden Ticket" scenario here later
  // 'golden-ticket': 'dcsync', 
};

export default function ScenarioSelectionPage({ allScenarios, progress, customScenarios, onScenarioSelect }) {
  const builtInScenarios = Object.values(scenarioMap) || [];
  const customScenariosList = customScenarios || [];
  
  // Combine lists for display
  const scenariosToDisplay = [
    { type: 'Built-in', list: builtInScenarios },
    { type: 'Custom', list: customScenariosList },
  ];

  return (
    <div className="scenario-selection-page">
      <div className="selector-header">
        <Swords size={28} className="text-accent-color" />
        <h1>Select Your Attack Scenario</h1>
      </div>
      
      <div className="scenarios-grid-container">
        {scenariosToDisplay.map(({ type, list }) => {
          if (list.length === 0 && type === 'Custom') return null;
          
          return (
            <div key={type} className="scenarios-section">
              <h2 className="section-title">{type} Scenarios</h2>
              <div className="scenarios-list-grid">
                {list.map((scenario) => {
                  
                  // --- NEW LOGIC FOR LOCKING ---
                  const isCompleted = progress.scenariosCompleted?.includes(scenario.id);
                  const prerequisiteId = scenarioPrerequisites[scenario.id];
                  const prerequisiteScenario = prerequisiteId ? allScenarios[prerequisiteId] : null;
                  
                  // A scenario is locked if it's "Built-in", has a prerequisite,
                  // and that prerequisite is NOT in the completed list.
                  // Custom scenarios are never locked.
                  const isLocked = type === 'Built-in' &&
                                   prerequisiteId &&
                                   !progress.scenariosCompleted?.includes(prerequisiteId);
                  
                  const difficultyClass = `difficulty-${scenario.difficulty?.toLowerCase() || 'beginner'}`;
                  
                  // --- Card Content (re-used for locked/unlocked) ---
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
                          
                          {/* Updated status logic */}
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
                  
                  // --- Render a locked card or a clickable link ---
                  if (isLocked) {
                    return (
                      <Tooltip key={scenario.id}>
                        <TooltipTrigger asChild>
                          {/* Tooltip needs a non-link element to wrap */}
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

                  return (
                    // Unlocked scenarios are Links
                    <Link 
                      key={scenario.id} 
                      href={`/scenario/${scenario.id}`}
                      onClick={() => onScenarioSelect(scenario)}
                      className="scenario-card-link"
                    >
                      {cardContent}
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}