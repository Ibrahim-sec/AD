# Phase 1-3 Implementation Guide

## ✅ COMPLETED FILES

The following files have been successfully created/updated:

1. **client/src/lib/progressTracker.js** - v3 with global inventory
2. **client/src/data/campaigns/index.js** - Campaign definitions  
3. **client/src/lib/campaignManager.js** - Campaign management
4. **client/src/lib/scenarioManager.js** - Prerequisites & unlocking
5. **client/src/lib/simulator/lootResolver.js** - Global inventory integration
6. **client/src/components/SimulatorPage/hooks/useStepProcessing.js** - Progress passing

## 🔧 FILES THAT NEED MANUAL UPDATES

### 1. client/src/components/SimulatorPage/index.jsx

**What to change:**
Add `progress` and `setProgress` props to useStepProcessing call.

**Find this section (around line 60-75):**
```javascript
const {
  processStepOutput,
  processSubCommandOutput,
  processingRef,
  mountedRef
} = useStepProcessing({
  scenarioId,
  currentScenario,
  currentStep: state.currentStep,
  // ... other props
  setSimulatedFiles: state.setSimulatedFiles,
  setSimulatedFileSystem: state.setSimulatedFileSystem,
  setCredentialInventory: state.setCredentialInventory
});
```

**Add these two props:**
```javascript
const {
  processStepOutput,
  processSubCommandOutput,
  processingRef,
  mountedRef
} = useStepProcessing({
  scenarioId,
  currentScenario,
  currentStep: state.currentStep,
  // ... other props
  setSimulatedFiles: state.setSimulatedFiles,
  setSimulatedFileSystem: state.setSimulatedFileSystem,
  setCredentialInventory: state.setCredentialInventory,
  progress,              // ADD THIS
  setProgress            // ADD THIS
});
```

### 2. client/src/components/SimulatorPage/hooks/useScenarioInitialization.js

**What to change:**
Load global inventory on scenario start.

**Find the resetScenario function:**
```javascript
const resetScenario = useCallback(() => {
  return {
    currentStep: 0,
    // ...
    credentialInventory: [],
    simulatedFiles: [],
    // ...
  };
}, [scenarioId]);
```

**Replace with:**
```javascript
const resetScenario = useCallback(() => {
  // Load global inventory into session
  const globalCreds = progress?.globalInventory?.credentials || [];
  const globalFiles = progress?.globalInventory?.files || [];
  
  return {
    currentStep: 0,
    // ...
    credentialInventory: globalCreds,  // Start with global creds
    simulatedFiles: globalFiles,       // Start with global files
    // ...
  };
}, [scenarioId, progress]);
```

### 3. client/src/components/SimulatorPage/hooks/useScenarioCompletion.js

**What to change:**
Integrate campaign completion logic.

**Add imports at the top:**
```javascript
import { 
  completeCampaignScenario, 
  isCampaignComplete, 
  completeCampaign 
} from '@/lib/campaignManager';
import { getUnlockableScenarios } from '@/lib/scenarioManager';
```

**In the completeScenario function, ADD after regular completion:**
```javascript
const completeScenario = useCallback((stats) => {
  // Existing completion logic...
  let updatedProgress = addScenarioCompletion(progress, scenarioId, stats);
  
  // NEW: Campaign integration
  if (updatedProgress.activeCampaign) {
    updatedProgress = completeCampaignScenario(updatedProgress, scenarioId, stats);
    
    // Check if campaign is complete
    if (isCampaignComplete(updatedProgress)) {
      updatedProgress = completeCampaign(updatedProgress);
    }
  }
  
  // NEW: Check for unlocked scenarios
  const unlockedScenarios = getUnlockableScenarios(updatedProgress, scenarioId);
  if (unlockedScenarios.length > 0) {
    updatedProgress.recentlyUnlocked = unlockedScenarios.map(s => s.id);
  }
  
  setProgress(updatedProgress);
  saveProgress(updatedProgress);
  
  // Rest of existing code...
}, [scenarioId, progress, setProgress]);
```

### 4. client/src/components/HomePage.jsx

**What to add:**
Campaign selection UI and locked scenario indicators.

**Add imports:**
```javascript
import { getAvailableCampaigns } from '@/data/campaigns/index';
import { isScenarioUnlocked } from '@/lib/scenarioManager';
import { Lock } from 'lucide-react';
```

**Add state for campaigns:**
```javascript
const [showCampaigns, setShowCampaigns] = useState(false);
const availableCampaigns = getAvailableCampaigns(progress);
```

**In the scenario card rendering, add lock overlay:**
```javascript
{scenarios.map(scenario => {
  const lockStatus = isScenarioUnlocked(scenario.id, progress);
  const isCompleted = progress.scenariosCompleted.includes(scenario.id);
  
  return (
    <div 
      key={scenario.id}
      className={`scenario-card ${!lockStatus.unlocked ? 'locked' : ''}`}
    >
      {/* Show lock overlay if locked */}
      {!lockStatus.unlocked && (
        <div className="absolute inset-0 bg-black/80 backdrop-blur-sm rounded-lg flex flex-col items-center justify-center z-10 p-4">
          <Lock className="w-12 h-12 text-red-400 mb-3" />
          <p className="text-white font-semibold text-center mb-2">Scenario Locked</p>
          
          {lockStatus.reason === 'prerequisite' && (
            <div className="text-sm text-white/80 text-center">
              <p className="mb-2">Complete these first:</p>
              {lockStatus.missing.map(id => (
                <div key={id} className="text-yellow-400">
                  • {scenarioMap[id]?.title}
                </div>
              ))}
            </div>
          )}
          
          {lockStatus.reason === 'missing-loot' && (
            <div className="text-sm text-white/80 text-center">
              <p className="mb-2">Required credentials:</p>
              {lockStatus.missing.map(user => (
                <div key={user} className="text-yellow-400">
                  • {user}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      
      {/* Rest of scenario card content */}
    </div>
  );
})}
```

**Add Campaign Selection Button (before scenarios grid):**
```javascript
<div className="mb-6">
  <button
    onClick={() => setShowCampaigns(true)}
    className="px-6 py-3 bg-gradient-to-r from-[#2D9CDB] to-blue-600 text-white rounded-lg font-semibold hover:scale-105 transition-transform flex items-center gap-2"
  >
    <Trophy className="w-5 h-5" />
    Start Campaign Mode
    {progress.activeCampaign && (
      <span className="ml-2 px-2 py-0.5 bg-yellow-400 text-black text-xs rounded-full">
        In Progress
      </span>
    )}
  </button>
</div>
```

### 5. Create client/src/components/CampaignModal.jsx (NEW FILE)

```javascript
// client/src/components/CampaignModal.jsx

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Lock, Trophy, Clock, Zap, CheckCircle } from 'lucide-react';
import { getCampaignById, isCampaignUnlocked } from '@/data/campaigns/index';
import { startCampaign } from '@/lib/campaignManager';
import { useLocation } from 'wouter';

export default function CampaignModal({ isOpen, onClose, campaigns, progress, setProgress }) {
  const [, setLocation] = useLocation();
  
  const handleStartCampaign = (campaignId) => {
    const updatedProgress = startCampaign(progress, campaignId);
    setProgress(updatedProgress);
    
    // Navigate to first scenario
    const campaign = getCampaignById(campaignId);
    const firstScenario = campaign.scenarios[0];
    setLocation(`/scenario/${firstScenario.id}`);
    onClose();
  };
  
  if (!isOpen) return null;
  
  return (
    <AnimatePresence>
      <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.9 }}
          className="bg-[#101214] border border-white/10 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto"
        >
          {/* Header */}
          <div className="sticky top-0 bg-[#101214] border-b border-white/10 p-6 flex items-center justify-between">
            <div>
              <h2 className="text-2xl font-bold text-white">Campaign Mode</h2>
              <p className="text-white/60 text-sm mt-1">Multi-scenario attack chains with story progression</p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white/5 rounded-lg transition-colors"
            >
              <X className="w-6 h-6 text-white/60" />
            </button>
          </div>
          
          {/* Campaigns Grid */}
          <div className="p-6 space-y-4">
            {Object.values(campaigns).map(campaign => {
              const locked = !isCampaignUnlocked(campaign.id, progress);
              const completed = progress.completedCampaigns?.includes(campaign.id);
              const active = progress.activeCampaign?.id === campaign.id;
              
              return (
                <div
                  key={campaign.id}
                  className={`relative bg-[#1a1d24] border rounded-xl p-6 transition-all ${
                    locked ? 'opacity-60' : 'hover:border-[#2D9CDB] cursor-pointer'
                  }`}
                >
                  {/* Campaign Badge */}
                  <div className="flex items-start gap-4">
                    <div className="text-5xl">{campaign.badge}</div>
                    
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <h3 className="text-xl font-bold text-white">{campaign.title}</h3>
                        {completed && <CheckCircle className="w-5 h-5 text-green-400" />}
                        {active && (
                          <span className="px-2 py-0.5 bg-yellow-400 text-black text-xs rounded-full font-semibold">
                            IN PROGRESS
                          </span>
                        )}
                        {locked && <Lock className="w-5 h-5 text-red-400" />}
                      </div>
                      
                      <p className="text-white/70 text-sm mb-4">{campaign.description}</p>
                      
                      {/* Meta Info */}
                      <div className="flex items-center gap-4 text-sm text-white/60 mb-4">
                        <span className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          {campaign.estimatedTime}
                        </span>
                        <span className="flex items-center gap-1">
                          <Zap className="w-4 h-4" />
                          +{campaign.xpReward} XP
                        </span>
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold ${
                          campaign.difficulty === 'Beginner' ? 'bg-green-500/20 text-green-400' :
                          campaign.difficulty === 'Intermediate' ? 'bg-yellow-500/20 text-yellow-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          {campaign.difficulty}
                        </span>
                      </div>
                      
                      {/* Scenarios Preview */}
                      <div className="space-y-2 mb-4">
                        <p className="text-xs text-white/40 uppercase font-semibold">Scenarios ({campaign.scenarios.length}):</p>
                        <div className="flex flex-wrap gap-2">
                          {campaign.scenarios.map((s, i) => (
                            <div
                              key={i}
                              className="px-3 py-1 bg-white/5 rounded-full text-xs text-white/70"
                            >
                              {i + 1}. {s.description}
                              {s.required !== false && <span className="text-yellow-400 ml-1">*</span>}
                            </div>
                          ))}
                        </div>
                      </div>
                      
                      {/* Prerequisites */}
                      {campaign.prerequisites.length > 0 && (
                        <div className="text-xs text-white/50 mb-4">
                          Requires: {campaign.prerequisites.join(', ')}
                        </div>
                      )}
                      
                      {/* Action Button */}
                      <button
                        disabled={locked}
                        onClick={() => handleStartCampaign(campaign.id)}
                        className={`px-6 py-2 rounded-lg font-semibold transition-all ${
                          locked ? 'bg-white/5 text-white/30 cursor-not-allowed' :
                          completed ? 'bg-green-500/20 text-green-400 hover:bg-green-500/30' :
                          active ? 'bg-yellow-500/20 text-yellow-400 hover:bg-yellow-500/30' :
                          'bg-[#2D9CDB] text-white hover:bg-[#2D9CDB]/80'
                        }`}
                      >
                        {completed ? '✓ Replay Campaign' :
                         active ? 'Continue Campaign' :
                         locked ? '🔒 Locked' :
                         'Start Campaign'}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
```

### 6. Update client/src/components/Header.jsx

**Add campaign progress indicator:**

**Import:**
```javascript
import { getCampaignById, getCampaignProgress } from '@/lib/campaignManager';
```

**Add after existing header content:**
```javascript
{progress.activeCampaign && (
  <div className="flex items-center gap-3 px-4 py-2 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
    <Trophy className="w-5 h-5 text-yellow-400" />
    <div className="text-sm">
      <div className="font-semibold text-yellow-400">
        {getCampaignById(progress.activeCampaign.id)?.title}
      </div>
      <div className="text-white/60 text-xs">
        Scenario {progress.activeCampaign.currentScenarioIndex + 1} of {getCampaignById(progress.activeCampaign.id)?.scenarios.length}
      </div>
    </div>
    <div className="ml-auto">
      <div className="w-32 h-2 bg-white/10 rounded-full overflow-hidden">
        <div
          className="h-full bg-yellow-400 transition-all duration-300"
          style={{ width: `${getCampaignProgress(progress)}%` }}
        />
      </div>
    </div>
  </div>
)}
```

## ✅ TESTING CHECKLIST

After making all changes:

1. [ ] Start dev server: `pnpm dev`
2. [ ] Open browser console - check for no errors
3. [ ] Complete AS-REP Roasting scenario
4. [ ] Check that credentials appear in Loot tab
5. [ ] Close simulator and reopen
6. [ ] Verify credentials still there (global inventory working)
7. [ ] Try to start Kerberoasting - should have svc_backup creds available
8. [ ] Click "Start Campaign Mode" button
9. [ ] Start "Initial Foothold" campaign
10. [ ] Complete campaign scenarios in order
11. [ ] Verify story transitions appear between scenarios
12. [ ] Check that next campaign unlocks after completion

## 🐛 COMMON ISSUES

### Issue: "Cannot read property 'credentials' of undefined"
**Fix:** Make sure migration in progressTracker.js initializes globalInventory for old saves.

### Issue: Credentials not persisting
**Fix:** Verify progress and setProgress are passed to useStepProcessing.

### Issue: Scenarios still locked when they shouldn't be
**Fix:** Check scenarioRelationships in scenarioManager.js - may need to adjust prerequisites.

### Issue: Campaign doesn't advance
**Fix:** Ensure completeCampaignScenario is called in useScenarioCompletion.js.

## 📚 NEXT STEPS AFTER TESTING

1. Create more campaigns
2. Add transition modals between campaign scenarios
3. Add unlock notifications
4. Create inventory panel UI
5. Add campaign statistics page
