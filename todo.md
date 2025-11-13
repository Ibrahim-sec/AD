# AD Attack Simulator - Project TODO

## Phase 1: BloodHound Simulation (Minimal Prototype)

### Core Features
- [x] Create BloodHound scenario data structure with steps, commands, and outputs
- [x] Implement three-panel layout (Guide, Attacker Terminal, Internal Server)
- [x] Build Header component with project title
- [x] Build AttackerPanel component with terminal-like interface
- [x] Build InternalPanel component with server log display
- [x] Implement command input and validation logic
- [x] Implement step progression system
- [x] Add simulated typing effect for outputs
- [x] Style panels with dark terminal theme
- [x] Add fake IP addresses for realism (Attacker: 10.0.0.5, Server: 10.0.1.10)

### BloodHound Scenario Steps
- [x] Step 1: Start Neo4j database
- [x] Step 2: Run BloodHound Python collector
- [x] Step 3: Display completion message with export file

### UI/UX Requirements
- [x] Left panel: Guide with attack explanation and steps
- [x] Middle panel: Dark terminal for attacker commands
- [x] Right panel: Server logs showing responses
- [x] Responsive layout for all screen sizes
- [x] Clear visual distinction between panels

### Technical Implementation
- [x] Create `data/bloodhoundScenario.js` with scenario configuration
- [x] Update `App.jsx` with state management for simulation
- [x] Create `components/Header.jsx`
- [x] Create `components/AttackerPanel.jsx`
- [x] Create `components/InternalPanel.jsx`
- [x] Create `components/GuidePanel.jsx`
- [x] Add custom CSS for terminal styling

### Testing & Validation
- [x] Test command input and validation
- [x] Test step progression flow
- [x] Test all three panels display correctly
- [x] Verify outputs match scenario data
- [x] Test on different screen sizes

### Future Enhancements (Post-Phase 1)
- [ ] Add more attack scenarios (Mimikatz, Kerberoasting, etc.)
- [ ] Add scoring system
- [ ] Add progress tracking
- [ ] Add hints system
- [ ] Add reset functionality


## Phase 2: Multiple Scenarios & Enhanced Features

### Scenario Data Files
- [x] Create Kerberoasting scenario with 4-5 steps
- [x] Create AS-REP Roasting scenario with 4-5 steps
- [x] Create Pass-the-Hash scenario with 4-5 steps
- [x] Create scenarios/index.js to export all scenarios
- [x] Update BloodHound scenario with consistent structure

### Scenario Selection UI
- [x] Create ScenarioSelector component (left sidebar)
- [x] Implement scenario switching logic in App.jsx
- [x] Reset panels when switching scenarios
- [x] Update guide and step indicators on scenario change

### Machine Switching
- [x] Add machine tabs in AttackerPanel (Attacker, Internal Server, DC)
- [x] Create DomainControllerPanel component
- [x] Implement tab switching logic
- [x] Display DC-specific logs and outputs

### Network Map
- [x] Create NetworkMap.jsx SVG component
- [x] Design network topology (Attacker → Internal Server → DC)
- [x] Implement dynamic highlighting on step execution
- [x] Add machine status indicators

### Terminal Enhancements
- [x] Implement command suggestion system
- [x] Add "near-miss" command detection
- [x] Improve auto-scroll behavior
- [x] Add keyboard navigation support

### Styling & Animations
- [x] Add fade-in animations for log entries
- [x] Add colored borders for each machine
- [x] Create "Scenario Completed" banner
- [x] Add transition effects for machine switching
- [x] Improve responsive design

### Testing & Validation
- [x] Test all four scenarios end-to-end
- [x] Test scenario switching and reset
- [x] Test machine tab switching
- [x] Test network map highlighting
- [x] Test terminal suggestions
- [x] Verify animations and styling


## Phase 3: Gamification & Learning Features ✅ COMPLETE

### Player Progress & Scoring
- [x] Create PlayerHUD component showing score, rank, and step info
- [x] Implement scoring logic (+10 first try, +5 with hints, 0 skip)
- [x] Create rank system (Script Kiddie, Junior Red Teamer, Operator)
- [x] Implement localStorage persistence for score and rank
- [x] Track completed scenarios in localStorage

### Mission Flow
- [x] Create MissionModal component for briefing and debriefing
- [x] Add mission briefing modal at scenario start
- [x] Add mission debrief modal at scenario end
- [x] Display mission summary and learning points
- [x] Show score gained from scenario

### Hints & Tutorial Mode
- [x] Add hintShort and hintFull to all scenario steps
- [x] Create hint button in AttackerPanel
- [x] Implement progressive hint disclosure
- [x] Add Tutorial Mode toggle
- [x] Implement forgiving command matching in tutorial mode

### Post-Scenario Quiz
- [x] Create quizzes/bloodhoundQuiz.js with 3-5 questions
- [x] Create quizzes/kerberoastQuiz.js with 3-5 questions
- [x] Create quizzes/asrepQuiz.js with 3-5 questions
- [x] Create quizzes/pthQuiz.js with 3-5 questions
- [x] Create quizzes/index.js to export all quizzes
- [x] Build QuizPanel component
- [x] Implement quiz answer validation
- [x] Add bonus score for correct answers (+5 per correct)

### Achievements System
- [x] Create achievements.js with achievement definitions
- [x] Build AchievementsPanel component
- [x] Implement achievement unlock logic
- [x] Store unlocked achievements in localStorage
- [x] Show newly unlocked achievements after scenarios

### UI Enhancements & Animations
- [x] Add fade/slide animations for terminal output
- [x] Add fade-in animations for server logs
- [x] Add glow effects to network map nodes when active
- [x] Implement success animation when step completes
- [x] Create "Mission Complete" banner
- [x] Add animations for achievement unlocks
- [x] Improve visual feedback for correct/incorrect commands

### Testing & Integration
- [x] Test scoring system across all scenarios
- [x] Test localStorage persistence
- [x] Test hint system functionality
- [x] Test tutorial mode with forgiving matching
- [x] Test quiz functionality
- [x] Test achievement unlock logic
- [x] Test all animations and visual effects
- [x] Verify rank progression


## Bug Fixes & Issues

- [x] Fix TypeError: Cannot read properties of undefined (reading 'title') in QuizPanel
  - Issue: Quiz data export mismatch between quiz files and index.js
  - Solution: Fixed quiz file exports to use consistent default exports
  - Added null checks in QuizPanel component for safety


## Phase 4: Scenario Editor & Custom Scenarios

### Utilities & Storage
- [ ] Create `utils/scenarioStorage.js` with localStorage helpers
  - getCustomScenarios()
  - saveCustomScenario(scenario)
  - deleteCustomScenario(id)
  - updateCustomScenario(id, scenario)
- [ ] Create `utils/scenarioValidation.js` for JSON validation
  - validateScenarioStructure(scenario)
  - validateStep(step)
  - Return structured error messages
- [ ] Create `utils/scenarioTemplates.js` with template definitions
  - BloodHound-style recon template
  - Kerberoast-style attack template
  - Lateral movement template

### Scenario Editor Component
- [ ] Create `components/ScenarioEditor.jsx` with full editor UI
  - Metadata fields (name, difficulty, target, description)
  - Machine configuration (attacker, internal, DC)
  - Dynamic steps list with CRUD operations
  - Add/delete/reorder steps functionality
  - Multi-line text areas for outputs
  - Hint fields (short and full)
  - Score value input

### Import/Export Features
- [ ] Implement "Export as JSON" button
  - Download scenario as .json file
  - Include all metadata and steps
- [ ] Implement "Import from JSON" button
  - File picker for JSON upload
  - Validate imported scenario
  - Show error messages on validation failure
  - Load into editor on success

### Template System
- [ ] Add "Create from Template" option
  - Template selector dropdown
  - Pre-fill scenario with template data
  - Allow user to customize after selection

### Integration with Play Mode
- [ ] Update ScenarioSelector to show "Built-in" and "Custom" sections
- [ ] Load custom scenarios from localStorage on app start
- [ ] Ensure custom scenarios work with existing trainer logic
- [ ] Handle missing quizzes for custom scenarios gracefully

### Mode Toggle
- [ ] Add mode selector at top of app
  - "Play Scenarios" tab
  - "Scenario Editor" tab
  - Toggle between modes without losing data
- [ ] Update App.jsx to render appropriate UI based on mode

### Testing & Validation
- [ ] Test creating new scenario from scratch
- [ ] Test editing existing scenario
- [ ] Test saving/loading custom scenarios
- [ ] Test export/import JSON functionality
- [ ] Test template creation
- [ ] Test custom scenarios in Play Mode
- [ ] Verify all Phase 1-3 features still work
- [ ] Test error handling for invalid JSON


## Phase 6: Polish, Stability & Robustness

### Design System & Layout
- [x] Create design token constants (colors, spacing, typography, radius)
- [x] Refactor button styles (primary, secondary, ghost variants)
- [x] Standardize card and panel styling
- [x] Refactor input fields and textareas
- [x] Standardize tabs and sidebar items
- [x] Test responsive design on 1280x720 and smaller screens
- [x] Fix any layout overflow issues

### Typography & Hierarchy
- [x] Define consistent heading levels (h1, h2, h3, h4)
- [x] Improve line height and font sizes for readability
- [x] Ensure terminal text is monospaced
- [x] Make logs visually distinct from guide text
- [x] Add clear separators between sections
- [x] Improve guide panel readability

### Terminal UX Polish
- [x] Implement auto-scroll to latest line in terminal
- [x] Add clear input prompt (e.g., "ATTACKER01>")
- [x] Improve error messages for rejected commands
- [x] Add input field state management (disabled when finished)
- [x] Clear input field on successful command
- [x] Add visual feedback for command submission

### Machine Panel Improvements
- [x] Add clear labels for each machine
- [x] Use consistent icons or visual markers
- [x] Improve panel header styling
- [x] Make machine selection obvious

### Scenario Editor Validation
- [x] Validate required fields (name, at least one step)
- [x] Validate each step has description, expectedCommand, output
- [x] Show actionable error messages
- [x] Prevent saving invalid scenarios
- [x] Improve JSON import error messages
- [x] Guard against invalid JSON parsing

### Error Handling & Fallbacks
- [x] Add runtime validation for scenario data
- [x] Show fallback message for invalid scenarios
- [x] Prevent crashes from bad data
- [x] Create safe localStorage helper functions
- [x] Handle JSON parse errors gracefully
- [x] Handle missing localStorage keys

### Empty States & Feedback
- [x] Add empty state for custom scenarios
- [x] Add empty state for sessions
- [x] Add empty state for leaderboard
- [x] Add save confirmation messages
- [x] Add action feedback (toast/snackbar)
- [x] Improve user feedback for all actions

### Accessibility Improvements
- [x] Ensure Tab navigation works
- [x] Make buttons clearly focusable
- [x] Make terminal input keyboard-accessible
- [x] Add ARIA labels to tab controls
- [x] Add ARIA labels to custom controls
- [x] Test keyboard-only navigation

### Error Boundaries
- [x] Create ErrorBoundary component
- [x] Wrap Trainer view with error boundary
- [x] Add fallback UI for errors
- [x] Test error recovery

### Code Cleanup
- [x] Remove unused imports
- [x] Remove dead code
- [x] Standardize component naming
- [x] Consolidate duplicate logic
- [x] Improve code organization
- [x] Add helpful comments where needed

### Testing & Validation
- [x] Test all scenarios end-to-end
- [x] Test editor validation
- [x] Test error handling
- [x] Test localStorage recovery
- [x] Test responsive design
- [x] Test keyboard navigation
- [x] Test empty states


## Critical Bug Fixes

- [x] Fix BloodHound scenario clicking error with debug logging
- [x] Fix layout overflow - right panel (Machine Terminal) is cut off
- [x] Ensure all panels visible at normal zoom (100%)
- [x] Test scenario switching for all 4 scenarios


## Design Redesign - Phase 7

### Color Scheme Unification
- [ ] Replace all accent colors with single #2D9CDB (cyber blue)
- [ ] Remove red, green, purple, blue outlines from machines
- [ ] Remove multicolored borders and glow effects
- [ ] Update all UI elements to use consistent accent color

### Panel Style Unification
- [ ] Apply consistent panel style to all containers
  - background: #101214
  - border: 1px solid rgba(255,255,255,0.07)
  - border-radius: 8px
  - padding: 16px
- [ ] Update Attack Guide panel
- [ ] Update Terminal panel
- [ ] Update Internal Server panel
- [ ] Update Scenario List panel
- [ ] Update all other major containers

### Spacing & Layout Fixes
- [ ] Reduce vertical gap between network map and mode toggle buttons (30-40px reduction)
- [ ] Reduce gap between mode toggle and main panels
- [ ] Apply consistent 16px padding inside panels
- [ ] Apply consistent 16px gap between panels
- [ ] Apply consistent 24px gap between sections
- [ ] Make layout feel tighter and more connected

### Sidebar Scrolling Fix
- [ ] Fix sidebar scroll bug - scenarios cut off
- [ ] Apply overflow-y: auto to scenario list
- [ ] Set max-height: calc(100vh - 200px)
- [ ] Add padding-right: 6px for scrollbar space
- [ ] Test all scenarios visible at normal zoom

### Machine Tabs Styling
- [ ] Update tab background to #1B1E22
- [ ] Set padding to 6px 14px
- [ ] Set border-radius to 6px
- [ ] Set margin-right to 8px
- [ ] Remove different colors for each machine
- [ ] Use accent color for active tab highlighting only

### Typography & Hierarchy
- [ ] Standardize panel title font size and style
- [ ] Improve guide text readability with proper line height
- [ ] Ensure terminal is monospace and contrasts clearly
- [ ] Make server logs slightly lighter than terminal
- [ ] Ensure consistent heading levels

### Header & Progress Bar
- [ ] Update progress bar color to #2D9CDB
- [ ] Make progress bar thinner and more subtle
- [ ] Clean up header styling for consistency

### Network Map Cleanup
- [ ] Remove multicolored borders from machines
- [ ] Update node styles to match unified theme
- [ ] Use accent color for highlights only

### Testing & Verification
- [ ] Test all design changes in browser
- [ ] Verify responsive layout at different zoom levels
- [ ] Test sidebar scrolling at normal zoom
- [ ] Verify all panels visible without zoom adjustment
- [ ] Check color consistency across entire app


## Phase 7: Architecture Cleanup & Refactoring

### Structural Issues - CRITICAL
- [ ] Remove duplicate App.tsx (keep App.jsx as main app)
- [ ] Remove Home.tsx template page
- [ ] Remove NotFound.tsx template page
- [ ] Remove duplicate ErrorBoundary.jsx (keep ErrorBoundary.tsx)
- [ ] Remove ManusDialog.tsx (unused)
- [ ] Remove const.ts (only used by template)
- [ ] Clean up unused imports from remaining files

### CSS & Layout Fixes - CRITICAL
- [ ] Fix main-content overflow: hidden → overflow-y: auto for vertical scrolling
- [ ] Remove overflow: hidden from panels-container
- [ ] Fix scenario sidebar overflow: hidden issue
- [ ] Fix mobile max-height: 150px clipping scenarios
- [ ] Ensure vertical scrolling works for all panels
- [ ] Test scrolling behavior on all screen sizes

### Theme & Style Consistency
- [ ] Set ThemeProvider defaultTheme="dark" in App.jsx
- [ ] Verify dark theme is applied consistently
- [ ] Remove unused Tailwind demo bits from index.css

### Code Cleanup
- [ ] Remove debug console.log statements from App.jsx
- [ ] Wrap remaining logs with import.meta.env.DEV check
- [ ] Remove unused imports from components
- [ ] Clean up dead code
- [ ] Standardize naming conventions

### Testing & Verification
- [ ] Test all scenarios load correctly
- [ ] Test vertical scrolling in all panels
- [ ] Test sidebar scrolling
- [ ] Verify no console errors
- [ ] Test on different screen sizes
- [ ] Verify no regressions in functionality


## Phase 8: Comprehensive Cleanup & Bugfix Pass

### 1. Sidebar Scroll Behavior Fix
- [x] Create .main-layout wrapper with fixed height calc(100vh - header-height)
- [x] Create .main-grid with flex: 1, grid layout, and overflow: hidden
- [x] Update .scenario-selector to use height: 100% and flex-direction: column
- [x] Ensure .scenarios-list has flex: 1 and overflow-y: auto
- [x] Remove any max-height constraints from outer sidebar
- [x] Test: scenario list scrolls independently, page doesn't jump

### 2. App Structure Unification
- [x] Convert App.jsx to App.tsx (or create Trainer.tsx page component)
- [x] Move simulator logic into TSX component
- [x] Update router to use simulator at / route
- [x] Delete duplicate App variant
- [x] Keep only one ErrorBoundary (prefer .tsx version)
- [x] Delete unused ErrorBoundary file
- [x] Remove leftover template pages (Home.tsx, NotFound.tsx)
- [x] Verify single clear entry point

### 3. LocalStorage Safety
- [x] Refactor scenarioStorage.js to use safeGetItem/safeSetItem/safeRemoveItem
- [x] Use consistent namespacing (ad-trainer-customScenarios)
- [x] Remove raw localStorage.getItem/setItem calls
- [x] Test storage operations work correctly

### 4. Scenario Editor Improvements
- [x] Add "Load as Template" button to load built-in scenarios into editor
- [x] When saving edits, store as custom scenario override
- [x] Implement scenario resolution: prefer custom → fallback to built-in
- [x] Test: editing built-in scenario creates custom override

### 5. Design Consistency
- [x] Verify single accent color used throughout
- [x] Standardize all main panels with same card style
- [x] Ensure same border-radius, border-color, background, padding
- [x] Reduce vertical gaps between network map, buttons, and panels
- [x] Test: layout feels tight and focused

### 6. Machine Tabs & Headers Polish
- [x] Increase tab padding and make easier to click
- [x] Use accent color for active tab (not machine colors)
- [x] Standardize IP badge styling
- [x] Ensure panel headers share typography and layout
- [x] Test: clear hierarchy and visual consistency

### 7. Testing & Verification
- [x] Test sidebar scroll behavior
- [x] Test all scenarios load correctly
- [x] Test custom scenario creation and override
- [x] Test localStorage operations
- [x] Verify no regressions in existing features
- [x] Test responsive layout
