// client/src/App.jsx

import React, { useState, useEffect } from 'react';
import { Route, Switch } from 'wouter';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import SimulatorPage from './components/SimulatorPage/index.jsx';
import ScenarioEditor from './components/ScenarioEditor';
import HomePage from './components/HomePage';
import KnowledgeBase from './components/KnowledgeBase';
import { scenarios, scenarioMap } from './data/scenarios/index.js';
import { loadProgress, saveProgress } from './lib/progressTracker.js';
import { checkStorageHealth } from './lib/safeStorage.js';
import './index.css';
import ErrorBoundary from './components/ErrorBoundary.tsx';


// ============================================================================
// ERROR BOUNDARY COMPONENT
// ============================================================================

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { 
      hasError: false, 
      error: null,
      errorInfo: null 
    };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Application Error:', error, errorInfo);
    this.setState({ error, errorInfo });
    
    if (window.trackError) {
      window.trackError(error, errorInfo);
    }
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null, errorInfo: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-[#0a0b0d] flex items-center justify-center p-4">
          <div className="max-w-md w-full bg-[#101214] border border-white/10 rounded-xl p-8 text-center">
            <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-red-500/20 flex items-center justify-center">
              <AlertTriangle className="w-8 h-8 text-red-500" />
            </div>
            
            <h2 className="text-2xl font-bold text-white mb-2">
              Something Went Wrong
            </h2>
            
            <p className="text-white/60 text-sm mb-6">
              The application encountered an unexpected error. 
              Your progress has been saved.
            </p>
            
            {this.props.showDetails && this.state.error && (
              <div className="bg-black/50 rounded-lg p-4 mb-6 text-left">
                <div className="text-xs font-mono text-red-400 mb-2">
                  {this.state.error.toString()}
                </div>
                {this.state.errorInfo && (
                  <div className="text-xs font-mono text-white/40 overflow-auto max-h-32">
                    {this.state.errorInfo.componentStack}
                  </div>
                )}
              </div>
            )}
            
            <div className="flex gap-3">
              <button
                onClick={this.handleReset}
                className="flex-1 px-4 py-3 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white font-semibold rounded-lg transition-all flex items-center justify-center gap-2"
              >
                <RefreshCw className="w-4 h-4" />
                Try Again
              </button>
              
              <button
                onClick={() => window.location.href = '/'}
                className="flex-1 px-4 py-3 bg-white/5 hover:bg-white/10 text-white font-semibold rounded-lg transition-all"
              >
                Go Home
              </button>
            </div>
            
            <button
              onClick={() => window.location.reload()}
              className="mt-3 w-full text-xs text-white/40 hover:text-white/60 transition-colors"
            >
              Force Reload Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

// ============================================================================
// MAIN APP COMPONENT
// ============================================================================

export default function App() {
  const [progress, setProgress] = useState(null);
  const [appMode, setAppMode] = useState('simulator');
  const [isLoading, setIsLoading] = useState(true);
  const [storageWarning, setStorageWarning] = useState(null);

  useEffect(() => {
    initializeApp();
  }, []);

  const initializeApp = async () => {
    try {
      const health = checkStorageHealth();
      
      if (!health.available) {
        setStorageWarning({
          type: 'error',
          message: 'localStorage is not available. Progress will not be saved.'
        });
      } else if (health.approaching) {
        setStorageWarning({
          type: 'warning',
          message: `Storage is ${Math.round(health.usage * 100)}% full. Consider clearing old data.`
        });
      }

      const loadedProgress = loadProgress();
      setProgress(loadedProgress);
      
      await new Promise(resolve => setTimeout(resolve, 300));
      
      setIsLoading(false);
    } catch (error) {
      console.error('Failed to initialize app:', error);
      
      const defaultProgress = {
        totalScore: 0,
        rank: 'Novice',
        scenariosCompleted: [],
        scenarioStats: {},
        quizScores: {},
        unlockedAchievements: [],
        tutorialMode: true
      };
      
      setProgress(defaultProgress);
      setIsLoading(false);
    }
  };

  const handleProgressUpdate = (newProgress) => {
    setProgress(newProgress);
    saveProgress(newProgress);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#0a0b0d] flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[#2D9CDB]/20 flex items-center justify-center animate-pulse">
            <div className="w-8 h-8 border-4 border-[#2D9CDB] border-t-transparent rounded-full animate-spin"></div>
          </div>
          <p className="text-white/60 text-sm">Loading AD Attack Simulator...</p>
        </div>
      </div>
    );
  }

  if (!progress) {
    return (
      <div className="min-h-screen bg-[#0a0b0d] flex items-center justify-center p-4">
        <div className="max-w-md w-full bg-[#101214] border border-white/10 rounded-xl p-8 text-center">
          <AlertTriangle className="w-16 h-16 mx-auto mb-4 text-red-500" />
          <h2 className="text-2xl font-bold text-white mb-2">
            Failed to Load Progress
          </h2>
          <p className="text-white/60 text-sm mb-6">
            Unable to initialize the application. Please refresh the page.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="px-6 py-3 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white font-semibold rounded-lg transition-all"
          >
            Reload Application
          </button>
        </div>
      </div>
    );
  }

  return (
    <ErrorBoundary showDetails={process.env.NODE_ENV === 'development'}>
      <div>
        {storageWarning && (
          <div className={`fixed top-0 left-0 right-0 z-50 px-4 py-3 text-center text-sm ${
            storageWarning.type === 'error' 
              ? 'bg-red-500/20 text-red-400 border-b border-red-500/30'
              : 'bg-yellow-500/20 text-yellow-400 border-b border-yellow-500/30'
          }`}>
            <span>{storageWarning.message}</span>
            <button
              onClick={() => setStorageWarning(null)}
              className="ml-4 underline hover:no-underline"
            >
              Dismiss
            </button>
          </div>
        )}

        <Switch>
          <Route path="/">
            <HomePage 
              scenarios={scenarios}
              progress={progress}
              appMode={appMode}
              setAppMode={setAppMode}
            />
          </Route>

          <Route path="/knowledge">
            <KnowledgeBase />
          </Route>

          <Route path="/scenario/:scenarioId">
            {(params) => {
              const scenario = scenarioMap[params.scenarioId];
              
              if (!scenario) {
                return <NotFound />;
              }

              return (
                <SimulatorPage
                  scenarioId={params.scenarioId}
                  allScenarios={scenarioMap}
                  progress={progress}
                  setProgress={handleProgressUpdate}
                  appMode={appMode}
                  setAppMode={setAppMode}
                />
              );
            }}
          </Route>

          <Route path="/editor">
            <ScenarioEditor />
          </Route>

          <Route>
            <NotFound />
          </Route>
        </Switch>
      </div>
    </ErrorBoundary>
  );
}

function NotFound() {
  return (
    <div className="min-h-screen bg-[#0a0b0d] flex items-center justify-center p-4">
      <div className="max-w-md w-full bg-[#101214] border border-white/10 rounded-xl p-8 text-center">
        <div className="text-6xl mb-4">🔍</div>
        <h2 className="text-2xl font-bold text-white mb-2">
          Page Not Found
        </h2>
        <p className="text-white/60 text-sm mb-6">
          The page you're looking for doesn't exist or has been moved.
        </p>
        <a
          href="/"
          className="inline-block px-6 py-3 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 text-white font-semibold rounded-lg transition-all"
        >
          Return Home
        </a>
      </div>
    </div>
  );
}
