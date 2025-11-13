import { Shield } from 'lucide-react';

export default function Header({ title, currentStep, totalSteps }) {
  return (
    <header className="simulator-header">
      <div className="header-content">
        <div className="header-left">
          <Shield className="header-icon" size={32} />
          <div className="header-title">
            <h1>AD Attack Simulator</h1>
            <p className="header-subtitle">{title}</p>
          </div>
        </div>
        
        <div className="header-right">
          <div className="step-indicator">
            <span className="step-label">Step</span>
            <span className="step-count">{currentStep} / {totalSteps}</span>
          </div>
        </div>
      </div>
      
      <div className="progress-bar">
        <div 
          className="progress-fill" 
          style={{ width: `${(currentStep / totalSteps) * 100}%` }}
        />
      </div>
    </header>
  );
}
