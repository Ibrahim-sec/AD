// Replace ResizablePanelGroup with a simple div
<div className="h-full flex">
  {/* Left Panel */}
  <div style={{ width: '25%', minWidth: '300px' }}>
    <GuidePanel {...} />
  </div>
  
  {/* Center Panel */}
  <div style={{ flex: 1 }}>
    {/* Network Map */}
  </div>
  
  {/* Right Panel */}
  <div style={{ width: '40%', minWidth: '400px' }}>
    <AttackerPanel {...} />
  </div>
</div>
