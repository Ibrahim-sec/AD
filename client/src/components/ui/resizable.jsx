// client/src/components/ui/resizable.jsx

import * as React from "react";
import { GripVertical } from "lucide-react";

// ============================================================================
// RESIZABLE PANEL GROUP
// ============================================================================

const ResizablePanelGroup = React.forwardRef(
  ({ className = "", direction = "horizontal", children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={`flex ${direction === "vertical" ? "flex-col" : "flex-row"} w-full h-full ${className}`}
        {...props}
      >
        {children}
      </div>
    );
  }
);
ResizablePanelGroup.displayName = "ResizablePanelGroup";

// ============================================================================
// RESIZABLE PANEL
// ============================================================================

const ResizablePanel = React.forwardRef(
  ({ className = "", defaultSize = 50, minSize = 10, maxSize = 90, children, ...props }, ref) => {
    const [size, setSize] = React.useState(defaultSize);

    return (
      <div
        ref={ref}
        className={`relative overflow-hidden ${className}`}
        style={{ 
          flex: `0 0 ${size}%`,
          minWidth: `${minSize}%`,
          maxWidth: `${maxSize}%`
        }}
        data-panel-size={size}
        {...props}
      >
        {children}
      </div>
    );
  }
);
ResizablePanel.displayName = "ResizablePanel";

// ============================================================================
// RESIZABLE HANDLE
// ============================================================================

const ResizableHandle = React.forwardRef(
  ({ className = "", withHandle = false, ...props }, ref) => {
    const [isDragging, setIsDragging] = React.useState(false);

    const handleMouseDown = (e) => {
      setIsDragging(true);
      e.preventDefault();

      const startX = e.clientX;
      const parentElement = e.currentTarget.parentElement;
      const prevPanel = e.currentTarget.previousElementSibling;
      const nextPanel = e.currentTarget.nextElementSibling;

      if (!prevPanel || !nextPanel) return;

      const prevSize = parseFloat(prevPanel.dataset.panelSize || 50);
      const nextSize = parseFloat(nextPanel.dataset.panelSize || 50);

      const handleMouseMove = (moveEvent) => {
        const deltaX = moveEvent.clientX - startX;
        const parentWidth = parentElement.offsetWidth;
        const deltaPercent = (deltaX / parentWidth) * 100;

        const newPrevSize = Math.max(10, Math.min(90, prevSize + deltaPercent));
        const newNextSize = Math.max(10, Math.min(90, nextSize - deltaPercent));

        // Update sizes
        prevPanel.style.flex = `0 0 ${newPrevSize}%`;
        nextPanel.style.flex = `0 0 ${newNextSize}%`;
        prevPanel.dataset.panelSize = newPrevSize;
        nextPanel.dataset.panelSize = newNextSize;
      };

      const handleMouseUp = () => {
        setIsDragging(false);
        document.removeEventListener("mousemove", handleMouseMove);
        document.removeEventListener("mouseup", handleMouseUp);
      };

      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    };

    return (
      <div
        ref={ref}
        className={`relative flex items-center justify-center w-2 cursor-col-resize bg-transparent hover:bg-white/10 transition-colors ${
          isDragging ? "bg-[#2D9CDB]/30" : ""
        } ${className}`}
        onMouseDown={handleMouseDown}
        {...props}
      >
        {withHandle && (
          <div className="flex items-center justify-center w-6 h-12 rounded-md bg-white/5 border border-white/10">
            <GripVertical className="w-4 h-4 text-white/40" />
          </div>
        )}
      </div>
    );
  }
);
ResizableHandle.displayName = "ResizableHandle";

// ============================================================================
// EXPORTS
// ============================================================================

export { ResizablePanelGroup, ResizablePanel, ResizableHandle };
