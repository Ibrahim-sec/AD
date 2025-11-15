// client/src/components/SimulatorPage/hooks/useModalManagement.js

import { useState } from 'react';

export const useModalManagement = () => {
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [showQuiz, setShowQuiz] = useState(false);
  const [showAchievements, setShowAchievements] = useState(false);
  const [inspectingNode, setInspectingNode] = useState(null);

  return {
    isSettingsOpen,
    setIsSettingsOpen,
    showQuiz,
    setShowQuiz,
    showAchievements,
    setShowAchievements,
    inspectingNode,
    setInspectingNode
  };
};
