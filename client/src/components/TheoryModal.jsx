import { useState } from 'react';
import { NetworkDiagram } from './diagrams';

export default function TheoryModal({ module, isOpen, onClose, onComplete }) {
  const [currentSection, setCurrentSection] = useState(0);

  if (!module) return null;
  const { sections, diagram, quiz } = module;

  const section = sections[currentSection];

  const handleNext = () => {
    if (currentSection < sections.length - 1) {
      setCurrentSection(currentSection + 1);
    } else if (quiz) {
      setCurrentSection(sections.length); // Move to quiz
    } else {
      onComplete?.();
    }
  };

  const handlePrev = () => {
    if (currentSection > 0) setCurrentSection(currentSection - 1);
  };

  return (
    <div className={`fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur select-none ${!isOpen ? 'hidden' : ''}`}>
      <div className="mx-2 bg-[#161925] border border-white/10 rounded-xl max-w-2xl w-full shadow-2xl p-6 overflow-y-auto relative">
        {/* Close */}
        <button
          className="absolute top-4 right-4 p-2 text-white/70 hover:text-white"
          onClick={() => onClose?.()}>
          ✕
        </button>
        
        {/* Section Content */}
        <div>
          <h2 className="font-bold text-2xl mb-2">{module.title}</h2>
          <div className="mb-4 text-sm text-white/60">{module.subtitle}</div>
          <div className="mb-5">
            <div className="font-bold text-lg mb-2">{section.title}</div>
            <div className="whitespace-pre-line">
              {section.content}
            </div>
          </div>
          {/* Render diagram after the "How It Works" section, or by index */}
          {(diagram && ((section.title?.toLowerCase().includes('diagram')) || currentSection === 1)) && (
            <div className="my-5">
              <NetworkDiagram diagramData={diagram} height="340px" />
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex justify-between items-center mt-8">
          <button onClick={handlePrev} disabled={currentSection === 0} className="px-4 py-2 bg-white/10 rounded text-white/70 disabled:opacity-40">
            Previous
          </button>
          <button onClick={handleNext} className="px-4 py-2 bg-blue-500 hover:bg-blue-600 rounded text-white">
            {currentSection < sections.length - 1
              ? 'Next'
              : quiz
                ? 'Take Quiz'
                : 'Finish'}
          </button>
        </div>

        {/* (Optional) Quiz display as last step */}
        {quiz && currentSection === sections.length && (
          <div className="mt-8">
            {/* Pass quiz to your quiz panel */}
            {/* <QuizPanel quiz={quiz} ... /> */}
            <div>Quiz goes here!</div>
          </div>
        )}
      </div>
    </div>
  );
}
