// client/src/components/TheoryModal.jsx - COMPLETE VERSION WITH DIAGRAMS

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Book,
  ChevronRight,
  ChevronLeft,
  Check,
  AlertTriangle,
  Info,
  Shield,
  Clock,
  ExternalLink,
  Code,
  Lightbulb
} from 'lucide-react';
import { NetworkDiagram } from './diagrams';

export default function TheoryModal({ isOpen, onClose, module, onComplete }) {
  const [currentSection, setCurrentSection] = useState(0);
  const [completedSections, setCompletedSections] = useState(new Set());
  const [showQuiz, setShowQuiz] = useState(false);
  const [quizAnswers, setQuizAnswers] = useState({});
  const [quizSubmitted, setQuizSubmitted] = useState(false);

  // Reset state when module changes
  useEffect(() => {
    if (isOpen && module) {
      setCurrentSection(0);
      setCompletedSections(new Set());
      setShowQuiz(false);
      setQuizAnswers({});
      setQuizSubmitted(false);
    }
  }, [isOpen, module?.id]);

  if (!module) return null;

  const totalSections = module.sections?.length || 0;
  const progress = totalSections > 0 ? Math.round((completedSections.size / totalSections) * 100) : 0;

  const handleNext = () => {
    setCompletedSections(prev => new Set(prev).add(currentSection));
    
    if (currentSection < totalSections - 1) {
      setCurrentSection(currentSection + 1);
    } else if (module.quiz && !showQuiz) {
      setShowQuiz(true);
    }
  };

  const handlePrevious = () => {
    if (showQuiz) {
      setShowQuiz(false);
    } else if (currentSection > 0) {
      setCurrentSection(currentSection - 1);
    }
  };

  const handleQuizSubmit = () => {
    setQuizSubmitted(true);
    
    const allCorrect = module.quiz.every((q, idx) => quizAnswers[idx] === q.correct);
    
    if (allCorrect && onComplete) {
      setTimeout(() => {
        onComplete();
      }, 2000);
    }
  };

  const currentContent = showQuiz ? null : module.sections[currentSection];

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            onClick={(e) => e.stopPropagation()}
            className="relative bg-[#101214] rounded-xl border border-white/10 shadow-2xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-6 border-b border-white/10">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-[#2D9CDB]/20 flex items-center justify-center">
                  <Book className="w-5 h-5 text-[#2D9CDB]" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">{module.title}</h2>
                  <div className="flex items-center gap-3 mt-1">
                    <span className="text-xs text-white/60 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {module.estimatedTime}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      module.difficulty === 'Beginner' ? 'bg-green-500/20 text-green-400' :
                      module.difficulty === 'Intermediate' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-red-500/20 text-red-400'
                    }`}>
                      {module.difficulty}
                    </span>
                  </div>
                </div>
              </div>
              
              <button
                onClick={onClose}
                className="p-2 hover:bg-white/5 rounded-lg transition-colors"
              >
                <X className="w-5 h-5 text-white/60" />
              </button>
            </div>

            {/* Progress Bar */}
            <div className="px-6 pt-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-white/60">Progress</span>
                <span className="text-xs font-semibold text-[#2D9CDB]">{progress}%</span>
              </div>
              <div className="h-2 bg-white/5 rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${progress}%` }}
                  className="h-full bg-gradient-to-r from-[#2D9CDB] to-cyan-400"
                />
              </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              {showQuiz ? (
                <QuizSection
                  quiz={module.quiz}
                  answers={quizAnswers}
                  setAnswers={setQuizAnswers}
                  submitted={quizSubmitted}
                />
              ) : (
                <SectionContent 
                  section={currentContent} 
                  moduleData={module}
                  diagram={module.diagram}
                  currentSection={currentSection}
                />
              )}
            </div>

            {/* Footer Navigation */}
            <div className="flex items-center justify-between p-6 border-t border-white/10 bg-[#0a0b0d]">
              <button
                onClick={handlePrevious}
                disabled={currentSection === 0 && !showQuiz}
                className="flex items-center gap-2 px-4 py-2 bg-white/5 hover:bg-white/10 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg transition-all"
              >
                <ChevronLeft className="w-4 h-4" />
                Previous
              </button>

              <div className="text-sm text-white/60">
                {showQuiz ? 'Knowledge Check' : `Section ${currentSection + 1} of ${totalSections}`}
              </div>

              {showQuiz ? (
                <button
                  onClick={handleQuizSubmit}
                  disabled={Object.keys(quizAnswers).length !== module.quiz.length}
                  className="flex items-center gap-2 px-6 py-2 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg font-semibold transition-all"
                >
                  <Check className="w-4 h-4" />
                  Submit Quiz
                </button>
              ) : (
                <button
                  onClick={handleNext}
                  className="flex items-center gap-2 px-6 py-2 bg-[#2D9CDB] hover:bg-[#2D9CDB]/80 rounded-lg font-semibold transition-all"
                >
                  {currentSection === totalSections - 1 && module.quiz ? 'Take Quiz' : 'Next'}
                  <ChevronRight className="w-4 h-4" />
                </button>
              )}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// ============================================================================
// SECTION CONTENT COMPONENT - WITH INLINE DIAGRAM SUPPORT
// ============================================================================

function SectionContent({ section, moduleData, diagram, currentSection }) {
  if (!section) return null;

  // Show diagram after section 1 (usually "How It Works") or if section title contains "diagram"
  const shouldShowDiagram = diagram && (
    currentSection === 1 || 
    section.title?.toLowerCase().includes('diagram') ||
    section.title?.toLowerCase().includes('how it works')
  );

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-2xl font-bold text-white mb-4">{section.title}</h3>
        <p className="text-white/70 leading-relaxed whitespace-pre-line">{section.content}</p>
      </div>

      {/* INLINE DIAGRAM - NEW FEATURE */}
      {shouldShowDiagram && (
        <div className="my-6">
          <NetworkDiagram 
            diagramData={diagram} 
            height="450px"
            showMiniMap={true}
            showControls={true}
          />
        </div>
      )}

      {/* Key Points */}
      {section.keyPoints && section.keyPoints.length > 0 && (
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Lightbulb className="w-5 h-5 text-blue-400" />
            <h4 className="font-semibold text-blue-400">Key Takeaways</h4>
          </div>
          <ul className="space-y-2">
            {section.keyPoints.map((point, idx) => (
              <li key={idx} className="text-sm text-blue-300/80 flex items-start gap-2">
                <span className="text-blue-400 mt-1">•</span>
                <span>{point}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Code Example */}
      {section.example && (
        <div className="bg-[#0a0b0d] border border-white/10 rounded-lg overflow-hidden">
          <div className="bg-white/5 px-4 py-2 border-b border-white/10 flex items-center gap-2">
            <Code className="w-4 h-4 text-[#2D9CDB]" />
            <span className="text-sm font-semibold text-white">{section.example.title}</span>
          </div>
          <pre className="p-4 text-sm text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
            {section.example.code}
          </pre>
        </div>
      )}

      {/* Steps */}
      {section.steps && section.steps.length > 0 && (
        <div className="space-y-4">
          {section.steps.map((step, idx) => (
            <div key={idx} className="flex gap-4">
              <div className="w-8 h-8 rounded-full bg-[#2D9CDB]/20 flex items-center justify-center flex-shrink-0">
                <span className="text-sm font-bold text-[#2D9CDB]">{step.number}</span>
              </div>
              <div className="flex-1">
                <h5 className="font-semibold text-white mb-1">{step.title}</h5>
                <p className="text-sm text-white/60 mb-2">{step.description}</p>
                {step.commands && step.commands.length > 0 && (
                  <div className="bg-[#0a0b0d] border border-white/10 rounded p-2 space-y-1">
                    {step.commands.map((cmd, cmdIdx) => (
                      <code key={cmdIdx} className="text-xs text-green-400 font-mono block">
                        {cmd}
                      </code>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Defense Section */}
      {section.type === 'defensive' && section.detection && (
        <div className="space-y-4">
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-yellow-400" />
              <h4 className="font-semibold text-yellow-400">Detection Methods</h4>
            </div>
            <div className="space-y-2">
              {section.detection.logs?.map((log, idx) => (
                <div key={idx} className="text-sm text-yellow-300/80">• {log}</div>
              ))}
              {section.detection.indicators?.map((indicator, idx) => (
                <div key={idx} className="text-sm text-yellow-300/80">• {indicator}</div>
              ))}
            </div>
          </div>

          {section.prevention && section.prevention.length > 0 && (
            <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-3">
                <Shield className="w-5 h-5 text-green-400" />
                <h4 className="font-semibold text-green-400">Prevention Strategies</h4>
              </div>
              <div className="space-y-3">
                {section.prevention.map((prev, idx) => (
                  <div key={idx}>
                    <div className="font-semibold text-sm text-green-300">{prev.title}</div>
                    <div className="text-xs text-green-300/70 mt-1">{prev.description}</div>
                    {prev.example && (
                      <code className="text-xs text-green-400 mt-1 block bg-black/30 p-2 rounded">
                        {prev.example}
                      </code>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Resources - Show on last section */}
      {section.id === moduleData.sections[moduleData.sections.length - 1].id && moduleData.resources && (
        <div className="bg-white/5 border border-white/10 rounded-lg p-4">
          <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
            <ExternalLink className="w-4 h-4" />
            Additional Resources
          </h4>
          <div className="space-y-2">
            {moduleData.resources.map((resource, idx) => (
              <a
                key={idx}
                href={resource.url}
                target="_blank"
                rel="noopener noreferrer"
                className="block text-sm text-[#2D9CDB] hover:text-cyan-400 hover:underline"
              >
                {resource.title} →
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ============================================================================
// QUIZ SECTION COMPONENT
// ============================================================================

function QuizSection({ quiz, answers, setAnswers, submitted }) {
  const score = submitted ? quiz.filter((q, idx) => answers[idx] === q.correct).length : 0;
  const percentage = submitted ? Math.round((score / quiz.length) * 100) : 0;

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-2xl font-bold text-white mb-2">Knowledge Check</h3>
        <p className="text-white/60">Test your understanding of the concepts covered.</p>
      </div>

      {submitted && (
        <div className={`p-4 rounded-lg border ${
          percentage >= 80
            ? 'bg-green-500/10 border-green-500/20'
            : 'bg-yellow-500/10 border-yellow-500/20'
        }`}>
          <div className="flex items-center gap-2 mb-2">
            {percentage >= 80 ? (
              <Check className="w-5 h-5 text-green-400" />
            ) : (
              <Info className="w-5 h-5 text-yellow-400" />
            )}
            <span className={`font-semibold ${
              percentage >= 80 ? 'text-green-400' : 'text-yellow-400'
            }`}>
              Score: {score}/{quiz.length} ({percentage}%)
            </span>
          </div>
          <p className={`text-sm ${
            percentage >= 80 ? 'text-green-300/80' : 'text-yellow-300/80'
          }`}>
            {percentage >= 80
              ? 'Excellent! You have a solid understanding of the concepts.'
              : 'Review the explanations and try again to improve your understanding.'}
          </p>
        </div>
      )}

      <div className="space-y-6">
        {quiz.map((question, qIdx) => (
          <div key={qIdx} className="bg-white/5 rounded-lg p-4 border border-white/10">
            <h4 className="font-semibold text-white mb-3">
              {qIdx + 1}. {question.question}
            </h4>
            
            <div className="space-y-2">
              {question.options.map((option, oIdx) => {
                const isSelected = answers[qIdx] === oIdx;
                const isCorrect = oIdx === question.correct;
                const showResult = submitted;

                return (
                  <button
                    key={oIdx}
                    onClick={() => !submitted && setAnswers({ ...answers, [qIdx]: oIdx })}
                    disabled={submitted}
                    className={`w-full text-left p-3 rounded-lg border transition-all ${
                      showResult && isCorrect
                        ? 'bg-green-500/20 border-green-500/50'
                        : showResult && isSelected && !isCorrect
                        ? 'bg-red-500/20 border-red-500/50'
                        : isSelected
                        ? 'bg-[#2D9CDB]/20 border-[#2D9CDB]/50'
                        : 'bg-white/5 border-white/10 hover:border-white/20'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-white">{option}</span>
                      {showResult && isCorrect && (
                        <Check className="w-4 h-4 text-green-400" />
                      )}
                    </div>
                  </button>
                );
              })}
            </div>

            {submitted && (
              <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/20 rounded-lg">
                <p className="text-xs text-blue-300">{question.explanation}</p>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
