import { useState } from 'react';
import { CheckCircle2, XCircle, ChevronRight } from 'lucide-react';

export default function QuizPanel({ quiz, onComplete, onSkip }) {
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [selectedAnswers, setSelectedAnswers] = useState({});
  const [showExplanation, setShowExplanation] = useState(false);
  const [completed, setCompleted] = useState(false);

  if (!quiz || !quiz.questions) {
    return (
      <div className="quiz-panel">
        <p>Loading quiz...</p>
      </div>
    );
  }

  const question = quiz.questions[currentQuestion];
  const selectedAnswer = selectedAnswers[currentQuestion];
  const isCorrect = question && selectedAnswer === question.correctIndex;

  const handleSelectAnswer = (index) => {
    if (!selectedAnswers.hasOwnProperty(currentQuestion)) {
      setSelectedAnswers(prev => ({
        ...prev,
        [currentQuestion]: index
      }));
      setShowExplanation(true);
    }
  };

  const handleNextQuestion = () => {
    if (currentQuestion < quiz.questions.length - 1) {
      setCurrentQuestion(currentQuestion + 1);
      setShowExplanation(false);
    } else {
      finishQuiz();
    }
  };

  const finishQuiz = () => {
    const correctCount = Object.entries(selectedAnswers).filter(
      ([qIdx, aIdx]) => quiz.questions[parseInt(qIdx)].correctIndex === aIdx
    ).length;
    const score = Math.round((correctCount / quiz.questions.length) * 100);
    
    setCompleted(true);
    onComplete({
      score,
      correctAnswers: correctCount,
      totalQuestions: quiz.questions.length
    });
  };

  if (completed) {
    const correctCount = Object.entries(selectedAnswers).filter(
      ([qIdx, aIdx]) => quiz.questions[parseInt(qIdx)].correctIndex === aIdx
    ).length;
    const score = Math.round((correctCount / quiz.questions.length) * 100);

    return (
      <div className="quiz-completed">
        <div className="quiz-result-header">
          {score === 100 ? (
            <>
              <CheckCircle2 size={48} className="result-icon success" />
              <h2>Perfect Score! 🎉</h2>
            </>
          ) : score >= 75 ? (
            <>
              <CheckCircle2 size={48} className="result-icon good" />
              <h2>Great Job! 👏</h2>
            </>
          ) : (
            <>
              <XCircle size={48} className="result-icon" />
              <h2>Keep Learning 📚</h2>
            </>
          )}
        </div>

        <div className="quiz-result-stats">
          <div className="result-stat">
            <span className="result-label">Score</span>
            <span className="result-value">{score}%</span>
          </div>
          <div className="result-stat">
            <span className="result-label">Correct</span>
            <span className="result-value">{correctCount}/{quiz.questions.length}</span>
          </div>
          <div className="result-stat">
            <span className="result-label">Bonus Points</span>
            <span className="result-value">{score === 100 ? '+5' : '+0'}</span>
          </div>
        </div>

        <button className="quiz-button" onClick={onSkip}>
          Close Quiz
        </button>
      </div>
    );
  }

  return (
    <div className="quiz-panel">
      <div className="quiz-header">
        <h2>📝 {quiz.title}</h2>
        <span className="quiz-progress">
          Question {currentQuestion + 1} of {quiz.questions.length}
        </span>
      </div>

      <div className="quiz-progress-bar">
        <div 
          className="quiz-progress-fill"
          style={{ width: `${((currentQuestion + 1) / quiz.questions.length) * 100}%` }}
        />
      </div>

      <div className="quiz-content">
        <h3 className="quiz-question">{question.question}</h3>

        <div className="quiz-options">
          {question.options.map((option, idx) => (
            <button
              key={idx}
              className={`quiz-option ${
                selectedAnswers.hasOwnProperty(currentQuestion)
                  ? idx === question.correctIndex
                    ? 'correct'
                    : idx === selectedAnswer
                    ? 'incorrect'
                    : ''
                  : ''
              } ${selectedAnswers.hasOwnProperty(currentQuestion) ? 'disabled' : ''}`}
              onClick={() => handleSelectAnswer(idx)}
              disabled={selectedAnswers.hasOwnProperty(currentQuestion)}
            >
              <span className="option-letter">
                {String.fromCharCode(65 + idx)}
              </span>
              <span className="option-text">{option}</span>
              {selectedAnswers.hasOwnProperty(currentQuestion) && (
                <>
                  {idx === question.correctIndex && (
                    <CheckCircle2 size={20} className="option-icon correct-icon" />
                  )}
                  {idx === selectedAnswer && idx !== question.correctIndex && (
                    <XCircle size={20} className="option-icon incorrect-icon" />
                  )}
                </>
              )}
            </button>
          ))}
        </div>

        {showExplanation && (
          <div className={`quiz-explanation ${isCorrect ? 'correct' : 'incorrect'}`}>
            <p className="explanation-title">
              {isCorrect ? '✓ Correct!' : '✗ Incorrect'}
            </p>
            <p className="explanation-text">{question.explanation}</p>
          </div>
        )}
      </div>

      {selectedAnswers.hasOwnProperty(currentQuestion) && (
        <button className="quiz-button" onClick={handleNextQuestion}>
          {currentQuestion < quiz.questions.length - 1 ? (
            <>
              Next Question <ChevronRight size={18} />
            </>
          ) : (
            'Finish Quiz'
          )}
        </button>
      )}
    </div>
  );
}
