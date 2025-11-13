/**
 * Quizzes Index
 * 
 * Central export point for all post-scenario quizzes
 */

import bloodhoundQuiz from './bloodhoundQuiz.js';
import kerberoastQuiz from './kerberoastQuiz.js';
import asrepQuiz from './asrepQuiz.js';
import pthQuiz from './pthQuiz.js';

export const quizzes = [
  bloodhoundQuiz,
  kerberoastQuiz,
  asrepQuiz,
  pthQuiz
];

export const quizMap = {
  'bloodhound': bloodhoundQuiz,
  'kerberoasting': kerberoastQuiz,
  'asrep-roasting': asrepQuiz,
  'pass-the-hash': pthQuiz
};

export default quizzes;
