/**
 * Design System Tokens
 * Centralized design constants for consistent styling across the app
 */

export const colors = {
  // Primary Colors
  primary: '#58a6ff',
  primaryLight: '#79c0ff',
  primaryDark: '#1f6feb',

  // Secondary Colors
  secondary: '#79c0ff',
  secondaryLight: '#a5d6ff',
  secondaryDark: '#388bfd',

  // Semantic Colors
  success: '#3fb950',
  warning: '#d29922',
  error: '#f85149',
  info: '#58a6ff',

  // Background Colors
  background: '#010409',
  surface: '#0d1117',
  surfaceAlt: '#161b22',
  surfaceHover: '#1a1f2e',

  // Text Colors
  textPrimary: '#c9d1d9',
  textSecondary: '#8b949e',
  textTertiary: '#6e7681',
  textInverse: '#000000',

  // Terminal Colors
  terminal: {
    bg: '#0d1117',
    text: '#c9d1d9',
    green: '#58a6ff',
    red: '#f85149',
    yellow: '#d29922',
    blue: '#58a6ff',
  },

  // Border Colors
  border: '#30363d',
  borderLight: '#21262d',
  borderDark: '#444c56',

  // Machine Colors
  attacker: '#ff4444',
  target: '#4444ff',
  dc: '#44ff44',
};

export const spacing = {
  xs: '4px',
  sm: '8px',
  md: '12px',
  lg: '16px',
  xl: '24px',
  xxl: '32px',
};

export const typography = {
  fontFamily: {
    mono: "'Consolas', 'Monaco', 'Courier New', monospace",
    sans: "'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif",
  },
  fontSize: {
    xs: '11px',
    sm: '12px',
    md: '13px',
    lg: '14px',
    xl: '16px',
    xxl: '18px',
    xxxl: '24px',
  },
  fontWeight: {
    regular: 400,
    medium: 500,
    semibold: 600,
    bold: 700,
  },
  lineHeight: {
    tight: 1.3,
    normal: 1.5,
    relaxed: 1.7,
  },
};

export const radius = {
  sm: '4px',
  md: '6px',
  lg: '8px',
  xl: '12px',
  full: '9999px',
};

export const shadows = {
  sm: '0 2px 4px rgba(0, 0, 0, 0.3)',
  md: '0 4px 12px rgba(0, 0, 0, 0.5)',
  lg: '0 8px 24px rgba(0, 0, 0, 0.6)',
  glow: '0 0 8px rgba(88, 166, 255, 0.6)',
  glowStrong: '0 0 15px rgba(88, 166, 255, 0.8)',
};

export const transitions = {
  fast: '0.15s ease',
  normal: '0.3s ease',
  slow: '0.5s ease',
};

export const breakpoints = {
  mobile: '480px',
  tablet: '768px',
  desktop: '1024px',
  wide: '1280px',
  ultraWide: '1920px',
};

// Component-specific tokens
export const componentTokens = {
  button: {
    padding: {
      sm: `${spacing.sm} ${spacing.md}`,
      md: `${spacing.md} ${spacing.lg}`,
      lg: `${spacing.lg} ${spacing.xl}`,
    },
    fontSize: typography.fontSize.md,
    borderRadius: radius.md,
    fontWeight: typography.fontWeight.semibold,
  },
  input: {
    padding: `${spacing.md} ${spacing.lg}`,
    fontSize: typography.fontSize.md,
    borderRadius: radius.md,
    borderWidth: '1px',
  },
  card: {
    padding: spacing.lg,
    borderRadius: radius.lg,
    borderWidth: '1px',
  },
  panel: {
    padding: spacing.lg,
    borderRadius: radius.lg,
    borderWidth: '1px',
  },
};
