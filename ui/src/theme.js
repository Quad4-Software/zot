import { createTheme } from '@mui/material/styles';
import { makeStyles as muiMakeStyles } from '@mui/styles';

// Quad4 brand palette, see https://quad4.io/branding
const quad4 = {
  dark: {
    canvas: '#0a0a0b',
    surface: '#101013',
    raised: '#16161a',
    fg: '#f4f4f5',
    muted: '#a1a1aa',
    faint: '#8f8f98',
    line: '#1f1f24',
    accent: '#fafafa',
    onAccent: '#0a0a0b'
  },
  light: {
    canvas: '#fafafa',
    surface: '#ffffff',
    raised: '#f4f4f5',
    fg: '#0a0a0b',
    muted: '#52525b',
    faint: '#52525b',
    line: '#d9d9de',
    accent: '#0a0a0b',
    onAccent: '#fafafa'
  }
};

export const buildTheme = (mode) => {
  const q = quad4[mode] || quad4.dark;

  const theme = createTheme({
    palette: {
      mode,
      primary: {
        main: q.accent,
        contrastText: q.onAccent
      },
      secondary: {
        main: q.muted,
        contrastText: q.fg
      },
      background: {
        default: q.canvas,
        paper: q.surface
      },
      text: {
        primary: q.fg,
        secondary: q.muted
      },
      divider: q.line,
      error: { main: mode === 'dark' ? '#f87171' : '#dc2626' },
      warning: { main: mode === 'dark' ? '#fb923c' : '#c2410c' },
      success: { main: mode === 'dark' ? '#4ade80' : '#16a34a' },
      info: { main: mode === 'dark' ? '#93c5fd' : '#1d4ed8' },
      quad4: {
        canvas: q.canvas,
        surface: q.surface,
        raised: q.raised,
        fg: q.fg,
        muted: q.muted,
        faint: q.faint,
        line: q.line,
        accent: q.accent,
        onAccent: q.onAccent,
        errorBg: mode === 'dark' ? '#2a1215' : '#feebee',
        successBg: mode === 'dark' ? '#12241a' : '#e8f5e9',
        warningBg: mode === 'dark' ? '#2a1a0d' : '#fff3e0',
        infoBg: mode === 'dark' ? '#101c2a' : '#e3f2fd'
      }
    },
    typography: {
      fontFamily: "'Space Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    },
    components: {
      MuiCssBaseline: {
        styleOverrides: {
          body: {
            backgroundColor: q.canvas
          }
        }
      }
    }
  });

  theme.typography.h4 = {
    fontSize: '2.5rem',
    [theme.breakpoints.down('sm')]: {
      fontSize: '1.5rem'
    }
  };

  return theme;
};

const defaultTheme = buildTheme('dark');

// makeStyles with a fallback theme so components render without a ThemeProvider
export const makeStyles = (stylesOrCreator, options = {}) =>
  muiMakeStyles(stylesOrCreator, { defaultTheme, ...options });
