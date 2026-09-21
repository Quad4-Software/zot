import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';

import { buildTheme } from '../theme';

const STORAGE_KEY = 'quad4-theme';

const ThemeModeContext = createContext({ mode: 'dark', toggleMode: () => {} });

export const useThemeMode = () => useContext(ThemeModeContext);

const getInitialMode = () => {
  const saved = localStorage.getItem(STORAGE_KEY);
  return saved === 'light' ? 'light' : 'dark';
};

export function ThemeModeProvider({ children }) {
  const [mode, setMode] = useState(getInitialMode);

  const theme = useMemo(() => buildTheme(mode), [mode]);

  useEffect(() => {
    document.documentElement.dataset.theme = mode;
    document.documentElement.style.backgroundColor = theme.palette.background.default;
    localStorage.setItem(STORAGE_KEY, mode);
  }, [mode, theme]);

  const value = useMemo(() => ({ mode, toggleMode: () => setMode((m) => (m === 'dark' ? 'light' : 'dark')) }), [mode]);

  return (
    <ThemeModeContext.Provider value={value}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {children}
      </ThemeProvider>
    </ThemeModeContext.Provider>
  );
}
