import React from 'react';
import { ThemeProvider } from '@mui/material/styles';

import { buildTheme } from '../theme';

const theme = buildTheme('dark');

function MockThemeProvider({ children }) {
  return <ThemeProvider theme={theme}>{children}</ThemeProvider>;
}

export default MockThemeProvider;
