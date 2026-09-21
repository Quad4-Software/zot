import React from 'react';

import { Stack, Typography } from '@mui/material';
import { makeStyles } from 'theme';

import logoWhite from '../../assets/quad4-mark.svg';

const useStyles = makeStyles((theme) => ({
  container: {
    backgroundColor: '#0a0a0b',
    backgroundImage:
      'radial-gradient(ellipse 80% 60% at 30% 20%, rgba(250, 250, 250, 0.06), transparent), radial-gradient(ellipse 60% 50% at 70% 80%, rgba(250, 250, 250, 0.04), transparent)',
    minHeight: '100%',
    width: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRight: `1px solid ${theme.palette.divider}`
  },
  contentContainer: {
    width: '51%',
    height: '22%'
  },
  logoContainer: {
    width: '100%',
    display: 'flex',
    justifyContent: 'center'
  },
  logo: {
    width: '56%'
  },
  mainText: {
    color: '#fafafa',
    fontWeight: '700',
    width: '100%',
    fontSize: '2.5rem',
    lineHeight: '3rem'
  },
  subText: {
    color: '#a1a1aa',
    width: '100%',
    fontSize: '1.125rem',
    lineHeight: '1.75rem'
  }
}));

export default function SigninPresentation() {
  const classes = useStyles();
  return (
    <div className={classes.container}>
      <Stack spacing={'2rem'} className={classes.contentContainer} data-testid="presentation-container">
        <div className={classes.logoContainer}>
          <img src={logoWhite} alt="Quad4 logo" className={classes.logo}></img>
        </div>
        <Typography variant="h2" className={classes.mainText}>
          OCI-native container image registry
        </Typography>
        <Typography variant="body1" className={classes.subText}>
          Signed, scanned and attested by default.
        </Typography>
      </Stack>
    </div>
  );
}
