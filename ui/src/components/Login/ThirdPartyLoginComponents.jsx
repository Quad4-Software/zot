import React from 'react';

import Button from '@mui/material/Button';
import GitHubIcon from '@mui/icons-material/GitHub';

// styling
import { makeStyles } from 'theme';

const useStyles = makeStyles((theme) => ({
  githubButton: {
    textTransform: 'none',
    background: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    borderRadius: '0.25rem',
    padding: 0,
    height: '3.125rem',
    boxShadow: 'none',
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
      boxShadow: 'none'
    }
  },
  googleButton: {
    textTransform: 'none',
    background: theme.palette.background.paper,
    color: theme.palette.text.secondary,
    borderRadius: '0.25rem',
    border: `1px solid ${theme.palette.divider}`,
    padding: 0,
    height: '3.125rem',
    boxShadow: 'none',
    '&:hover': {
      backgroundColor: theme.palette.background.paper,
      boxShadow: 'none'
    }
  },
  buttonsText: {
    lineHeight: '2.125rem',
    height: '2.125rem',
    fontSize: '1.438rem',
    fontWeight: '600',
    letterSpacing: '0.01rem'
  }
}));

function GithubLoginButton({ handleClick }) {
  const classes = useStyles();

  return (
    <Button
      fullWidth
      variant="contained"
      className={classes.githubButton}
      endIcon={<GitHubIcon fontSize="medium" />}
      onClick={(e) => handleClick(e, 'github')}
    >
      <span className={classes.buttonsText}>Continue with Github</span>
    </Button>
  );
}

function GoogleLoginButton({ handleClick }) {
  const classes = useStyles();

  return (
    <Button fullWidth variant="contained" className={classes.googleButton} onClick={(e) => handleClick(e, 'google')}>
      <span className={classes.buttonsText}>Continue with Google</span>
    </Button>
  );
}

function GitlabLoginButton({ handleClick }) {
  const classes = useStyles();

  return (
    <Button fullWidth variant="contained" className={classes.button} onClick={(e) => handleClick(e, 'gitlab')}>
      Sign in with Gitlab
    </Button>
  );
}

function OIDCLoginButton({ handleClick, oidcName }) {
  const classes = useStyles();
  const loginWithName = oidcName || 'OIDC';

  return (
    <Button fullWidth variant="contained" className={classes.button} onClick={(e) => handleClick(e, 'oidc')}>
      Sign in with {loginWithName}
    </Button>
  );
}

export { GithubLoginButton, GoogleLoginButton, GitlabLoginButton, OIDCLoginButton };
