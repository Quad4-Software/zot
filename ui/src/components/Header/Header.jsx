// react global
import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router';

import { isAuthenticated, isAuthenticationEnabled, getLoggedInUser, logoutUser } from '../../utilities/authUtilities';
import { useThemeMode } from 'utilities/ThemeModeProvider';

// components
import { AppBar, Toolbar, Grid, Button, IconButton, Tooltip } from '@mui/material';
import DarkModeIcon from '@mui/icons-material/DarkMode';
import LightModeIcon from '@mui/icons-material/LightMode';
import SearchSuggestion from './SearchSuggestion';
import UserAccountMenu from './UserAccountMenu';
// styling
import { makeStyles } from 'theme';
import logoDark from '../../assets/quad4-mark.svg';
import logoLight from '../../assets/quad4-mark-black.svg';

const useStyles = makeStyles((theme) => ({
  barOpen: {
    position: 'sticky',
    minHeight: '10%'
  },
  barClosed: {
    position: 'sticky',
    minHeight: '10%',
    backgroundColor: 'red'
  },
  header: {
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 0,
    backgroundColor: theme.palette.quad4.raised,
    height: '100%',
    width: '100%',
    borderBottom: `0.0625rem solid ${theme.palette.divider}`,
    boxShadow: '0rem 0.3125rem 0.625rem rgba(131, 131, 131, 0.08)'
  },
  headerContainer: {
    minWidth: '60%'
  },
  searchIcon: {
    color: theme.palette.text.secondary,
    paddingRight: '3%'
  },
  input: {
    color: theme.palette.text.primary,
    marginLeft: 1,
    width: '90%'
  },

  icons: {
    color: theme.palette.text.primary
  },
  appName: {
    marginLeft: 10,
    marginTop: 8,
    color: theme.palette.text.primary
  },
  logoWrapper: {},
  logo: {
    width: '2.25rem',
    height: '2.25rem',
    display: 'block'
  },
  headerLinkContainer: {
    [theme.breakpoints.down('md')]: {
      display: 'none'
    }
  },
  link: {
    color: theme.palette.text.primary,
    fontSize: '1rem',
    fontWeight: 600
  },
  grid: {
    display: 'flex',
    flexDirection: 'row',
    justifyContent: 'center',
    alignItems: 'center',
    height: '2.875rem',
    [theme.breakpoints.down('md')]: {
      justifyContent: 'space-between'
    }
  },
  gridItem: {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center'
  },
  signInBtn: {
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: '0.625rem',
    backgroundColor: 'transparent',
    color: theme.palette.text.primary,
    fontSize: '1rem',
    textTransform: 'none',
    fontWeight: 600
  }
}));

function setNavShow() {
  const [show, setShow] = useState(true);
  const [lastScrollY, setLastScrollY] = useState(null);

  const controlNavbar = () => {
    if (typeof window !== 'undefined') {
      if (window.scrollY < lastScrollY) {
        setShow(true);
      } else {
        setShow(false);
      }

      setLastScrollY(window.scrollY);
    }
  };

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.addEventListener('scroll', controlNavbar);

      return () => {
        window.removeEventListener('scroll', controlNavbar);
      };
    }
  }, [lastScrollY]);
  return show;
}

function Header({ setSearchCurrentValue = () => {} }) {
  const show = setNavShow();
  const classes = useStyles();
  const path = useLocation().pathname;
  const { mode, toggleMode } = useThemeMode();

  const handleSignInClick = () => {
    logoutUser();
  };

  return (
    <AppBar position={show ? 'fixed' : 'absolute'} sx={{ height: '5rem' }}>
      <Toolbar className={classes.header}>
        <Grid container className={classes.grid}>
          <Grid item container xs={3} md={4} spacing="1.5rem" className={classes.gridItem}>
            <Grid item>
              <Link to="/home">
                <img alt="Quad4" src={mode === 'dark' ? logoDark : logoLight} className={classes.logo} />
              </Link>
            </Grid>
            <Grid item className={classes.headerLinkContainer}>
              <a className={classes.link} href="https://quad4.io" target="_blank" rel="noreferrer">
                Quad4
              </a>
            </Grid>
            {(!isAuthenticationEnabled() || getLoggedInUser()) && (
              <Grid item className={classes.headerLinkContainer}>
                <Link to="/admin" className={classes.link}>
                  Admin
                </Link>
              </Grid>
            )}
          </Grid>
          <Grid item xs={6} md={4} className={classes.gridItem}>
            {path !== '/' && <SearchSuggestion setSearchCurrentValue={setSearchCurrentValue} />}
          </Grid>
          <Grid item container xs={2} md={3} spacing="1.5rem" className={`${classes.gridItem}`}>
            <Grid item>
              <Tooltip title={mode === 'dark' ? 'Light mode' : 'Dark mode'}>
                <IconButton
                  className={classes.icons}
                  onClick={toggleMode}
                  aria-label="toggle color theme"
                  data-testid="theme-toggle"
                >
                  {mode === 'dark' ? <LightModeIcon /> : <DarkModeIcon />}
                </IconButton>
              </Tooltip>
            </Grid>
            {isAuthenticated() && isAuthenticationEnabled() && (
              <Grid item>
                <UserAccountMenu />
              </Grid>
            )}
            {!isAuthenticated() && isAuthenticationEnabled() && (
              <Grid item>
                <Button className={classes.signInBtn} onClick={handleSignInClick}>
                  Sign in
                </Button>
              </Grid>
            )}
          </Grid>
        </Grid>
      </Toolbar>
    </AppBar>
  );
}

export default Header;
