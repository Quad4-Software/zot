import React from 'react';
import { makeStyles } from 'theme';
import logo from '../../assets/quad4-mark.svg';

const useStyles = makeStyles(() => ({
  wrapper: {
    position: 'relative',
    top: '10%',
    left: 0,
    right: 0,
    bottom: 0,
    zIndex: 10000,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    width: '100%',
    height: '100%'
  }
}));

const Loading = () => {
  const classes = useStyles();

  return (
    <div className={classes.wrapper}>
      <img src={logo} className="App-logo Loading" alt="logo" />
    </div>
  );
};

export default Loading;
