import React from 'react';

import { Dialog, DialogContent, DialogTitle, DialogActions, Button, Typography, Grid } from '@mui/material';

import { makeStyles } from 'theme';

const useStyles = makeStyles((theme) => ({
  gridWrapper: {
    paddingTop: '2rem',
    paddingBottom: '2rem'
  },
  apiKeyDisplay: {
    boxSizing: 'border-box',
    color: theme.palette.text.secondary,
    fontSize: '1rem',
    fontWeight: '400',
    padding: '0.75rem',
    backgroundColor: theme.palette.background.default,
    borderRadius: '0.9rem',
    overflowWrap: 'break-word'
  }
}));

function ApiKeyConfirmDialog(props) {
  const { open, setOpen, apiKey } = props;

  const classes = useStyles();

  const handleClose = () => {
    setOpen(false);
  };

  return (
    <Dialog open={open} onClose={handleClose}>
      <DialogTitle>Api Key &quot;{apiKey?.label}&quot; Created</DialogTitle>
      <DialogContent className={classes.apiKeyForm}>
        <Grid container className={classes.gridWrapper}>
          <Grid item xs={12}>
            <Typography>Please copy the api key, you will not be able to see it once the page is refreshed</Typography>
          </Grid>
          <Grid item xs={12}>
            <Typography variant="body1" align="center" className={classes.apiKeyDisplay}>
              {apiKey?.apiKey}
            </Typography>
          </Grid>
        </Grid>
      </DialogContent>
      <DialogActions>
        <Button variant="outlined" onClick={handleClose}>
          Close
        </Button>
      </DialogActions>
    </Dialog>
  );
}

export default ApiKeyConfirmDialog;
