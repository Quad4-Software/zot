// components
import React from 'react';
import Header from '../components/Header/Header.jsx';

import { makeStyles } from 'theme';
import { Container, Grid, Stack } from '@mui/material';
import Home from 'components/Home/Home.jsx';

const useStyles = makeStyles((theme) => ({
  container: {
    paddingTop: 30,
    paddingBottom: 5,
    height: '100%',
    minWidth: '60%'
  },
  gridWrapper: {
    border: `0.0625em ${theme.palette.divider} dashed`
  },
  pageWrapper: {
    height: '100%'
  },
  tile: {
    width: '100%'
  }
}));

function HomePage() {
  const classes = useStyles();

  return (
    <Stack className={classes.pageWrapper} direction="column" data-testid="homepage-container">
      <Header />
      <Container className={classes.container}>
        <Grid container className={classes.gridWrapper}>
          <Grid item className={classes.tile}>
            <Home />
          </Grid>
        </Grid>
      </Container>
    </Stack>
  );
}

export default HomePage;
