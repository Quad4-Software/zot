// components
import React from 'react';
import Header from '../components/Header/Header.jsx';

import { makeStyles } from 'theme';
import { Container, Grid, Stack } from '@mui/material';
import Explore from 'components/Explore/Explore.jsx';
import { useState } from 'react';

const useStyles = makeStyles((theme) => ({
  container: {
    paddingTop: 30,
    paddingBottom: 5,
    height: '100%',
    minWidth: '60%'
  },
  gridWrapper: {
    border: `0.0625rem ${theme.palette.divider} dashed`
  },
  pageWrapper: {
    height: '100%'
  },
  tile: {
    width: '100%',
    padding: 5
  }
}));

function ExplorePage() {
  const classes = useStyles();
  const [searchCurrentValue, setSearchCurrentValue] = useState();

  return (
    <Stack className={classes.pageWrapper} direction="column" data-testid="explore-container">
      <Header setSearchCurrentValue={setSearchCurrentValue} />
      <Container className={classes.container}>
        <Grid container className={classes.gridWrapper}>
          <Grid item className={classes.tile}>
            <Explore searchInputValue={searchCurrentValue} />
          </Grid>
        </Grid>
      </Container>
    </Stack>
  );
}

export default ExplorePage;
