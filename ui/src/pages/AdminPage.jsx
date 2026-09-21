// components
import React from 'react';
import Header from '../components/Header/Header.jsx';

import { makeStyles } from 'theme';
import { Container, Grid, Stack } from '@mui/material';
import Admin from 'components/Admin/Admin.jsx';

const useStyles = makeStyles(() => ({
  container: {
    paddingTop: 30,
    paddingBottom: 5,
    height: '100%',
    minWidth: '60%'
  },
  pageWrapper: {
    height: '100%'
  },
  tile: {
    width: '100%'
  }
}));

function AdminPage() {
  const classes = useStyles();

  return (
    <Stack className={classes.pageWrapper} direction="column" data-testid="adminpage-container">
      <Header />
      <Container className={classes.container}>
        <Grid container>
          <Grid item className={classes.tile}>
            <Admin />
          </Grid>
        </Grid>
      </Container>
    </Stack>
  );
}

export default AdminPage;
