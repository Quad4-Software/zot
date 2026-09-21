import React, { useState } from 'react';

import transform from 'utilities/transform';

import { Card, CardContent, Typography, Grid, Divider, Stack, Collapse, Tooltip, ButtonBase } from '@mui/material';
import { KeyboardArrowDown, KeyboardArrowRight } from '@mui/icons-material';

import { makeStyles } from 'theme';

const useStyles = makeStyles((theme) => ({
  card: {
    marginBottom: 2,
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: theme.palette.background.paper,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: '0.75rem',
    alignSelf: 'stretch',
    flexGrow: 0,
    order: 0,
    width: '100%'
  },
  content: {
    textAlign: 'left',
    color: theme.palette.text.secondary,
    width: '100%',
    boxSizing: 'border-box',
    padding: '1rem',
    backgroundColor: theme.palette.background.paper,
    '&:hover': {
      backgroundColor: theme.palette.background.paper
    },
    '&:last-child': {
      paddingBottom: '1rem'
    }
  },
  fileName: {
    fontSize: '1rem',
    fontWeight: '400',
    paddingRight: '0.5rem',
    paddingBottom: '0.5rem',
    paddingTop: '0.5rem',
    textAlign: 'left',
    width: '100%',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis'
  },
  values: {
    fontSize: '1rem',
    fontWeight: '400',
    paddingBottom: '0.5rem',
    paddingTop: '0.5rem',
    textAlign: 'right'
  },
  dropdownText: {
    color: theme.palette.primary.main,
    paddingTop: '1rem',
    fontSize: '1rem',
    fontWeight: '600',
    cursor: 'pointer',
    textAlign: 'center'
  },
  dropdownButton: {
    color: theme.palette.primary.main,
    paddingTop: '1rem',
    fontSize: '0.8125rem',
    fontWeight: '600',
    cursor: 'pointer'
  },
  dropdownContentBox: {
    boxSizing: 'border-box',
    color: theme.palette.text.secondary,
    fontSize: '1rem',
    fontWeight: '400',
    padding: '0.75rem',
    backgroundColor: theme.palette.background.default,
    borderRadius: '0.9rem',
    overflowWrap: 'break-word'
  },
  divider: {
    margin: '1rem 0'
  }
}));

function ArtifactFileCard(props) {
  const classes = useStyles();
  const { layer } = props;
  const [open, setOpen] = useState(false);

  const title = layer?.digest || '';
  const detailsId = `artifact-file-details-${(layer?.digest || 'unknown').replace(/[^a-zA-Z0-9_-]/g, '-')}`;

  return (
    <Card variant="outlined" className={classes.card} data-testid="artifact-file-card">
      <CardContent className={classes.content}>
        <Grid container alignItems="center" justifyContent="space-between">
          <Grid item xs={10}>
            <Tooltip title={title} placement="top">
              <Typography variant="body1" className={classes.fileName}>
                {title}
              </Typography>
            </Tooltip>
          </Grid>
          <Grid item xs={2}>
            <Typography variant="body1" className={classes.values}>
              {transform.formatBytes(layer?.size)}
            </Typography>
          </Grid>
          <Grid item xs={12}>
            <Divider className={classes.divider} />
          </Grid>
          <Grid item xs={12}>
            <ButtonBase onClick={() => setOpen((prev) => !prev)} aria-expanded={open} aria-controls={detailsId}>
              <Stack direction="row">
                {!open ? (
                  <KeyboardArrowRight className={classes.dropdownText} />
                ) : (
                  <KeyboardArrowDown className={classes.dropdownText} />
                )}
                <Typography className={classes.dropdownButton}>DETAILS</Typography>
              </Stack>
            </ButtonBase>
            <Collapse id={detailsId} in={open} timeout="auto" unmountOnExit sx={{ marginTop: '1rem' }}>
              <Stack direction="column" spacing="1.2rem">
                <Typography variant="body1">DIGEST</Typography>
                <Typography variant="body1" align="left" className={classes.dropdownContentBox}>
                  {layer?.digest}
                </Typography>
              </Stack>
            </Collapse>
          </Grid>
        </Grid>
      </CardContent>
    </Card>
  );
}

export default ArtifactFileCard;
