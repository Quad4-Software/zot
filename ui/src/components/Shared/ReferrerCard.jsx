import React from 'react';
import { makeStyles } from 'theme';
import { Card, CardContent, Chip, Stack, Tooltip, Typography, Collapse, Box, Grid } from '@mui/material';
import { KeyboardArrowDown, KeyboardArrowRight } from '@mui/icons-material';
import { useState } from 'react';

const useStyles = makeStyles((theme) => ({
  refCard: {
    marginBottom: 2,
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    background: theme.palette.background.paper,
    boxShadow: 'none!important',
    borderRadius: '1.875rem',
    flex: 'none',
    alignSelf: 'stretch',
    flexGrow: 0,
    order: 0,
    width: '100%'
  },
  card: {
    marginBottom: '2rem',
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    background: theme.palette.background.paper,
    boxShadow: '0rem 0.3125rem 0.625rem rgba(131, 131, 131, 0.08)',
    borderRadius: '1.875rem',
    flex: 'none',
    alignSelf: 'stretch',
    flexGrow: 0,
    order: 0,
    width: '100%'
  },
  content: {
    textAlign: 'left',
    color: theme.palette.text.secondary,
    padding: '2% 3% 2% 3%',
    width: '100%'
  },
  clickCursor: {
    cursor: 'pointer'
  },
  cardText: {
    color: theme.palette.text.primary,
    fontSize: '1rem',
    paddingBottom: '0.5rem',
    paddingTop: '0.5rem',
    textOverflow: 'ellipsis'
  },
  dropdown: {
    flexDirection: 'row',
    alignItems: 'center'
  },
  dropdownText: {
    color: theme.palette.primary.main,
    paddingTop: '1rem',
    fontSize: '1rem',
    fontWeight: '600',
    cursor: 'pointer',
    textAlign: 'center'
  }
}));

const SIGNATURE_TYPES = [
  'application/vnd.dev.cosign.artifact.sig.v1+json',
  'application/vnd.cncf.notary.signature',
  'application/vnd.dev.sigstore.bundle'
];

const VEX_TYPES = ['application/vnd.openvex+json', 'text/vnd.openvex+json'];

const SBOM_TYPES = ['application/vnd.syft+json', 'application/spdx+json', 'application/vnd.cyclonedx+json'];

const classifyReferrer = (artifactType, mediaType, annotations) => {
  const types = [artifactType, mediaType].filter(Boolean).join(' ');
  const predicateType = annotations?.find((a) => a.key === 'dev.cosignproject.cosign/predicateType')?.value || '';
  if (SIGNATURE_TYPES.some((t) => types.includes(t))) return { label: 'Signature', color: 'success' };
  if (VEX_TYPES.some((t) => types.includes(t)) || predicateType.includes('openvex'))
    return { label: 'VEX', color: 'info' };
  if (
    SBOM_TYPES.some((t) => types.includes(t)) ||
    predicateType.includes('spdx') ||
    predicateType.includes('cyclonedx')
  )
    return { label: 'SBOM', color: 'info' };
  if (predicateType) return { label: 'Attestation', color: 'warning' };
  return { label: 'Artifact', color: 'default' };
};

const createdTimestamp = (annotations) =>
  annotations?.find((a) => a.key === 'org.opencontainers.image.created')?.value || null;

export default function ReferrerCard(props) {
  const { artifactType, mediaType, size, digest, annotations } = props;
  const [digestDropdownOpen, setDigestDropdownOpen] = useState(false);
  const [annotationDropdownOpen, setAnnotationDropdownOpen] = useState(false);
  const classes = useStyles();
  const kind = classifyReferrer(artifactType, mediaType, annotations);
  const created = createdTimestamp(annotations);

  return (
    <Card className={classes.card} raised>
      <CardContent className={classes.content}>
        <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ paddingBottom: '0.5rem' }}>
          <Chip label={kind.label} color={kind.color} size="small" variant="outlined" />
          {created && (
            <Tooltip title={created} placement="top">
              <Typography variant="caption" color="text.secondary">
                {created.slice(0, 16).replace('T', ' ')}
              </Typography>
            </Tooltip>
          )}
        </Stack>
        <Typography variant="body1" align="left" className={classes.cardText}>
          Type: {artifactType && `${artifactType}`}
        </Typography>
        <Typography variant="body1" align="left" className={classes.cardText}>
          Media type: {mediaType && `${mediaType}`}
        </Typography>
        <Typography variant="body1" align="left" className={classes.cardText}>
          Size: {size && `${size}`}
        </Typography>
        <Stack direction="row" onClick={() => setDigestDropdownOpen(!digestDropdownOpen)}>
          {!digestDropdownOpen ? (
            <KeyboardArrowRight className={classes.dropdownText} />
          ) : (
            <KeyboardArrowDown className={classes.dropdownText} />
          )}
          <Typography
            sx={{
              color: 'primary.main',
              paddingTop: '1rem',
              fontSize: '0.8125rem',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            DIGEST
          </Typography>
        </Stack>
        <Collapse in={digestDropdownOpen} timeout="auto" unmountOnExit>
          <Box>
            <Grid container item xs={12} direction={'row'}>
              <Tooltip title={digest || ''} placement="top">
                <Typography variant="body1">{digest}</Typography>
              </Tooltip>
            </Grid>
          </Box>
        </Collapse>

        <Stack direction="row" onClick={() => setAnnotationDropdownOpen(!annotationDropdownOpen)}>
          {!annotationDropdownOpen ? (
            <KeyboardArrowRight className={classes.dropdownText} />
          ) : (
            <KeyboardArrowDown className={classes.dropdownText} />
          )}
          <Typography
            sx={{
              color: 'primary.main',
              paddingTop: '1rem',
              fontSize: '0.8125rem',
              fontWeight: '600',
              cursor: 'pointer'
            }}
          >
            ANNOTATIONS
          </Typography>
        </Stack>
        <Collapse in={annotationDropdownOpen} timeout="auto" unmountOnExit>
          <Box>
            <Grid container item xs={12} direction={'row'}>
              <ul>
                {annotations?.map((annotation) => (
                  <li key={annotation.key}>
                    <Typography variant="body1">{`${annotation?.key}: ${annotation?.value}`}</Typography>
                  </li>
                ))}
              </ul>
            </Grid>
          </Box>
        </Collapse>
      </CardContent>
    </Card>
  );
}
