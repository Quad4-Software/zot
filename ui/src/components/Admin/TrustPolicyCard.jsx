import React, { useEffect, useRef, useState } from 'react';
import { api, endpoints } from '../../api';
import { host } from '../../host';
import { makeStyles } from 'theme';
import { Button, Card, CardContent, Chip, Stack, Typography } from '@mui/material';
import UploadFileIcon from '@mui/icons-material/UploadFile';
import { isEmpty } from 'lodash';

const useStyles = makeStyles((theme) => ({
  card: {
    backgroundColor: theme.palette.background.paper,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: '0.75rem',
    boxShadow: 'none',
    marginBottom: '1.5rem'
  },
  cardTitle: {
    color: theme.palette.text.primary,
    fontWeight: 600,
    marginBottom: '0.75rem'
  },
  sectionTitle: {
    color: theme.palette.text.secondary,
    fontWeight: 600,
    fontSize: '0.875rem',
    marginBottom: '0.5rem'
  },
  infoGrid: {
    display: 'flex',
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  subtext: {
    color: theme.palette.text.secondary,
    fontSize: '0.8125rem'
  }
}));

function TrustPolicyCard({ trust }) {
  const classes = useStyles();
  const [cosignKeys, setCosignKeys] = useState(null);
  const [notationCerts, setNotationCerts] = useState(null);
  const [message, setMessage] = useState(null);
  const fileInput = useRef(null);
  const uploadTarget = useRef('cosign');

  const load = () => {
    if (trust?.cosign) {
      api
        .get(`${host()}${endpoints.cosignKeys}`)
        .then((response) => setCosignKeys(response.data?.keys || []))
        .catch((err) => {
          console.error(err);
          setCosignKeys([]);
        });
    }
    if (trust?.notation) {
      api
        .get(`${host()}${endpoints.notationCerts}`)
        .then((response) => setNotationCerts(response.data?.certificates || []))
        .catch((err) => {
          console.error(err);
          setNotationCerts([]);
        });
    }
  };

  useEffect(() => {
    load();
  }, []);

  const pickFile = (target) => {
    uploadTarget.current = target;
    fileInput.current?.click();
  };

  const onFile = (e) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    const endpoint = uploadTarget.current === 'cosign' ? endpoints.cosignKeys : endpoints.notationCerts;
    api
      .post(`${host()}${endpoint}`, file, {
        headers: { 'Content-Type': 'application/octet-stream' }
      })
      .then(() => {
        setMessage({ severity: 'success', text: `${file.name} uploaded` });
        load();
      })
      .catch((err) => {
        console.error(err);
        setMessage({ severity: 'error', text: `upload failed: ${err?.response?.status || err.message}` });
      });
  };

  if (!trust?.enabled) return null;

  return (
    <Card className={classes.card} data-testid="trust-policy-card">
      <CardContent>
        <Typography className={classes.cardTitle}>Image trust policy</Typography>
        <input type="file" hidden ref={fileInput} onChange={onFile} data-testid="trust-file-input" />
        <div className={classes.infoGrid} style={{ marginBottom: '1rem' }}>
          {trust.signedOnly && (
            <Chip label="signedOnly: unsigned tag pushes rejected" color="success" variant="outlined" />
          )}
          {trust.cosign && <Chip label="cosign" variant="outlined" />}
          {trust.notation && <Chip label="notation" variant="outlined" />}
        </div>
        {message && (
          <Typography className={classes.subtext} color={message.severity === 'error' ? 'error' : 'text.secondary'}>
            {message.text}
          </Typography>
        )}
        {trust.cosign && (
          <div style={{ marginBottom: '1rem' }}>
            <Typography className={classes.sectionTitle}>Cosign public keys</Typography>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Button
                size="small"
                variant="outlined"
                startIcon={<UploadFileIcon />}
                onClick={() => pickFile('cosign')}
                data-testid="upload-cosign-key"
              >
                Upload key
              </Button>
              {cosignKeys === null && <Typography className={classes.subtext}>loading...</Typography>}
              {cosignKeys !== null && isEmpty(cosignKeys) && (
                <Typography className={classes.subtext}>no keys uploaded</Typography>
              )}
              {cosignKeys?.map((key) => (
                <Chip key={key} label={key} size="small" variant="outlined" />
              ))}
            </Stack>
          </div>
        )}
        {trust.notation && (
          <div>
            <Typography className={classes.sectionTitle}>Notation certificates</Typography>
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap" useFlexGap>
              <Button
                size="small"
                variant="outlined"
                startIcon={<UploadFileIcon />}
                onClick={() => pickFile('notation')}
                data-testid="upload-notation-cert"
              >
                Upload certificate
              </Button>
              {notationCerts === null && <Typography className={classes.subtext}>loading...</Typography>}
              {notationCerts !== null && isEmpty(notationCerts) && (
                <Typography className={classes.subtext}>no certificates uploaded</Typography>
              )}
              {notationCerts?.map((cert) => (
                <Chip key={cert} label={cert} size="small" variant="outlined" />
              ))}
            </Stack>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export default TrustPolicyCard;
