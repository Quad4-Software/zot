import React, { useEffect, useState } from 'react';
import { api, endpoints } from '../../api';
import { host } from '../../host';
import { makeStyles } from 'theme';
import { Card, CardContent, Chip, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';
import { DateTime } from 'luxon';
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
  tableHeadCell: {
    color: theme.palette.text.secondary,
    fontWeight: 600,
    borderBottom: `1px solid ${theme.palette.divider}`
  },
  tableCell: {
    color: theme.palette.text.primary,
    borderBottom: `1px solid ${theme.palette.divider}`
  },
  subtext: {
    color: theme.palette.text.secondary
  }
}));

const relativeTime = (iso) => {
  if (!iso) return 'never';
  const dt = DateTime.fromISO(iso);
  return dt.isValid ? dt.toRelative() : iso;
};

function ScannerStatusCard() {
  const classes = useStyles();
  const [scanners, setScanners] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .get(`${host()}${endpoints.scannerStatus}`)
      .then((response) => setScanners(response.data?.scanners || []))
      .catch((err) => {
        if (err?.response?.status !== 501) {
          console.error(err);
        }
        setError(err?.response?.status);
      });
  }, []);

  if (error === 501) return null;

  const isStale = (scanner) => {
    if (!scanner.dbUpdatedAt) return false;
    const next = scanner.nextUpdate ? DateTime.fromISO(scanner.nextUpdate) : null;
    if (next?.isValid) return next < DateTime.now();
    return DateTime.fromISO(scanner.dbUpdatedAt) < DateTime.now().minus({ days: 2 });
  };

  return (
    <Card className={classes.card} data-testid="scanner-status-card">
      <CardContent>
        <Typography className={classes.cardTitle}>Scanner databases</Typography>
        {error && <Typography className={classes.subtext}>scanner status unavailable</Typography>}
        {!error && scanners === null && null}
        {!error && scanners !== null && (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell className={classes.tableHeadCell}>Scanner</TableCell>
                <TableCell className={classes.tableHeadCell}>DB version</TableCell>
                <TableCell className={classes.tableHeadCell}>Last update</TableCell>
                <TableCell className={classes.tableHeadCell}>State</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {scanners.map((scanner) => (
                <TableRow key={scanner.name}>
                  <TableCell className={classes.tableCell}>{scanner.name}</TableCell>
                  <TableCell className={classes.tableCell}>{scanner.dbVersion || '-'}</TableCell>
                  <TableCell className={classes.tableCell}>{relativeTime(scanner.dbUpdatedAt)}</TableCell>
                  <TableCell className={classes.tableCell}>
                    {scanner.error ? (
                      <Chip label="error" color="error" size="small" variant="outlined" title={scanner.error} />
                    ) : isStale(scanner) ? (
                      <Chip label="stale" color="warning" size="small" variant="outlined" />
                    ) : (
                      <Chip label="fresh" color="success" size="small" variant="outlined" />
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {isEmpty(scanners) && (
                <TableRow>
                  <TableCell className={classes.tableCell} colSpan={4}>
                    <Typography className={classes.subtext}>no scanners enabled</Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

export default ScannerStatusCard;
