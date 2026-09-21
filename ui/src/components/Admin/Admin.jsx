import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';

// utility
import { api, endpoints } from '../../api';
import { host } from '../../host';
import transform from 'utilities/transform';
import { mapSignatureInfo } from 'utilities/objectModels';
import { SignatureIconCheck, VulnerabilityChipCheck } from 'utilities/vulnerabilityAndSignatureCheck';
import { isEmpty } from 'lodash';

// components
import {
  Alert,
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Snackbar,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Typography
} from '@mui/material';
import AdminPanelSettingsIcon from '@mui/icons-material/AdminPanelSettings';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import RefreshIcon from '@mui/icons-material/Refresh';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import LabelIcon from '@mui/icons-material/Label';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import CleaningServicesIcon from '@mui/icons-material/CleaningServices';
import BugReportIcon from '@mui/icons-material/BugReport';
import HistoryIcon from '@mui/icons-material/History';
import GridOnIcon from '@mui/icons-material/GridOn';
import DeleteTag from 'components/Shared/DeleteTag';
import Loading from 'components/Shared/Loading';
import ScannerStatusCard from './ScannerStatusCard';
import TrustPolicyCard from './TrustPolicyCard';

// styling
import { makeStyles } from 'theme';

const useStyles = makeStyles((theme) => ({
  pageWrapper: {
    width: '100%',
    paddingBottom: '2rem'
  },
  titleRow: {
    display: 'flex',
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '1.5rem'
  },
  title: {
    color: theme.palette.text.primary,
    fontWeight: 700,
    display: 'flex',
    alignItems: 'center',
    gap: '0.75rem'
  },
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
  infoGrid: {
    display: 'flex',
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: '0.5rem'
  },
  table: {
    backgroundColor: theme.palette.background.paper,
    border: `1px solid ${theme.palette.divider}`,
    borderRadius: '0.75rem'
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
  tagRow: {
    backgroundColor: theme.palette.quad4.canvas
  },
  link: {
    color: theme.palette.text.primary
  },
  icons: {
    color: theme.palette.text.primary
  },
  pagination: {
    display: 'flex',
    justifyContent: 'flex-end',
    gap: '0.5rem',
    marginTop: '1rem'
  },
  errorText: {
    color: theme.palette.error.main
  }
}));

const PAGE_SIZE = 15;

const MANIFEST_ACCEPT = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
  'application/vnd.docker.distribution.manifest.v2+json'
].join(',');

function LabelsButton({ repo, tag }) {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [labels, setLabels] = useState(null);
  const [error, setError] = useState(null);

  const load = () => {
    setLabels(null);
    setError(null);
    setOpen(true);

    const manifestCfg = { ...api.getRequestCfg(), headers: { Accept: MANIFEST_ACCEPT } };
    api
      .get(`${host()}/v2/${repo}/manifests/${tag}`, null, manifestCfg)
      .then(async (response) => {
        const manifest = response.data;
        let found = { ...(manifest?.annotations || {}) };
        const mediaType = manifest?.mediaType || '';
        // image indexes carry annotations; single manifests may also have
        // labels baked into the config blob
        if (!mediaType.includes('index') && !mediaType.includes('manifest.list') && manifest?.config?.digest) {
          const configRes = await api.get(
            `${host()}/v2/${repo}/blobs/${manifest.config.digest}`,
            null,
            api.getRequestCfg()
          );
          found = { ...(configRes.data?.config?.Labels || {}), ...found };
        }
        setLabels(found);
      })
      .catch((err) => {
        console.error(err);
        setError('failed to load labels');
      });
  };

  return (
    <>
      <Tooltip title="Image labels">
        <IconButton className={classes.icons} size="small" onClick={load} data-testid={`labels-${tag}`}>
          <LabelIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          {repo}:{tag}
        </DialogTitle>
        <DialogContent>
          {error && <Typography className={classes.errorText}>{error}</Typography>}
          {!error && labels === null && <Loading />}
          {!error && labels !== null && isEmpty(labels) && <Typography>no labels on this image</Typography>}
          {!error && !isEmpty(labels) && (
            <Table size="small">
              <TableBody>
                {Object.entries(labels).map(([key, value]) => (
                  <TableRow key={key}>
                    <TableCell
                      className={classes.tableCell}
                      sx={{ fontFamily: "'Space Mono', monospace", fontSize: '0.8rem', width: '45%' }}
                    >
                      {key}
                    </TableCell>
                    <TableCell
                      className={classes.tableCell}
                      sx={{ fontFamily: "'Space Mono', monospace", fontSize: '0.8rem', wordBreak: 'break-all' }}
                    >
                      {value}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function ScannerReportButton({ repo, tag }) {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);

  const load = () => {
    setReport(null);
    setError(null);
    setOpen(true);

    api
      .get(`${host()}${endpoints.cveScanReport(repo, tag)}`)
      .then((response) => setReport(response.data))
      .catch((err) => {
        console.error(err);
        const status = err?.response?.status;
        setError(
          status === 403
            ? 'admin access required'
            : status === 501
              ? 'cve scanning is not enabled on this server'
              : 'failed to load scan report'
        );
      });
  };

  const scannerNames = report ? Object.keys(report.scanners || {}) : [];
  const onlyIn = report?.onlyIn || {};
  const common = report?.common || [];
  const vexSuppressed = report?.vexSuppressed || {};
  const hasDisagreement = Object.values(onlyIn).some((ids) => !isEmpty(ids));

  return (
    <>
      <Tooltip title="Per-scanner CVE report">
        <IconButton className={classes.icons} size="small" onClick={load} data-testid={`scan-report-${tag}`}>
          <BugReportIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {repo}:{tag} scan report
        </DialogTitle>
        <DialogContent>
          {error && <Typography className={classes.errorText}>{error}</Typography>}
          {!error && report === null && <Loading />}
          {!error && report !== null && (
            <>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell className={classes.tableHeadCell}>Scanner</TableCell>
                    <TableCell className={classes.tableHeadCell}>Status</TableCell>
                    <TableCell className={classes.tableHeadCell}>CVEs</TableCell>
                    <TableCell className={classes.tableHeadCell}>Max severity</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {scannerNames.map((name) => {
                    const r = report.scanners[name];
                    return (
                      <TableRow key={name} className={classes.tagRow}>
                        <TableCell className={classes.tableCell}>{name}</TableCell>
                        <TableCell className={classes.tableCell}>
                          {r.scanned ? 'scanned' : r.error || 'no result'}
                        </TableCell>
                        <TableCell className={classes.tableCell}>{r.scanned ? r.count : '-'}</TableCell>
                        <TableCell className={classes.tableCell}>
                          {r.scanned && r.maxSeverity ? (
                            <VulnerabilityChipCheck vulnerabilitySeverity={r.maxSeverity} />
                          ) : (
                            '-'
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
              <div className={classes.infoGrid} style={{ marginTop: '1rem' }}>
                <Chip label={`${common.length} reported by all scanners`} variant="outlined" />
                {hasDisagreement ? (
                  scannerNames
                    .filter((name) => !isEmpty(onlyIn[name]))
                    .map((name) => (
                      <Chip
                        key={name}
                        color="warning"
                        variant="outlined"
                        label={`${onlyIn[name].length} only in ${name}`}
                      />
                    ))
                ) : (
                  <Chip label="no disagreements" variant="outlined" />
                )}
              </div>
              {hasDisagreement &&
                scannerNames
                  .filter((name) => !isEmpty(onlyIn[name]))
                  .map((name) => (
                    <div key={name} style={{ marginTop: '1rem' }}>
                      <Typography className={classes.cardTitle}>Only in {name}</Typography>
                      <div className={classes.infoGrid}>
                        {onlyIn[name].map((id) => (
                          <Chip key={id} label={id} size="small" variant="outlined" />
                        ))}
                      </div>
                    </div>
                  ))}
              {!isEmpty(vexSuppressed) && (
                <div style={{ marginTop: '1rem' }}>
                  <Typography className={classes.cardTitle}>Suppressed by VEX statements</Typography>
                  <div className={classes.infoGrid}>
                    {Object.entries(vexSuppressed).map(([id, status]) => (
                      <Chip key={id} label={`${id} (${status})`} size="small" color="success" variant="outlined" />
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function TagHistoryButton({ repo }) {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [history, setHistory] = useState(null);
  const [error, setError] = useState(null);

  const load = () => {
    setHistory(null);
    setError(null);
    setOpen(true);

    api
      .get(`${host()}${endpoints.tagHistory(repo)}`)
      .then((response) => setHistory(response.data?.history || []))
      .catch((err) => {
        console.error(err);
        const status = err?.response?.status;
        setError(
          status === 403
            ? 'admin access required'
            : status === 501
              ? 'tag history is not supported by this metadb backend'
              : 'failed to load tag history'
        );
      });
  };

  return (
    <>
      <Tooltip title="Tag history">
        <IconButton className={classes.icons} size="small" onClick={load} data-testid={`tag-history-${repo}`}>
          <HistoryIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{repo} tag history</DialogTitle>
        <DialogContent>
          {error && <Typography className={classes.errorText}>{error}</Typography>}
          {!error && history === null && <Loading />}
          {!error && history !== null && isEmpty(history) && (
            <Typography className={classes.errorText}>no recorded tag movements</Typography>
          )}
          {!error && !isEmpty(history) && (
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell className={classes.tableHeadCell}>When</TableCell>
                  <TableCell className={classes.tableHeadCell}>Tag</TableCell>
                  <TableCell className={classes.tableHeadCell}>Action</TableCell>
                  <TableCell className={classes.tableHeadCell}>Digest</TableCell>
                  <TableCell className={classes.tableHeadCell}>By</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {history.map((entry, index) => (
                  <TableRow key={`${entry.timestamp}-${index}`} className={classes.tagRow}>
                    <TableCell className={classes.tableCell}>
                      {entry.timestamp?.slice(0, 19).replace('T', ' ')}
                    </TableCell>
                    <TableCell className={classes.tableCell}>{entry.tag}</TableCell>
                    <TableCell className={classes.tableCell}>
                      <Chip
                        label={entry.action}
                        size="small"
                        variant="outlined"
                        color={entry.action === 'delete' ? 'error' : 'default'}
                      />
                    </TableCell>
                    <TableCell className={classes.tableCell}>
                      <Tooltip title={entry.digest} placement="top">
                        <span>{entry.digest?.slice(0, 19)}</span>
                      </Tooltip>
                    </TableCell>
                    <TableCell className={classes.tableCell}>{entry.user || '-'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function ScanMatrixButton({ repo }) {
  const classes = useStyles();
  const [open, setOpen] = useState(false);
  const [rows, setRows] = useState(null);
  const [scannerNames, setScannerNames] = useState([]);
  const [error, setError] = useState(null);

  const load = () => {
    setRows(null);
    setError(null);
    setOpen(true);

    api
      .get(`${host()}${endpoints.detailedRepoInfo(repo)}`)
      .then((response) => {
        const images = response.data?.data?.ExpandedRepoInfo?.Images || [];
        const tags = images.map((img) => img.Tag).filter(Boolean);

        return Promise.all(
          tags.map((tag) =>
            api
              .get(`${host()}${endpoints.cveScanReport(repo, tag, { cached: true })}`)
              .then((r) => ({ tag, scanners: r.data?.scanners || {} }))
              .catch(() => ({ tag, scanners: null }))
          )
        );
      })
      .then((tagRows) => {
        const names = [...new Set(tagRows.flatMap((row) => Object.keys(row.scanners || {})))];
        setScannerNames(names);
        setRows(tagRows);
      })
      .catch((err) => {
        console.error(err);
        setError('failed to load scan matrix');
      });
  };

  return (
    <>
      <Tooltip title="Scanner severity matrix (cached)">
        <IconButton className={classes.icons} size="small" onClick={load} data-testid={`scan-matrix-${repo}`}>
          <GridOnIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{repo} scanner matrix</DialogTitle>
        <DialogContent>
          {error && <Typography className={classes.errorText}>{error}</Typography>}
          {!error && rows === null && <Loading />}
          {!error && rows !== null && (
            <>
              <Typography sx={{ color: 'text.secondary', fontSize: '0.8125rem', marginBottom: '0.75rem' }}>
                Cached results only. Cells show each scanner&apos;s max severity per tag.
              </Typography>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell className={classes.tableHeadCell}>Tag</TableCell>
                    {scannerNames.map((name) => (
                      <TableCell key={name} className={classes.tableHeadCell}>
                        {name}
                      </TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.map((row) => (
                    <TableRow key={row.tag} className={classes.tagRow}>
                      <TableCell className={classes.tableCell}>{row.tag}</TableCell>
                      {scannerNames.map((name) => {
                        const cell = row.scanners?.[name];
                        return (
                          <TableCell key={name} className={classes.tableCell}>
                            {cell === undefined ? (
                              <Typography sx={{ color: 'text.secondary' }}>-</Typography>
                            ) : cell?.error ? (
                              <Chip
                                label={cell.error === 'not scanned' ? 'not scanned' : 'error'}
                                size="small"
                                variant="outlined"
                              />
                            ) : (
                              <VulnerabilityChipCheck vulnerabilitySeverity={cell.maxSeverity || 'NONE'} />
                            )}
                          </TableCell>
                        );
                      })}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </>
          )}
        </DialogContent>
      </Dialog>
    </>
  );
}

function TagRows({ repo }) {
  const classes = useStyles();
  const [images, setImages] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    api
      .get(`${host()}${endpoints.detailedRepoInfo(repo)}`)
      .then((response) => {
        setImages(response.data?.data?.ExpandedRepoInfo?.Images || []);
      })
      .catch((err) => {
        console.error(err);
        setError('failed to load tags');
      });
  }, [repo]);

  if (error) {
    return (
      <TableRow>
        <TableCell colSpan={7} className={classes.tableCell}>
          <Typography className={classes.errorText}>{error}</Typography>
        </TableCell>
      </TableRow>
    );
  }

  if (images === null) {
    return (
      <TableRow>
        <TableCell colSpan={7} className={classes.tableCell}>
          <Loading />
        </TableCell>
      </TableRow>
    );
  }

  if (isEmpty(images)) {
    return (
      <TableRow>
        <TableCell colSpan={7} className={classes.tableCell}>
          <Typography className={classes.errorText}>no tags found</Typography>
        </TableCell>
      </TableRow>
    );
  }

  return images.map((image) => (
    <TableRow key={`${repo}:${image.Tag}-${image.Digest}`} className={classes.tagRow}>
      <TableCell className={classes.tableCell}></TableCell>
      <TableCell className={classes.tableCell}>{image.Tag}</TableCell>
      <TableCell className={classes.tableCell} sx={{ fontFamily: "'Space Mono', monospace", fontSize: '0.8rem' }}>
        {image.Digest?.slice(0, 19)}
      </TableCell>
      <TableCell className={classes.tableCell}>
        {transform.formatBytes(Number(image.Manifests?.reduce((acc, m) => acc + Number(m.Size || 0), 0) || 0))}
      </TableCell>
      <TableCell className={classes.tableCell}>
        {image.Vulnerabilities?.MaxSeverity != null && (
          <VulnerabilityChipCheck vulnerabilitySeverity={image.Vulnerabilities.MaxSeverity} />
        )}
      </TableCell>
      <TableCell className={classes.tableCell}>
        <SignatureIconCheck signatureInfo={image.SignatureInfo?.map((si) => mapSignatureInfo(si))} />
      </TableCell>
      <TableCell className={classes.tableCell} align="right">
        <LabelsButton repo={repo} tag={image.Tag} />
        <ScannerReportButton repo={repo} tag={image.Tag} />
        {image.IsDeletable && (
          <DeleteTag
            repo={repo}
            tag={image.Tag}
            onTagDelete={() => setImages((prev) => prev.filter((i) => i.Tag !== image.Tag))}
          />
        )}
      </TableCell>
    </TableRow>
  ));
}

function Admin() {
  const classes = useStyles();
  const [serverInfo, setServerInfo] = useState(null);
  const [repos, setRepos] = useState([]);
  const [page, setPage] = useState(1);
  const [expanded, setExpanded] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [gcRunning, setGcRunning] = useState(false);
  const [snack, setSnack] = useState({ open: false, severity: 'info', message: '' });

  const loadServerInfo = () => {
    api
      .get(`${host()}${endpoints.authConfig}`)
      .then((response) => setServerInfo(response.data))
      .catch((err) => console.error(err));
  };

  const loadRepos = (pageNumber = page) => {
    setLoading(true);
    api
      .get(`${host()}${endpoints.repoList({ pageNumber, pageSize: PAGE_SIZE })}`)
      .then((response) => {
        setRepos(response.data?.data?.RepoListWithNewestImage?.Results || []);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError('failed to load repositories');
        setLoading(false);
      });
  };

  useEffect(() => {
    loadServerInfo();
    loadRepos(1);
  }, []);

  const authMethods = () => {
    const auth = serverInfo?.http?.auth;
    if (!auth) return 'none';
    const methods = [];
    if (auth.htpasswd) methods.push('htpasswd');
    if (auth.bearer) methods.push('bearer');
    if (auth.ldap) methods.push('ldap');
    if (auth.apikey) methods.push('apikey');
    if (auth.openid?.providers) methods.push(...Object.keys(auth.openid.providers));
    if (auth.allowAnonymousAccess) methods.push('anonymous');
    return methods.length ? methods.join(', ') : 'none';
  };

  const runGC = () => {
    setGcRunning(true);
    api
      .post(`${host()}${endpoints.runGC}`)
      .then(() => setSnack({ open: true, severity: 'success', message: 'Garbage collection started' }))
      .catch((err) => {
        const status = err?.response?.status;
        const message =
          status === 403
            ? 'Admin access required to run GC'
            : status === 409
              ? 'A GC run is already in progress'
              : 'Failed to start GC';
        setSnack({ open: true, severity: 'error', message });
      })
      .finally(() => setGcRunning(false));
  };

  return (
    <div className={classes.pageWrapper} data-testid="admin-container">
      <div className={classes.titleRow}>
        <Typography variant="h4" className={classes.title}>
          <AdminPanelSettingsIcon fontSize="large" /> Admin
        </Typography>
        <Tooltip title="Refresh">
          <IconButton className={classes.icons} onClick={() => loadRepos(page)} data-testid="admin-refresh">
            <RefreshIcon />
          </IconButton>
        </Tooltip>
      </div>

      {serverInfo && (
        <Card className={classes.card}>
          <CardContent>
            <Typography className={classes.cardTitle}>Server</Typography>
            <div className={classes.infoGrid}>
              <Chip label={`version ${serverInfo.releaseTag || 'dev'}`} variant="outlined" />
              <Chip label={`commit ${serverInfo.commit?.slice(0, 7) || 'unknown'}`} variant="outlined" />
              <Chip label={`${serverInfo.binaryType || ''} build`} variant="outlined" />
              <Chip label={`dist-spec ${serverInfo.distSpecVersion || ''}`} variant="outlined" />
              <Chip label={`auth: ${authMethods()}`} variant="outlined" />
              {serverInfo.http?.auth?.apikey && (
                <Chip
                  icon={<VpnKeyIcon />}
                  label="API keys"
                  variant="outlined"
                  component={Link}
                  to="/user/apikey"
                  clickable
                />
              )}
            </div>
          </CardContent>
        </Card>
      )}

      <ScannerStatusCard />
      <TrustPolicyCard trust={serverInfo?.trust} />

      {serverInfo?.storage && (serverInfo.storage.gc || !isEmpty(serverInfo.storage.retention)) && (
        <Card className={classes.card}>
          <CardContent>
            <Typography className={classes.cardTitle}>Garbage collection</Typography>
            <div className={classes.infoGrid}>
              <Chip label={`gc: ${serverInfo.storage.gc ? 'enabled' : 'disabled'}`} variant="outlined" />
              {serverInfo.storage.gcInterval && (
                <Chip label={`interval ${serverInfo.storage.gcInterval}`} variant="outlined" />
              )}
              <Chip label={`dedupe: ${serverInfo.storage.dedupe ? 'on' : 'off'}`} variant="outlined" />
            </div>
            {!isEmpty(serverInfo.storage.retention) && (
              <Table size="small" sx={{ marginTop: '1rem' }}>
                <TableHead>
                  <TableRow>
                    <TableCell className={classes.tableHeadCell}>Repositories</TableCell>
                    <TableCell className={classes.tableHeadCell}>Rules</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {serverInfo.storage.retention.map((policy, idx) => (
                    <TableRow key={idx}>
                      <TableCell
                        className={classes.tableCell}
                        sx={{ fontFamily: "'Space Mono', monospace", fontSize: '0.8rem' }}
                      >
                        {(policy.repositories || []).join(', ') || '**'}
                      </TableCell>
                      <TableCell className={classes.tableCell}>
                        {[
                          policy.keepTags > 0
                            ? `keep ${policy.keepTags} tag rule${policy.keepTags > 1 ? 's' : ''}`
                            : null,
                          policy.deleteUntagged ? 'delete untagged' : null,
                          policy.deleteReferrers ? 'delete referrers' : null
                        ]
                          .filter(Boolean)
                          .join(', ') || 'none'}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            {serverInfo.storage.gc && (
              <Button
                variant="outlined"
                size="small"
                startIcon={<CleaningServicesIcon />}
                disabled={gcRunning}
                onClick={runGC}
                sx={{ marginTop: '1rem' }}
                data-testid="run-gc"
              >
                Run GC now
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      <Card className={classes.card}>
        <CardContent>
          <Typography className={classes.cardTitle}>Repositories</Typography>
          {error && <Typography className={classes.errorText}>{error}</Typography>}
          <TableContainer>
            <Table className={classes.table} size="small">
              <TableHead>
                <TableRow>
                  <TableCell className={classes.tableHeadCell}></TableCell>
                  <TableCell className={classes.tableHeadCell}>Name</TableCell>
                  <TableCell className={classes.tableHeadCell}>Latest tag</TableCell>
                  <TableCell className={classes.tableHeadCell}>Size</TableCell>
                  <TableCell className={classes.tableHeadCell} align="right">
                    Actions
                  </TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={5} className={classes.tableCell}>
                      <Loading />
                    </TableCell>
                  </TableRow>
                ) : (
                  repos.map((repo) => (
                    <React.Fragment key={repo.Name}>
                      <TableRow>
                        <TableCell className={classes.tableCell}>
                          <IconButton
                            className={classes.icons}
                            size="small"
                            onClick={() => setExpanded(expanded === repo.Name ? null : repo.Name)}
                            data-testid={`expand-${repo.Name}`}
                          >
                            {expanded === repo.Name ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                          </IconButton>
                        </TableCell>
                        <TableCell className={classes.tableCell}>
                          <Link to={`/image/${repo.Name}`} className={classes.link}>
                            {repo.Name}
                          </Link>
                        </TableCell>
                        <TableCell className={classes.tableCell}>{repo.NewestImage?.Tag}</TableCell>
                        <TableCell className={classes.tableCell}>
                          {transform.formatBytes(Number(repo.Size || 0))}
                        </TableCell>
                        <TableCell className={classes.tableCell} align="right">
                          <TagHistoryButton repo={repo.Name} />
                          <ScanMatrixButton repo={repo.Name} />
                          <Tooltip title="Open repository">
                            <IconButton
                              className={classes.icons}
                              size="small"
                              component={Link}
                              to={`/image/${repo.Name}`}
                            >
                              <OpenInNewIcon fontSize="small" />
                            </IconButton>
                          </Tooltip>
                        </TableCell>
                      </TableRow>
                      <TableRow>
                        <TableCell className={classes.tableCell} colSpan={5} sx={{ padding: 0 }}>
                          <Collapse in={expanded === repo.Name} timeout="auto" unmountOnExit>
                            <Table size="small">
                              <TableHead>
                                <TableRow>
                                  <TableCell className={classes.tableHeadCell}></TableCell>
                                  <TableCell className={classes.tableHeadCell}>Tag</TableCell>
                                  <TableCell className={classes.tableHeadCell}>Digest</TableCell>
                                  <TableCell className={classes.tableHeadCell}>Size</TableCell>
                                  <TableCell className={classes.tableHeadCell}>CVEs</TableCell>
                                  <TableCell className={classes.tableHeadCell}>Trust</TableCell>
                                  <TableCell className={classes.tableHeadCell} align="right">
                                    Actions
                                  </TableCell>
                                </TableRow>
                              </TableHead>
                              <TableBody>
                                <TagRows repo={repo.Name} />
                              </TableBody>
                            </Table>
                          </Collapse>
                        </TableCell>
                      </TableRow>
                    </React.Fragment>
                  ))
                )}
                {!loading && isEmpty(repos) && (
                  <TableRow>
                    <TableCell colSpan={5} className={classes.tableCell}>
                      <Typography>no repositories found</Typography>
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
          <div className={classes.pagination}>
            <Button
              variant="outlined"
              disabled={page === 1}
              onClick={() => {
                setPage(page - 1);
                loadRepos(page - 1);
              }}
            >
              Previous
            </Button>
            <Button
              variant="outlined"
              disabled={repos.length < PAGE_SIZE}
              onClick={() => {
                setPage(page + 1);
                loadRepos(page + 1);
              }}
            >
              Next
            </Button>
          </div>
        </CardContent>
      </Card>

      <Snackbar
        open={snack.open}
        autoHideDuration={4000}
        onClose={() => setSnack((prev) => ({ ...prev, open: false }))}
      >
        <Alert
          severity={snack.severity}
          variant="filled"
          onClose={() => setSnack((prev) => ({ ...prev, open: false }))}
        >
          {snack.message}
        </Alert>
      </Snackbar>
    </div>
  );
}

export default Admin;
