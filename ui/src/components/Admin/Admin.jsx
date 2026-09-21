import React, { useEffect, useState } from 'react';
import { Link } from 'react-router';

// utility
import { api, endpoints } from '../../api';
import { host } from '../../host';
import transform from 'utilities/transform';
import { isEmpty } from 'lodash';

// components
import {
  Button,
  Card,
  CardContent,
  Chip,
  Collapse,
  IconButton,
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
import DeleteTag from 'components/Shared/DeleteTag';
import Loading from 'components/Shared/Loading';

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
        <TableCell colSpan={5} className={classes.tableCell}>
          <Typography className={classes.errorText}>{error}</Typography>
        </TableCell>
      </TableRow>
    );
  }

  if (images === null) {
    return (
      <TableRow>
        <TableCell colSpan={5} className={classes.tableCell}>
          <Loading />
        </TableCell>
      </TableRow>
    );
  }

  if (isEmpty(images)) {
    return (
      <TableRow>
        <TableCell colSpan={5} className={classes.tableCell}>
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
      <TableCell className={classes.tableCell} align="right">
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
            </div>
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
    </div>
  );
}

export default Admin;
