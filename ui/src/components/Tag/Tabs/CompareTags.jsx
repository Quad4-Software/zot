// react global
import React, { useEffect, useRef, useState } from 'react';

// utility
import { api, endpoints } from '../../../api';
import { host } from '../../../host';
import { isEmpty } from 'lodash';

// components
import {
  Card,
  CardContent,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Select,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography
} from '@mui/material';
import Loading from '../../Shared/Loading';
import { VulnerabilityChipCheck } from 'utilities/vulnerabilityAndSignatureCheck';
import { makeStyles } from 'theme';

const useStyles = makeStyles((theme) => ({
  cardRoot: {
    boxShadow: 'none!important',
    borderRadius: '0.75rem'
  },
  heading: {
    fontWeight: 600,
    fontSize: '1rem',
    color: theme.palette.text.primary,
    marginBottom: '0.75rem'
  },
  subtext: {
    color: theme.palette.text.secondary,
    fontSize: '0.875rem'
  },
  tableCell: {
    borderBottom: `1px solid ${theme.palette.divider}`,
    fontSize: '0.875rem',
    color: theme.palette.text.primary,
    padding: '0.5rem 0.75rem'
  },
  tableHeaderCell: {
    borderBottom: `1px solid ${theme.palette.divider}`,
    color: theme.palette.text.secondary,
    fontSize: '0.75rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05rem',
    padding: '0.5rem 0.75rem'
  },
  compareSelect: {
    minWidth: '12rem',
    marginBottom: '1.25rem'
  },
  cveLink: {
    color: theme.palette.secondary.main,
    textDecoration: 'none',
    '&:hover': {
      textDecoration: 'underline'
    }
  }
}));

const renderPackageList = (packages, classes) => {
  if (isEmpty(packages)) return <Typography className={classes.subtext}>-</Typography>;
  return (
    <Stack spacing={0.5}>
      {packages.map((pkg, index) => (
        <Typography key={`${pkg.Name}-${index}`} className={classes.subtext}>
          {pkg.Name} {pkg.InstalledVersion}
          {pkg.FixedVersion ? ` -> ${pkg.FixedVersion}` : ''}
        </Typography>
      ))}
    </Stack>
  );
};

const renderDiffTable = (cveList, emptyText, classes) => {
  if (isEmpty(cveList)) {
    return <Typography className={classes.subtext}>{emptyText}</Typography>;
  }
  return (
    <TableContainer>
      <Table size="small" aria-label="cve diff list">
        <TableHead>
          <TableRow>
            <TableCell className={classes.tableHeaderCell}>CVE</TableCell>
            <TableCell className={classes.tableHeaderCell}>Severity</TableCell>
            <TableCell className={classes.tableHeaderCell}>Packages</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {cveList.map((cve) => (
            <TableRow key={cve.Id}>
              <TableCell className={classes.tableCell}>
                {cve.Reference ? (
                  <a className={classes.cveLink} href={cve.Reference} target="_blank" rel="noreferrer">
                    {cve.Id}
                  </a>
                ) : (
                  cve.Id
                )}
              </TableCell>
              <TableCell className={classes.tableCell}>
                <VulnerabilityChipCheck vulnerabilitySeverity={cve.Severity} />
              </TableCell>
              <TableCell className={classes.tableCell}>{renderPackageList(cve.PackageList, classes)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

function CompareTags({ name, tag }) {
  const classes = useStyles();
  const [tagList, setTagList] = useState([]);
  const [compareTag, setCompareTag] = useState('');
  const [onlyInCurrent, setOnlyInCurrent] = useState(null);
  const [onlyInOther, setOnlyInOther] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [compareFailed, setCompareFailed] = useState(false);
  const abortRef = useRef(new AbortController());

  useEffect(() => {
    abortRef.current = new AbortController();

    api
      .get(`${host()}${endpoints.detailedRepoInfo(name)}`, abortRef.current.signal)
      .then((response) => {
        if (response.data && response.data.data) {
          const images = response.data.data.ExpandedRepoInfo?.Images || [];
          setTagList(images.map((img) => img.Tag).filter((t) => t && t !== tag));
        }
      })
      .catch((e) => {
        if (e.name !== 'CanceledError') console.error(e);
      });
    return () => {
      abortRef.current.abort();
    };
  }, [name, tag]);

  const fetchDiff = (minuendTag, subtrahendTag) =>
    api
      .get(
        `${host()}${endpoints.cveDiffForImages({ repo: name, tag: minuendTag }, { repo: name, tag: subtrahendTag })}`,
        abortRef.current.signal
      )
      .then((response) => {
        if (response.data && response.data.data) {
          return response.data.data.CVEDiffListForImages?.CVEList || [];
        }
        return [];
      });

  const handleCompareChange = (e) => {
    const selected = e.target.value;
    setCompareTag(selected);
    setOnlyInCurrent(null);
    setOnlyInOther(null);
    setCompareFailed(false);
    if (isEmpty(selected)) return;
    setIsLoading(true);
    Promise.all([fetchDiff(tag, selected), fetchDiff(selected, tag)])
      .then(([currentOnly, otherOnly]) => {
        setOnlyInCurrent(currentOnly);
        setOnlyInOther(otherOnly);
        setIsLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setCompareFailed(true);
        setIsLoading(false);
      });
  };

  return (
    <Card className={classes.cardRoot}>
      <CardContent>
        <FormControl size="small" className={classes.compareSelect}>
          <InputLabel id="compare-tag-label">Compare with tag</InputLabel>
          <Select
            labelId="compare-tag-label"
            label="Compare with tag"
            value={compareTag}
            onChange={handleCompareChange}
            MenuProps={{ disableScrollLock: true }}
            data-testid="compare-tag-select"
          >
            {tagList.map((t) => (
              <MenuItem key={t} value={t}>
                {t}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        {isLoading && <Loading />}
        {compareFailed && (
          <Typography className={classes.subtext}>Could not load the comparison for these tags.</Typography>
        )}
        {!isLoading && !compareFailed && onlyInCurrent !== null && (
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography className={classes.heading}>
                Only in {name}:{tag} ({onlyInCurrent.length})
              </Typography>
              {renderDiffTable(onlyInCurrent, 'No unique vulnerabilities.', classes)}
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography className={classes.heading}>
                Only in {name}:{compareTag} ({onlyInOther.length})
              </Typography>
              {renderDiffTable(onlyInOther, 'No unique vulnerabilities.', classes)}
            </Grid>
          </Grid>
        )}
        {!isLoading && !compareFailed && onlyInCurrent === null && (
          <Typography className={classes.subtext}>
            Select another tag in this repository to compare vulnerability findings.
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

export default CompareTags;
