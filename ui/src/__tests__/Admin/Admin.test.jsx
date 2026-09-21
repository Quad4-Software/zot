import { render, screen, waitFor } from '@testing-library/react';
import { api } from 'api';
import Admin from 'components/Admin/Admin';
import React from 'react';
import { BrowserRouter } from 'react-router';
import MockThemeProvider from '__mocks__/MockThemeProvider';

const AdminWrapper = () => {
  return (
    <MockThemeProvider>
      <BrowserRouter>
        <Admin />
      </BrowserRouter>
    </MockThemeProvider>
  );
};

const mockServerInfo = {
  distSpecVersion: '1.1.1',
  commit: 'abc1234',
  releaseTag: 'v1.0.0',
  binaryType: 'extended',
  http: { auth: { apikey: true } },
  storage: {
    gc: true,
    gcInterval: '24h0m0s',
    dedupe: true,
    retention: [{ repositories: ['infra/**'], deleteUntagged: true, deleteReferrers: false, keepTags: 2 }]
  }
};

const mockRepoList = {
  RepoListWithNewestImage: {
    Results: [
      {
        Name: 'alpine',
        Size: '2806985',
        LastUpdated: '2022-08-09T17:19:53.274069586Z',
        NewestImage: { Tag: 'latest' }
      }
    ]
  }
};

const mockRepoDetail = {
  ExpandedRepoInfo: {
    Images: [
      {
        Tag: 'latest',
        Digest: 'sha256:abc123',
        IsDeletable: true,
        IsSigned: true,
        SignatureInfo: [{ Tool: 'cosign', IsTrusted: true, Author: 'ci@quad4.io' }],
        Vulnerabilities: { MaxSeverity: 'LOW', Count: '1' },
        Manifests: [{ Size: 100 }]
      }
    ]
  }
};

beforeEach(() => {
  jest.spyOn(api, 'get').mockImplementation((url) => {
    if (url.includes('_zot/ext/mgmt')) return Promise.resolve({ data: mockServerInfo });
    if (url.includes('ExpandedRepoInfo')) return Promise.resolve({ data: { data: mockRepoDetail } });
    return Promise.resolve({ data: { data: mockRepoList } });
  });
});

describe('Admin page', () => {
  it('renders server info and repositories', async () => {
    render(<AdminWrapper />);
    await waitFor(() => expect(screen.getByText('Admin')).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText('alpine')).toBeInTheDocument());
    expect(screen.getByText(/version v1.0.0/)).toBeInTheDocument();
    expect(screen.getByText(/auth: apikey/)).toBeInTheDocument();
  });

  it('expands a repository to list tags', async () => {
    render(<AdminWrapper />);
    await waitFor(() => expect(screen.getByText('alpine')).toBeInTheDocument());
    screen.getByTestId('expand-alpine').click();
    await waitFor(() => expect(screen.getByText('sha256:abc123')).toBeInTheDocument());
  });

  it('shows gc status, retention policies and an api keys link', async () => {
    render(<AdminWrapper />);
    await waitFor(() => expect(screen.getByText('Garbage collection')).toBeInTheDocument());
    expect(screen.getByText(/gc: enabled/)).toBeInTheDocument();
    expect(screen.getByText('infra/**')).toBeInTheDocument();
    expect(screen.getByText('API keys')).toBeInTheDocument();
    expect(screen.getByTestId('run-gc')).toBeInTheDocument();
  });

  it('shows image labels in a dialog', async () => {
    api.get.mockImplementation((url) => {
      if (url.includes('_zot/ext/mgmt')) return Promise.resolve({ data: mockServerInfo });
      if (url.includes('ExpandedRepoInfo')) return Promise.resolve({ data: { data: mockRepoDetail } });
      if (url.includes('/manifests/'))
        return Promise.resolve({
          data: {
            mediaType: 'application/vnd.oci.image.manifest.v1+json',
            annotations: { 'org.opencontainers.image.title': 'quad4-zot' },
            config: { digest: 'sha256:cfg' }
          }
        });
      if (url.includes('/blobs/'))
        return Promise.resolve({ data: { config: { Labels: { 'org.opencontainers.image.vendor': 'Quad4' } } } });
      return Promise.resolve({ data: { data: mockRepoList } });
    });
    render(<AdminWrapper />);
    await waitFor(() => expect(screen.getByText('alpine')).toBeInTheDocument());
    screen.getByTestId('expand-alpine').click();
    await waitFor(() => expect(screen.getByTestId('labels-latest')).toBeInTheDocument());
    screen.getByTestId('labels-latest').click();
    await waitFor(() => expect(screen.getByText('org.opencontainers.image.title')).toBeInTheDocument());
    expect(screen.getByText('org.opencontainers.image.vendor')).toBeInTheDocument();
  });

  it('shows the per-scanner scan report with disagreements', async () => {
    api.get.mockImplementation((url) => {
      if (url.includes('/mgmt/cve'))
        return Promise.resolve({
          data: {
            image: 'alpine:latest',
            scanners: {
              trivy: {
                scanned: true,
                count: 1,
                maxSeverity: 'CRITICAL',
                cves: [{ id: 'CVE-2021-36159', severity: 'CRITICAL' }]
              },
              grype: {
                scanned: true,
                count: 2,
                maxSeverity: 'HIGH',
                cves: [
                  { id: 'CVE-2021-36159', severity: 'HIGH' },
                  { id: 'CVE-2021-42374', severity: 'MEDIUM' }
                ]
              }
            },
            onlyIn: { grype: ['CVE-2021-42374'] },
            common: ['CVE-2021-36159']
          }
        });
      if (url.includes('_zot/ext/mgmt')) return Promise.resolve({ data: mockServerInfo });
      if (url.includes('ExpandedRepoInfo')) return Promise.resolve({ data: { data: mockRepoDetail } });
      return Promise.resolve({ data: { data: mockRepoList } });
    });
    render(<AdminWrapper />);
    await waitFor(() => expect(screen.getByText('alpine')).toBeInTheDocument());
    screen.getByTestId('expand-alpine').click();
    await waitFor(() => expect(screen.getByTestId('scan-report-latest')).toBeInTheDocument());
    screen.getByTestId('scan-report-latest').click();
    await waitFor(() => expect(screen.getByText('alpine:latest scan report')).toBeInTheDocument());
    expect(screen.getByText('1 reported by all scanners')).toBeInTheDocument();
    expect(screen.getByText('1 only in grype')).toBeInTheDocument();
    expect(screen.getByText('Only in grype')).toBeInTheDocument();
    expect(screen.getByText('CVE-2021-42374')).toBeInTheDocument();
  });
});
