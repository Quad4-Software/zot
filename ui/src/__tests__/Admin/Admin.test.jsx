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
  http: { auth: { apikey: true } }
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
});
