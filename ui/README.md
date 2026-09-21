# ui

Web UI for the Quad4 zot fork. Vendored from
[project-zot/zui](https://github.com/project-zot/zui), built with React and
Material UI.

## Scripts

pnpm is pinned through the `packageManager` field in `package.json`;
`corepack enable` installs the exact version. Supply-chain policy lives
in `pnpm-workspace.yaml` (minimum release age, blocked exotic subdeps,
trust downgrade checks, allowlisted build scripts).

- `pnpm install --frozen-lockfile` - install dependencies
- `pnpm start` - dev server
- `pnpm build` - production build into `build/`
- `pnpm test` - jest suite
- `pnpm lint` - eslint

The zot Makefile copies `build/` into `pkg/extensions/build/` for embedding.
To run standalone against a registry, set `hostConfig.auto` to false and
`default` to the registry URL in `src/host.js`.
