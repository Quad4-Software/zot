# ui

Web UI for the Quad4 zot fork. Vendored from
[project-zot/zui](https://github.com/project-zot/zui), built with React and
Material UI.

## Scripts

- `npm ci` - install dependencies
- `npm start` - dev server
- `npm run build` - production build into `build/`
- `npm test` - jest suite
- `npm run lint` - eslint

The zot Makefile copies `build/` into `pkg/extensions/build/` for embedding.
To run standalone against a registry, set `hostConfig.auto` to false and
`default` to the registry URL in `src/host.js`.
