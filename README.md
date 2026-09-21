# zot

Quad4's fork of [zot](https://zotregistry.dev), a vendor-neutral OCI image registry.

Changes from upstream:

- The web UI is vendored in `ui/` and rebuilt from source instead of fetching a
  prebuilt zui bundle at build time.
- Quad4 branding, dark mode by default, and a theme switcher.
- An admin page for browsing repositories and deleting images.
- Optional Linux Landlock filesystem sandboxing, enabled with `"landlock": true`
  in the config (see `examples/config-landlock.json`). When enabled, the process
  can only read and write the storage roots and the files referenced by the
  configuration. No-op on kernels without Landlock support and on non-Linux
  platforms.

## Build

Requires Go (see `.go-version`) and Node.js 22+.

```
make binary
```

The `ui` make target runs `npm ci && npm run build` inside `ui/` and copies the
bundle into `pkg/extensions/build/` for embedding. To reuse a prebuilt bundle
instead, set `ZUI_BUILD_PATH`:

```
make binary ZUI_BUILD_PATH=path/to/ui/build
```

## Run

```
./bin/zot-linux-amd64 serve examples/config-minimal.json
```

The UI is served at `/home`, `/explore`, `/image`, `/user` and `/admin` when the
`ui` extension is enabled.

Upstream documentation lives at https://zotregistry.dev.
