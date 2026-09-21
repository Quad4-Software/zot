# Getting Started

This repository is Quad4's fork of [zot](https://github.com/project-zot/zot).
To contribute to upstream zot itself, see the upstream
[CONTRIBUTING.md](https://github.com/project-zot/zot/blob/main/CONTRIBUTING.md).

## Clone Repository

```
git clone git@github.com:Quad4-Software/zot.git
cd zot

#Track upstream
git remote add upstream https://github.com/project-zot/zot.git
git fetch upstream
```

## Build

There are several ways to build the zot project. The resulting binaries are
produced under bin/


## Using host's toolchain

For fully-featured zot,

```
make
```

For a minimal dist-spec only zot,

```
make binary-minimal
```

For a zot that includes only the extensions that you specify,
the available extensions that can be used at the moment are: sync, scrub, metrics, search.

NOTES: When multiple extensions are used, they should be enlisted in the above presented order.

```
make binary EXTENSIONS=a,b,c
```

For a node exporter used by minimal dist-spec only zot,

```
make exporter-minimal
```

## Using container builds (stacker)

```
make oci-image
```

## Using container builds (docker)

```
make docker-image
```

# Project Structure

```
.
...
├── cmd/zot             # Source code contains the main logic
├── cmd/zxp             # Source code contains the main logic for node exporter
├── docs                # Source code for Swagger docs
├── errors              # Source code for errors
├── examples            # Configuration examples to enable various features
├── pkg/api             # Source code contains the HTTP handlers
├── pkg/cli             # Source code that handles the commandline logic
├── pkg/compliance      # Source code that handles the dist-spec compliance logic
├── pkg/exporter        # Source code used by the node exporter
├── pkg/extensions      # Source code that handles the feature extensions
├── pkg/log             # Source code that handles logging
├── pkg/storage         # Source code that handles image storage

```

## Contribute Workflow

PRs are always welcome, even if they only contain small fixes like typos or a few
lines of code. If there will be a significant effort, please document it as an
issue and get a discussion going before starting to work on it.

Please submit a PR broken down into small changes bit by bit. A PR consisting of
a lot features and code changes may be hard to review. It is recommended to
submit PRs in an incremental fashion.

Note: If you split your pull request to small changes, please make sure any of
the changes goes to master will not break anything. Otherwise, it can not be
merged until this feature complete.

## Develop, Build and Test

Write code on the new branch in your fork. The coding style used in zot is
suggested by the Golang community. See the [style doc](https://github.com/golang/go/wiki/CodeReviewComments) for details.

Try to limit column width to 120 characters for both code and markdown documents
such as this one.

As we are enforcing standards set by
[golangci-lint](https://github.com/golangci/golangci-lint), please always run a full 'make' on source
code before committing your changes. This will trigger compilation, unit tests
and linting. If it reports an issue, in general, the preferred action is to fix
the code. We try to enforce the guideline that code coverage doesn't drop as
code is added or modified.

## Automated Testing (via CI/CD)

Once your pull request has been opened, zot will start a full CI pipeline
against it that compiles, and runs unit tests and linters.

## Reporting issues

It is a great way to contribute to zot by reporting an issue. Well-written
and complete bug reports are always welcome! Please open an issue on Github and
follow the template to fill in required information.

Before opening any issue, please look up the existing issues to avoid submitting
a duplication. If you find a match, you can "subscribe" to it to get notified on
updates. If you have additional helpful information about the issue, please
leave a comment.

When reporting issues, always include:

Build environment (golang compiler, etc)
Configuration files of zot

Log files as per configuration.

Because the issues are open to the public, when submitting the log
and configuration files, be sure to remove any sensitive
information, e.g. user name, password, IP address, and company name.
You can replace those parts with "REDACTED" or other strings like
"****".

Be sure to include the steps to reproduce the problem if applicable.
It can help us understand and fix your issue faster.

## Documenting

Update the documentation if you are creating or changing features. Good
documentation is as important as the code itself.

Upstream documentation lives at https://zotregistry.dev. Document fork-specific
changes in README.md under "Changes from upstream".

## Design New Features

You can propose new designs for existing features. You can also design
entirely new features, Please submit a proposal in GitHub issues. Maintainers
will review this proposal as soon as possible. This is necessary to
ensure the overall architecture is consistent and to avoid duplicated work in
the roadmap.
