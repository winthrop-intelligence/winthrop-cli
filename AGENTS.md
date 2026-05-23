# Repository Guidelines

## Project Structure & Module Organization

This repository is `winthrop-cli`; it builds the `winthrop` binary, a cross-platform OAuth grant CLI for API users. Keep top-level files focused on repository configuration and contributor documentation.

Recommended Go layout:

- `cmd/winthrop/`: CLI entry point.
- `internal/`: private OAuth, config, and API client packages.
- `pkg/`: exported packages intended for external reuse.
- `testdata/`: fixtures used by Go tests.
- `docs/`: user-facing usage notes, protocol notes, and examples.

Do not commit binaries, coverage files, workspace files, or secrets; `.gitignore` already excludes common Go outputs and `.env`.

## Build, Test, and Development Commands

Once `go.mod` exists, use standard Go tooling:

- `go mod tidy`: sync module dependencies.
- `go build ./...`: compile all packages.
- `go test ./...`: run the full test suite.
- `go test -cover ./...`: run tests with package coverage.
- `go run ./cmd/winthrop --help`: run the CLI locally.

If scripts or a `Makefile` are added, keep them thin wrappers around these commands.

## Coding Style & Naming Conventions

Run `gofmt` on changed Go files before committing. Prefer short package names such as `oauth`, `config`, or `client`; avoid generic names like `utils`.

Use `PascalCase` for exported identifiers and `camelCase` for unexported identifiers. Keep CLI commands and flags lowercase and hyphenated, for example `--client-id`.

## Testing Guidelines

Use Go's built-in `testing` package. Place unit tests beside the code under test with `_test.go` suffixes. Prefer table-driven tests for parsing, validation, and OAuth state transitions.

Name tests around behavior, for example `TestConfigLoadsEnvOverrides`. Store static fixtures in `testdata/`. Do not rely on live OAuth providers in unit tests; mock HTTP interactions with `httptest`.

## Commit & Pull Request Guidelines

The current history only contains `Initial commit`, so no strict convention is established. Use concise, imperative messages such as `Add OAuth device flow command`.

Pull requests should include a short problem summary, implementation approach, test results, and any security or configuration impact. Link related issues when available. Include terminal output when CLI behavior changes.

## Security & Configuration Tips

Never commit client secrets, access tokens, refresh tokens, or `.env` files. Treat redirect URIs, scopes, and token storage paths as security-sensitive. Prefer environment variables or OS keychain integration over plaintext storage.
