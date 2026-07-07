# winthrop

`winthrop` is a cross-platform Go CLI for Winthrop API users. It uses OAuth2 Device Authorization Grant, stores refresh tokens in the OS credential store when available, and prints short-lived access tokens for generated API clients.

## Installation

For macOS and Linux, install the latest GitHub release:

```sh
curl -fsSL https://raw.githubusercontent.com/winthrop-intelligence/winthrop-cli/main/scripts/install.sh | sh
```

The installer downloads the correct binary for your OS and architecture, verifies the release checksum, and installs `winthrop` to `$HOME/.local/bin` by default. To install somewhere else:

~~~sh
curl -fsSL https://raw.githubusercontent.com/winthrop-intelligence/winthrop-cli/main/scripts/install.sh | WINTHROP_INSTALL_DIR=/usr/local/bin sh
~~~

For Windows, download the `windows_amd64` zip from the latest GitHub release, unzip it, and put `winthrop.exe` on your `PATH`.

Check the installed version:

```sh
winthrop version
```

## Configuration

Production auth, API, client ID, and scopes are built into the released CLI. Most users do not need to configure anything before running:

```sh
winthrop login
```

For local development or support overrides, set any of these environment variables:

```sh
# export WINTHROP_AUTH_BASE_URL="https://winad-hq.com"
# export WINTHROP_API_BASE_URL="https://api.winad-hq.com"
# export WINTHROP_CLIENT_ID="your-client-id"
# export WINTHROP_SCOPES="winad_read offline_access"
```

`WINTHROP_SCOPES` accepts space-separated OAuth scopes.

For local development, you can put the same keys in a `.env` file in the working directory. Real environment variables take precedence over values from `.env`.

## Interactive Login

```sh
winthrop login
```

The command prints a verification URL and user code, attempts to open the browser, then waits until the device flow is approved, denied, expired, or timed out. On success, it stores the refresh token securely and prints the current user when `/api/v1/users/me` is available.

## Access Tokens

The CLI caches the current access token in secure storage and reuses it until it has less than 60 seconds left before expiration.

For direct API reads, use `winthrop api` with an API path. It sends the current bearer token automatically and prints the raw response body to stdout:

```sh
winthrop api "/api/v1/coaches.json?q[first_name_eq]=Jason"
```

Use `-v` or `--verbose` to print safe request and response metadata to stderr while keeping stdout as the raw API response.

`winthrop token` is still available for scripts and generated clients. It prints only the access token to stdout; errors and guidance go to stderr.

```sh
TOKEN="$(winthrop token)"
curl -H "Authorization: Bearer $TOKEN" "$WINTHROP_API_BASE_URL/api/v1/users/me"
```

Python example:

```python
import subprocess

token = subprocess.check_output(["winthrop", "token"], text=True).strip()
headers = {"Authorization": f"Bearer {token}"}
```

## Generated Client Integration

Use a token-provider function instead of storing tokens in generated clients:

```python
import subprocess

def winthrop_access_token():
    return subprocess.check_output(["winthrop", "token"], text=True).strip()

client = GeneratedClient(
    base_url="https://api.example.com",
    token_provider=winthrop_access_token,
)
```

Apply the same pattern in Ruby or TypeScript: call `winthrop token` immediately before requests that need an `Authorization: Bearer ...` header.

## Commands

```sh
winthrop login    # start device authorization login
winthrop token    # print a short-lived access token
winthrop api      # make an authenticated GET request to the Winthrop API
winthrop whoami   # print the current user from /api/v1/users/me
winthrop logout   # delete the stored refresh token
winthrop doctor   # check config, storage, reachability, and login state
winthrop version  # print version and build metadata
```

## Troubleshooting

Run:

```sh
winthrop doctor
```

Common fixes:

- Missing config: export `WINTHROP_AUTH_BASE_URL`, `WINTHROP_API_BASE_URL`, and `WINTHROP_CLIENT_ID`.
- Secure storage failure: unlock or configure your OS credential store.
- Not logged in: run `winthrop login`.
- Token refresh failure: run `winthrop login` again.
- Auth/API unreachable: verify the base URL environment variables and network access.

## Releases

Maintainers publish a release by pushing a version tag:

```sh
git tag -s v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

The release workflow builds Linux, macOS, and Windows binaries and publishes checksums with the release artifacts.

## Development

```sh
go mod tidy
go test ./...
go build ./cmd/winthrop
```
