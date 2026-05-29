# winthrop

`winthrop` is a cross-platform Go CLI for Winthrop API users. It uses OAuth2 Device Authorization Grant, stores refresh tokens in the OS credential store when available, and prints short-lived access tokens for generated API clients.

## Configuration

Set the required environment variables:

```sh
export WINTHROP_AUTH_BASE_URL="https://auth.example.com"
export WINTHROP_API_BASE_URL="https://api.example.com"
export WINTHROP_CLIENT_ID="winthrop-cli"
export WINTHROP_SCOPES="openid profile offline_access"
```

`WINTHROP_SCOPES` is optional and accepts space-separated OAuth scopes.

For local development, you can put the same keys in a `.env` file in the working directory. Real environment variables take precedence over values from `.env`.

## Interactive Login

```sh
winthrop login
```

The command prints a verification URL and user code, attempts to open the browser, then waits until the device flow is approved, denied, expired, or timed out. On success, it stores the refresh token securely and prints the current user when `/api/v1/users/me` is available.

## Access Tokens

`winthrop token` is designed for scripts. It prints only the access token to stdout; errors and guidance go to stderr.

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
winthrop whoami   # print the current user from /api/v1/users/me
winthrop logout   # delete the stored refresh token
winthrop doctor   # check config, storage, reachability, and login state
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

## Development

```sh
go mod tidy
go test ./...
go build ./cmd/winthrop
```
