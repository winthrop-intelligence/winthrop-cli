#!/usr/bin/env sh
set -eu

repo="winthrop-intelligence/winthrop-cli"
install_dir="${WINTHROP_INSTALL_DIR:-$HOME/.local/bin}"
version="${WINTHROP_VERSION:-latest}"

need() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "error: $1 is required" >&2
    exit 1
  fi
}

need curl
need tar

if command -v sha256sum >/dev/null 2>&1; then
  checksum_verify="sha256sum -c -"
elif command -v shasum >/dev/null 2>&1; then
  checksum_verify="shasum -a 256 -c -"
else
  echo "error: sha256sum or shasum is required" >&2
  exit 1
fi

os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m)"

case "$os" in
  linux) goos="linux" ;;
  darwin) goos="darwin" ;;
  *) echo "error: unsupported OS: $os" >&2; exit 1 ;;
esac

case "$arch" in
  x86_64|amd64) goarch="amd64" ;;
  arm64|aarch64) goarch="arm64" ;;
  *) echo "error: unsupported architecture: $arch" >&2; exit 1 ;;
esac

if [ "$version" = "latest" ]; then
  api_url="https://api.github.com/repos/$repo/releases/latest"
  tag="$(curl -fsSL "$api_url" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$tag" ]; then
    echo "error: could not determine latest release" >&2
    exit 1
  fi
else
  tag="$version"
fi

name="winthrop_${tag}_${goos}_${goarch}"
archive="${name}.tar.gz"
base_url="https://github.com/$repo/releases/download/$tag"
tmpdir="$(mktemp -d)"

cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

curl -fsSLo "$tmpdir/$archive" "$base_url/$archive"
curl -fsSLo "$tmpdir/checksums.txt" "$base_url/checksums.txt"

(
  cd "$tmpdir"
  expected="$(grep " $archive$" checksums.txt || true)"
  if [ -z "$expected" ]; then
    echo "error: checksum not found for $archive" >&2
    exit 1
  fi
  printf '%s\n' "$expected" | $checksum_verify
  tar -xzf "$archive"
)

mkdir -p "$install_dir"
cp "$tmpdir/$name/winthrop" "$install_dir/winthrop"
chmod 0755 "$install_dir/winthrop"

echo "installed winthrop $tag to $install_dir/winthrop"
case ":$PATH:" in
  *":$install_dir:"*) ;;
  *) echo "note: add $install_dir to PATH to run winthrop from any directory" ;;
esac
