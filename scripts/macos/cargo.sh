#!/bin/bash
# Runs cargo on this tree the way macOS needs it: `scripts/macos/cargo.sh build --release ...`
#
# - applies the dependency patches (a no-op when they are applied already);
# - starts cargo outside the source tree, because the tree's .cargo/config.toml redirects
#   crates.io to Debian's packaged registry;
# - uses an empty environment with Apple's tools first. Inside a nix or devenv shell rustc
#   otherwise runs nix's cctools `strip` on what Apple's linker wrote, which damages it
#   ("mis-aligned LINKEDIT string pool") and shows up as
#   "can't find crate for <some procedural macro>";
# - takes cargo and rustc from PATH, or from nixpkgs when there are none.
# OpenSSL and zstd come from Homebrew. Output goes to native-target/.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
if ! command -v cargo >/dev/null || ! command -v rustc >/dev/null; then
    exec nix shell nixpkgs#cargo nixpkgs#rustc -c "$0" "$@"
fi
/usr/bin/python3 "$root/scripts/macos/apply-patches.py" >/dev/null
tools="$(dirname "$(command -v cargo)"):$(dirname "$(command -v rustc)")"
brew="${HOMEBREW_PREFIX:-/opt/homebrew}"
driver="$(mktemp -d)"
trap 'rm -rf "$driver"' EXIT
cd "$driver"
subcommand="$1"; shift
env -i HOME="$HOME" PATH="$tools:/usr/bin:/bin:/usr/sbin:/sbin:$brew/bin" SSL_CERT_FILE=/etc/ssl/cert.pem \
    OPENSSL_DIR="$brew/opt/openssl@3" ZSTD_SYS_USE_PKG_CONFIG=1 \
    CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER=/usr/bin/clang CC=/usr/bin/clang AR=/usr/bin/ar \
    cargo "$subcommand" --locked --manifest-path "$root/Cargo.toml" --target-dir "$root/native-target" "$@"
