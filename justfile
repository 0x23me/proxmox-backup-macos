# macOS client task runner. Run `just` to list recipes.

set shell := ["bash", "-euo", "pipefail", "-c"]

cargo := "scripts/macos/cargo.sh"
client := "native-target/release/proxmox-backup-client"

default:
    @just --list

# Build the client into native-target/release/proxmox-backup-client
build:
    {{cargo}} build --release --package proxmox-backup-client
    env -u PBS_REPOSITORY {{client}} version

# The tests that need no server: archive and restore on the local filesystem, formats, keys
test:
    {{cargo}} test --package pbs-client --test macos_filesystem
    # Two test sets of the base port only build on Linux and are left out here:
    # `--package pbs-client --lib` (create.rs tests build an Archiver without the macOS fields)
    # and `--package proxmox-sys` (links libcrypt and libacl).
    {{cargo}} test --package pbs-datastore --no-default-features
    {{cargo}} test --package pbs-key-config
    {{cargo}} test --package pathpatterns
    {{cargo}} test --package endian_trait
    {{cargo}} test --package proxmox-backup-client --bin proxmox-backup-client status_percentage_handles_restricted_and_malformed_values

# The tests against a PBS namespace: round trip, listing, extracting, change detection (see tests/macos/pbs.py for the environment)
test-pbs: build
    /usr/bin/python3 tests/macos/pbs.py

# Everything
check: test test-pbs
