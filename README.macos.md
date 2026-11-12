# Proxmox Backup Client for macOS — experimental port

This is a work in progress based on the original Proxmox Backup source,
starting at PBS v4.2.8. The canonical development repository retains the complete
upstream history. GitHub uses a separate snapshot baseline because an older
upstream test blob exceeds GitHub's 100 MB limit. Full unmodified history is
distributed separately as Git bundle source archives with checksums; see
[archive notes](SOURCE-ARCHIVES.md). It is not affiliated with or
officially supported by Proxmox. Native Apple Silicon backup and restore have passed integration tests against PBS.
This is an experimental port, not an official Proxmox release.

The objective is a native CLI retaining Linux backup command syntax, PBS
deduplication and client-side encryption, with explicit handling of macOS
filesystem metadata. Docker and a Linux guest are not runtime requirements.
OpenSSL and zstd for native development come from Homebrew; Darwin filesystem
and ACL operations should use the system APIs.

Implemented so far:

- Official dependency repositories pinned as submodules, with reproducible
  patches and a tracked Cargo.lock.
- Separation of server storage/configuration dependencies from client data
  formats. Linux server functionality retains its feature gate.
- Darwin system-library fixes, descriptor-based xattrs, 16 KiB page alignment
  for fixed and dynamic indexes, and native resizing of fixed-index mappings.
- Descriptor-relative hardlink parent resolution rejecting symlinks, absolute
  paths and parent traversal.
- A native Apple Silicon offline verifier using a separate non-login build UID,
  read-only source, no network, bounded logs and source/toolchain provenance.

Verified on native Apple Silicon macOS: 21 PBS format tests; 8 path matching
tests and 1 doctest; 7 isolated filesystem primitives; complete native PXAR
archive/restore including nanosecond times, UUID ACL primitives, flags, symlinks,
hardlinks, binary xattrs, FinderInfo and a resource fork larger than 1 MiB;
plus destination filename collision rejection before truncation.

PBS integration tests passed using a dedicated test datastore namespace and
restricted API token: two backups and restore without encryption, then two
backups and restore with client-side encryption. The repeated backup reused
100% of both primary data and native attribute archive chunks, uploading 0 B
for those archive data streams. These tests use synthetic files, not production
backup data. Linux format and compilation regressions are checked separately.

[Native metadata design and limits](docs/macos-native-metadata.md) describes the
versioned envelope and additional standard PXAR archive. The server and PXAR
wire formats are unchanged. The native client restores the associated metadata
automatically with the ordinary `restore` command. FUSE mount/map remain Linux-only.
Intel and older macOS versions have not been verified.

## Build and use

Build prerequisites are Rust, OpenSSL 3, zstd and pkg-config (Homebrew packages
`rust`, `openssl@3`, `zstd`, `pkgconf`). Initialize pinned Git submodules and run
`python3 scripts/macos/apply-patches.py`. Cargo must run from outside the source
tree with an explicit manifest to avoid upstream's Debian registry redirect.
The [Homebrew formula](Formula/proxmox-backup-client.rb) contains the build recipe;
a fresh Homebrew build/install on Apple Silicon and subsequent encrypted and
unencrypted PBS backup/restore using the installed executable have passed.

With [just](https://github.com/casey/just) the same steps are one command each:

```sh
git submodule update --init
just build      # native-target/release/proxmox-backup-client
just test       # tests that need no server
just test-pbs   # round trip, listing, extracting and change detection against a PBS namespace
```

`scripts/macos/cargo.sh` is what the recipes call. It applies the dependency patches, starts
Cargo outside the source tree and with an empty environment that puts Apple's linker and `strip`
first; inside a nix or devenv shell the build otherwise fails with
`can't find crate for <a procedural macro>`. Rust comes from `PATH`, or from nixpkgs if there is
none. `tests/macos/pbs.py` names the environment variables `just test-pbs` needs: a repository,
a namespace and a token with `DatastoreBackup` on it.

Two commands exist only in this fork, for programs that browse a snapshot without mounting it.
Both work on encrypted snapshots and read only what they return:

```sh
# one directory as JSON: [{"name": "...", "type": "file", "size": 70000, "mtime": 1700000000}, ...]
proxmox-backup-client catalog list <snapshot> documents.pxar [<directory>] --ns laptops

# one file or directory, with its Mac metadata, into a target directory
proxmox-backup-client catalog extract <snapshot> documents.pxar <path> /restore --ns laptops
```

`type` is `directory`, `file`, `symlink`, `hardlink` or `other`; `size` is present for files;
`mtime` is in seconds since the epoch. `restore --pattern` gives the same result as
`catalog extract` but reads the whole archive to get there.

Three options of `backup` also exist only here:

- `--skip-placeholders true` leaves out files whose contents are not on disk (evicted iCloud
  and File Provider files) and reports them, instead of failing the backup. Nothing is
  downloaded.
- `--skip-tm-excluded true` leaves out every entry that carries the Time Machine exclusion
  attribute (`com.apple.metadata:com_apple_backup_excludeItem`, set by `tmutil addexclusion`
  and by applications on caches and build folders), with everything below it.
- `--progress-json true` (also on `restore`) prints one JSON object per line on standard
  output while the log stays on standard error: a `progress` record every second with
  `entries`, `bytes_processed`, `bytes_uploaded`, `path` and `elapsed`, and one final `result`
  record with `ok`, the `snapshot` and `namespace`, `entries`, `bytes_processed`,
  `bytes_reused`, `bytes_uploaded`, `skipped_placeholders` (at most 1000 paths) with
  `skipped_placeholder_count`, `time_machine_excluded`, `warnings` and `duration`. On failure
  the record has `"ok": false` and the exit status is non-zero. The format is described in
  full at the top of `pbs-client/src/report.rs`.

The CLI retains the Linux syntax, for example:

```sh
export PBS_REPOSITORY='backup@pbs!mac@pbs.example.com:datastore'
export PBS_PASSWORD_FILE='/secure/location/pbs-token'
export PBS_FINGERPRINT='verified-server-certificate-fingerprint'
proxmox-backup-client backup documents.pxar:/Users/example/Documents --ns laptops
proxmox-backup-client restore host/mac/2026-10-24T12:00:00Z documents.pxar /restore --ns laptops
```

Use normal PBS encryption key options for client-side encryption. Full Disk
Access may be needed for protected source directories. Read restore warnings for
OS-managed attributes. Maintain an independent copy while evaluating the port.

The `endian_trait` RUSTSEC-2021-0039 ownership bug is addressed by a local,
MIT-licensed panic-safe compatibility fork (`vendor/endian-trait-pbs`,
`0.6.1+pbs.1`). This is not an upstream fixed release. The local override replaces
unsafe array/slice ownership duplication, checks Unicode scalar conversions and
forbids unsafe code. See its PATCH-NOTES.md and provenance for the exact changes
and regression coverage. Hickory is Linux-only; macOS uses the system resolver.

Proxmox licenses and copyright notices remain in force. Upstream contributions
should follow Proxmox's contribution and mailing-list process after independent
review and completion of the relevant tests.
