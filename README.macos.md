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
automatically with the ordinary `restore` command. `mount` works through FUSE-T (see
[Mounting an archive](#mounting-an-archive)); `map` and `unmap` remain Linux-only.
Intel and older macOS versions have not been verified.

## Build and use

Build prerequisites are Rust, OpenSSL 3, zstd and pkg-config (Homebrew packages
`rust`, `openssl@3`, `zstd`, `pkgconf`) and [FUSE-T](https://www.fuse-t.org)
(`brew install --cask fuse-t`), whose headers and library the build needs; this applies to the
Homebrew formula too. The built client runs without FUSE-T. Initialize pinned Git submodules and run
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

# everything below a directory, one JSON object per line, each with its "path" (to search by name)
proxmox-backup-client catalog list <snapshot> documents.pxar [<directory>] --recursive true --ns laptops

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

### Reading only what changed

A backup with `--change-detection-mode=metadata` does not read unchanged files, but it still
looks at every file and folder to see that they are unchanged. Told which folders changed, it
skips that as well:

```sh
proxmox-backup-client backup home.pxar:/Users/me --change-detection-mode=metadata \
    --changed-dirs /path/to/list --changed-dirs-base 2026-11-12T08:00:00Z
```

`--changed-dirs` names a file of records, each ended by a NUL byte: one byte for the kind and
an absolute path, as the client sees the folder being backed up (as given, or with symbolic
links resolved).

- `d<path>`: entries directly in this folder changed. It is read from disk. A folder in it
  is carried over unless it is named itself, has a named folder below it, or its own
  metadata differs from the previous snapshot.
- `r<path>`: everything at and below this path is read from disk. For a folder that was
  renamed or moved, or when the source of the list lost track of what happened below.

`--changed-dirs-base` is the time, as in its name, of the snapshot the list is relative to.
The top folder is always read. Paths outside the folder being backed up are ignored, so one
list serves a backup of several folders; a path that does not exist is ignored too.

A folder that is not read is carried over: its entries, their metadata and Mac attributes,
and for files the place of their contents, are taken from the previous snapshot's metadata
archive. Nothing below it is opened or even listed. The result with `--progress-json` gains
`change_list` (`"used"` or `"ignored: <reason>"`), `carried_dirs` and `walked_dirs`.

The list is ignored, and everything is read as without it, when the backup does not build on
exactly the snapshot named (another backup ran in between, the previous one is gone or was
made with another key), when an archive has no previous split archive, or when the previous
snapshot's Mac attribute archive cannot be read.

What this means:

- The backup is as complete as the list. A change in a folder the list does not name is not
  in the snapshot, and not in later ones either until that folder is named or everything is
  read again. Whoever writes the list has to name too much rather than too little, and
  leave the list out whenever it may have a gap.
- A folder moved or renamed with everything in it needs an `r` record at its new place.
  Without one it is still read when it looks different from what the previous snapshot has
  under that name (dates, mode, attributes); a folder that looks the same is taken for the
  same.
- Exclusions (`--exclude`, `.pxarexclude`, `--skip-tm-excluded`, `--skip-placeholders`) are
  not applied again to what is carried over: it stays as the previous run decided. Change
  the exclusions without the list. The counts of skipped entries cover the folders read.
- A folder with a `.pxarexclude` file is always read, so that its patterns hold below it;
  so is a folder in which the list names a folder that the previous snapshot does not have.
- Hard links stay hard links, whether link and target are carried over or read. A link whose
  target was read is read too.
- Files carried over are never encoded again, so the rule that re-encodes files when reusing
  their chunks would drag along more than 10 % of other data does not apply to them. The
  payload archive can refer to somewhat more data than it needs after many runs; a run
  without the list tidies that up.
- The previous snapshot's Mac attribute archive (`native-macos-payloads-N.pxar`) is
  downloaded at the start of the run, because the new snapshot needs the attribute values of
  what it carries over in its own. Values nothing refers to any more are dropped.

On a tree of 60,000 small files, half of them with an attribute, a run over the unchanged
tree took 2.5 s without the list and 0.5 s with it, against a server on the local network.

### Mounting an archive

```sh
proxmox-backup-client mount <snapshot> documents.pxar /some/empty/folder --ns laptops
umount /some/empty/folder
```

`mount` shows an archive of a snapshot as a read-only folder. It needs FUSE-T on the Mac at
run time. The command returns once the folder is mounted and leaves a background process
that ends with the unmount; `--verbose` keeps it in the foreground. A failed mount exits
non-zero. `--keyfd` is accepted, as on `backup`.

- **With FUSE-T installed:** plain and split archives mount; names, contents, sizes, modes,
  modification times and link targets match the source, and writing is refused.
- **Without FUSE-T:** `mount` fails with
  `FUSE is not available, FUSE-T (https://www.fuse-t.org) needs to be installed`. Every other
  command works as before; the library is linked weakly.

FUSE-T serves the folder over NFS, so a mount does not show extended attributes, resource
forks, ACLs, BSD flags or creation dates, and names may come back in another Unicode
normalization. Use `restore` or `catalog extract` to get files back with their Mac metadata.
`map` and `unmap` (drive images of virtual machines) are not available on macOS.

The mount code comes from the 3.2.4-based port
([Marvo2011/proxmox-backup-client-mac](https://github.com/Marvo2011/proxmox-backup-client-mac)):
a kqueue reactor and FUSE-T's buffer layout in `proxmox-fuse`
(`scripts/macos/proxmox-fuse-darwin.patch`), and lookups of `.`, `..` and of names in another
normalization in `pbs-pxar-fuse`.

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
