#!/usr/bin/python3
"""Tests of the macOS client against a Proxmox Backup Server namespace.

  pbs.py            run all tests; exit status 0 only when every one passed
  pbs.py selftest   check the comparison itself, without a server

What is tested:
  round trip         a fixture with Mac metadata is backed up encrypted, restored and compared:
                     contents, names byte for byte, modes, owners, BSD flags, modification and
                     creation times, every extended attribute including the resource fork,
                     ACLs, link targets and hard links
  catalog list       one directory as JSON: root, nested path, missing path; and everything
                     below a directory with --recursive
  catalog extract    one folder and one file, each into an empty target, with their metadata
  change detection   a second run over an unchanged tree in which every file carries an
                     extended attribute reuses everything and uploads no file data
  changed dirs       with --changed-dirs only the directories named as changed are read; the
                     others are carried over from the previous snapshot, with their attributes,
                     and are provably not looked at; a restore equals the source after one and
                     after two such runs; an 'r' record rereads everything below it; a list
                     relative to another snapshot, or without a previous one, is ignored
  progress records   --progress-json prints a record at least every two seconds and a final
                     record that names the snapshot the server then lists
  exclusions         --skip-tm-excluded leaves out what carries the Time Machine exclusion
                     attribute, with everything below it, and counts it
  unreadable files   a file that may not be opened is left out and named in the result; the
                     backup still succeeds
  placeholders       --skip-placeholders leaves out files whose contents are not on disk and
                     names them; without it the backup fails (needs PBS_TEST_PLACEHOLDER_DIR)
  mount              a plain and a split archive are mounted read-only through FUSE-T and
                     compared with the source: names, contents, sizes, modes, modification
                     times, link targets; writing is refused; unmounting ends the client
                     (skipped when FUSE-T is not installed)
  without FUSE-T     a copy of the client that cannot find FUSE-T's library still starts and
                     lists a snapshot; its mount fails and names FUSE-T

Environment:
  PBS_REPOSITORY             as for the client (required)
  PBS_PASSWORD, PBS_PASSWORD_FILE ...  as for the client; or
  PBS_TEST_KEYCHAIN_SERVICE  name of a login Keychain item holding the token secret
  PBS_TEST_NS                namespace to write to (required); the token needs DatastoreBackup there
  PBS_TEST_CLIENT            client binary (default native-target/release/proxmox-backup-client)
  PBS_TEST_PLACEHOLDER_DIR   optional folder that holds at least one evicted iCloud or File
                             Provider file; without it the placeholder test is skipped
  PBS_TEST_LARGE             optional "<snapshot> <archive>" of an existing big snapshot that
                             the key in PBS_TEST_LARGE_KEYFILE opens; its root must list within
                             five seconds

Every run writes a few small snapshots into the groups host/pbs-client-test-*, encrypted with a
key made for that run. Uses the system Python and no packages.
"""

import ctypes
import ctypes.util
import hashlib
import json
import os
import socket
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unicodedata

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
XATTR_NOFOLLOW = 0x0001
ACL_TYPE_EXTENDED = 0x00000100
RESOURCE_FORK = "com.apple.ResourceFork"
# Attributes macOS sets by itself: it tags what a process writes with the provenance of the app
# that started it, depending on that app, and keeps its own access list. Neither is the client's
# to restore, so a restored tree may differ from its source in them.
SYSTEM_ATTRIBUTES = ("com.apple.provenance", "com.apple.macl")

libc.listxattr.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
libc.listxattr.restype = ctypes.c_ssize_t
libc.getxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                          ctypes.c_uint32, ctypes.c_int]
libc.getxattr.restype = ctypes.c_ssize_t
libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t,
                          ctypes.c_uint32, ctypes.c_int]
libc.setxattr.restype = ctypes.c_int
libc.acl_get_link_np.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.acl_get_link_np.restype = ctypes.c_void_p
libc.acl_to_text.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
libc.acl_to_text.restype = ctypes.c_void_p
libc.acl_free.argtypes = [ctypes.c_void_p]


def oserror(path):
    err = ctypes.get_errno()
    return OSError(err, os.strerror(err), os.fsdecode(path))


def list_xattrs(path):
    size = libc.listxattr(path, None, 0, XATTR_NOFOLLOW)
    if size < 0:
        raise oserror(path)
    if size == 0:
        return []
    buf = ctypes.create_string_buffer(size)
    size = libc.listxattr(path, buf, size, XATTR_NOFOLLOW)
    if size < 0:
        raise oserror(path)
    return [name.decode() for name in buf.raw[:size].split(b"\0") if name]


def get_xattr(path, name):
    """Value of one attribute. The resource fork is read in pieces; other attributes at once."""
    name_b = name.encode()
    size = libc.getxattr(path, name_b, None, 0, 0, XATTR_NOFOLLOW)
    if size < 0:
        raise oserror(path)
    if name != RESOURCE_FORK:
        buf = ctypes.create_string_buffer(max(size, 1))
        got = libc.getxattr(path, name_b, buf, size, 0, XATTR_NOFOLLOW)
        if got < 0:
            raise oserror(path)
        return buf.raw[:got]
    out = bytearray()
    piece = ctypes.create_string_buffer(1 << 20)
    while len(out) < size:
        got = libc.getxattr(path, name_b, piece, len(piece), len(out), XATTR_NOFOLLOW)
        if got < 0:
            raise oserror(path)
        if got == 0:
            break
        out += piece.raw[:got]
    return bytes(out)


def set_xattr(path, name, value):
    path_b = os.fsencode(path)
    if libc.setxattr(path_b, name.encode(), value, len(value), 0, XATTR_NOFOLLOW) != 0:
        raise oserror(path_b)


def acl_text(path):
    acl = libc.acl_get_link_np(path, ACL_TYPE_EXTENDED)
    if not acl:
        return ""
    try:
        text = libc.acl_to_text(acl, None)
        try:
            return ctypes.string_at(text).decode()
        finally:
            libc.acl_free(text)
    finally:
        libc.acl_free(acl)


def times(paths):
    """Modification and creation time of each path as exact 'seconds.nanoseconds' strings."""
    result = {}
    for start in range(0, len(paths), 500):
        chunk = paths[start:start + 500]
        out = subprocess.run(["/usr/bin/stat", "-f", "%Fm %FB"] + chunk, check=True,
                             capture_output=True).stdout.decode().splitlines()
        for path, line in zip(chunk, out):
            mtime, birth = line.split()
            result[path] = (mtime, birth)
    return result


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


# --- fixture ---------------------------------------------------------------

OLD = 1_500_000_000          # 2017-07-14, used as creation date
LATER = 1_700_000_000        # 2023-11-14, used as modification date


def age(path, birth=OLD, mtime=LATER):
    """Give `path` a creation date older than its modification date.

    APFS moves the creation date back when the modification date is set to an earlier
    time, and leaves it alone when the modification date moves forward again.
    """
    os.utime(path, ns=(birth * 10**9 + 111_222_333, birth * 10**9 + 111_222_333),
             follow_symlinks=False)
    os.utime(path, ns=(mtime * 10**9 + 444_555_666, mtime * 10**9 + 444_555_666),
             follow_symlinks=False)


def write(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def make(root):
    os.makedirs(root)
    j = lambda *parts: os.path.join(root, *parts)

    write(j("plain.txt"), b"plain file\n")
    write(j("empty"), b"")
    os.mkdir(j("empty-dir"))

    # Quarantine, download origin, Finder info, tag, old creation date: one downloaded file.
    write(j("downloaded.pdf"), os.urandom(70_000))
    set_xattr(j("downloaded.pdf"), "com.apple.quarantine",
              b"0083;65a1b2c3;Safari;F1E2D3C4-B5A6-4978-8695-A4B3C2D1E0F9")
    set_xattr(j("downloaded.pdf"), "com.apple.metadata:kMDItemWhereFroms",
              plistlib.dumps(["https://example.org/files/report.pdf", "https://example.org/"],
                             fmt=plistlib.FMT_BINARY))
    finder_info = b"PDF CARO" + bytes(24)
    set_xattr(j("downloaded.pdf"), "com.apple.FinderInfo", finder_info)
    set_xattr(j("downloaded.pdf"), "com.apple.metadata:_kMDItemUserTags",
              plistlib.dumps(["Red\n6", "Tax 2026"], fmt=plistlib.FMT_BINARY))

    # Resource fork over 1 MiB.
    write(j("with-fork.bin"), b"data fork\n")
    write(j("with-fork.bin", "..namedfork", "rsrc"), os.urandom(1_600_000))

    # An ordinary attribute larger than one PXAR attribute record (64 KiB).
    write(j("big-xattr.txt"), b"big attribute\n")
    set_xattr(j("big-xattr.txt"), "org.example.big", os.urandom(200_000))

    # BSD flags.
    write(j("hidden.txt"), b"hidden\n")
    write(j("locked.txt"), b"locked\n")

    # ACLs: one on a file, an inherited one on a folder.
    write(j("acl-file.txt"), b"acl\n")
    os.mkdir(j("acl-dir"))
    write(j("acl-dir", "child.txt"), b"child\n")

    # Hard link, and symlinks (one carrying its own attribute, one dangling).
    write(j("link-a"), b"hard linked\n")
    os.link(j("link-a"), j("link-b"))
    os.symlink("plain.txt", j("symlink"))
    set_xattr(j("symlink"), "org.example.on-symlink", b"attribute on the link itself")
    os.symlink("does/not/exist", j("dangling"))

    # Names: decomposed and precomposed Unicode, kept in separate folders because APFS
    # treats them as the same name within one folder.
    os.mkdir(j("names"))
    os.mkdir(j("names", "nfd"))
    os.mkdir(j("names", "nfc"))
    write(j("names", "nfd", unicodedata.normalize("NFD", "été à Zürich.txt")), b"nfd\n")
    write(j("names", "nfc", unicodedata.normalize("NFC", "été à Zürich.txt")), b"nfc\n")
    write(j("names", "space and 'quote'.txt"), b"name\n")

    os.chmod(j("plain.txt"), 0o640)
    write(j("script.sh"), b"#!/bin/sh\n")
    os.chmod(j("script.sh"), 0o755)

    # Dates last, deepest first, because creating children changes a folder's dates.
    for dirpath, dirnames, filenames in os.walk(root, topdown=False):
        for name in filenames + dirnames:
            age(os.path.join(dirpath, name))
    age(root)

    # ACLs and flags after the dates: both can block later changes.
    subprocess.run(["/bin/chmod", "+a", "everyone deny delete", j("acl-file.txt")], check=True)
    subprocess.run(["/bin/chmod", "+a",
                    "staff allow list,search,add_file,file_inherit,directory_inherit",
                    j("acl-dir")], check=True)
    os.chflags(j("hidden.txt"), stat.UF_HIDDEN)
    os.chflags(j("locked.txt"), stat.UF_IMMUTABLE)


def remove(root):
    """Delete a fixture or a restored copy, clearing flags and ACLs that would refuse it."""
    if not os.path.lexists(root):
        return
    subprocess.run(["/usr/bin/chflags", "-R", "nouchg,nohidden", root], capture_output=True)
    subprocess.run(["/bin/chmod", "-R", "-N", root], capture_output=True)
    shutil.rmtree(root)


# --- compare ---------------------------------------------------------------

def scan(root):
    """Everything worth comparing about each entry below `root`, keyed by relative path bytes."""
    root_b = os.fsencode(root)
    entries = {}
    stack = [b""]
    while stack:
        rel = stack.pop()
        path = os.path.join(root_b, rel) if rel else root_b
        st = os.lstat(path)
        info = {
            "type": stat.S_IFMT(st.st_mode),
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid,
            "gid": st.st_gid,
            "flags": st.st_flags,
            "inode": (st.st_dev, st.st_ino),
            "nlink": st.st_nlink,
            "acl": acl_text(path),
            "xattrs": {name: hashlib.sha256(get_xattr(path, name)).hexdigest() + ":" +
                       str(len(get_xattr(path, name))) for name in list_xattrs(path)},
        }
        if stat.S_ISREG(st.st_mode):
            info["size"] = st.st_size
            info["sha256"] = sha256_file(path)
        elif stat.S_ISLNK(st.st_mode):
            info["target"] = os.readlink(path)
        elif stat.S_ISDIR(st.st_mode):
            for name in os.listdir(path):
                stack.append(os.path.join(rel, name) if rel else name)
        entries[rel or b"."] = info
    paths = sorted(entries)
    stamp = times([os.fsdecode(os.path.join(root_b, p)) if p != b"." else root for p in paths])
    for p in paths:
        full = os.fsdecode(os.path.join(root_b, p)) if p != b"." else root
        entries[p]["mtime"], entries[p]["birthtime"] = stamp[full]
    return entries


def hardlink_groups(entries):
    groups = {}
    for rel, info in entries.items():
        if info["type"] == stat.S_IFREG and info["nlink"] > 1:
            groups.setdefault(info["inode"], []).append(rel)
    return sorted(sorted(group) for group in groups.values())


def show(rel):
    return os.fsdecode(rel)


def compare(a_root, b_root, ignore_xattrs=()):
    a, b = scan(a_root), scan(b_root)
    diffs = []
    for rel in sorted(set(a) - set(b)):
        diffs.append(f"{show(rel)}: missing in {b_root}")
    for rel in sorted(set(b) - set(a)):
        diffs.append(f"{show(rel)}: only in {b_root} (name bytes {rel!r})")
    for rel in sorted(set(a) & set(b)):
        x, y = a[rel], b[rel]
        for field in ("type", "mode", "uid", "gid", "flags", "size", "sha256", "target",
                      "mtime", "birthtime", "acl"):
            if x.get(field) != y.get(field):
                diffs.append(f"{show(rel)}: {field} {x.get(field)!r} != {y.get(field)!r}")
        names = (set(x["xattrs"]) | set(y["xattrs"])) - set(ignore_xattrs)
        for name in sorted(names):
            if x["xattrs"].get(name) != y["xattrs"].get(name):
                diffs.append(f"{show(rel)}: xattr {name} "
                             f"{x['xattrs'].get(name, 'absent')} != {y['xattrs'].get(name, 'absent')}")
    if hardlink_groups(a) != hardlink_groups(b):
        diffs.append(f"hard links: {hardlink_groups(a)!r} != {hardlink_groups(b)!r}")
    return diffs, len(a)


# --- self test -------------------------------------------------------------

def selftest():
    work = tempfile.mkdtemp(prefix="pbs-tm-roundtrip-")
    src, copy = os.path.join(work, "src"), os.path.join(work, "copy")
    failures = []
    try:
        make(src)
        fixture = scan(src)
        expect = {
            "resource fork over 1 MiB": int(fixture[b"with-fork.bin"]["xattrs"][RESOURCE_FORK].split(":")[1]) > 1 << 20,
            "creation date older than modification date":
                float(fixture[b"downloaded.pdf"]["birthtime"]) < float(fixture[b"downloaded.pdf"]["mtime"]),
            "quarantine attribute": "com.apple.quarantine" in fixture[b"downloaded.pdf"]["xattrs"],
            "download origin": "com.apple.metadata:kMDItemWhereFroms" in fixture[b"downloaded.pdf"]["xattrs"],
            "Finder info": "com.apple.FinderInfo" in fixture[b"downloaded.pdf"]["xattrs"],
            "tag": "com.apple.metadata:_kMDItemUserTags" in fixture[b"downloaded.pdf"]["xattrs"],
            "BSD flags": fixture[b"hidden.txt"]["flags"] & stat.UF_HIDDEN and
                         fixture[b"locked.txt"]["flags"] & stat.UF_IMMUTABLE,
            "ACL on file": "deny" in fixture[b"acl-file.txt"]["acl"],
            "inherited ACL": "allow" in fixture[b"acl-dir"]["acl"],
            "hard link": hardlink_groups(fixture) == [[b"link-a", b"link-b"]],
            "symlink": fixture[b"symlink"].get("target") == b"plain.txt",
            "attribute on symlink": "org.example.on-symlink" in fixture[b"symlink"]["xattrs"],
            "decomposed name kept": os.fsencode(os.path.join("names", "nfd", unicodedata.normalize(
                "NFD", "été à Zürich.txt"))) in fixture,
        }
        failures += [f"fixture lacks: {name}" for name, ok in expect.items() if not ok]

        # A faithful copy must compare clean. ditto keeps forks, attributes, ACLs and hard
        # links but not creation dates or flags on every system, so the dates and flags
        # are copied by hand below.
        subprocess.run(["/usr/bin/ditto", src, copy], check=True)
        subprocess.run(["/usr/bin/chflags", "nouchg", os.path.join(copy, "locked.txt")], check=True)
        for rel, info in sorted(fixture.items(), key=lambda item: -item[0].count(b"/")):
            target = copy if rel == b"." else os.path.join(os.fsencode(copy), rel)
            age(target, birth=int(float(info["birthtime"])), mtime=int(float(info["mtime"])))
        age(copy)
        os.chflags(os.path.join(copy, "locked.txt"), stat.UF_IMMUTABLE)
        diffs, count = compare(src, copy, ignore_xattrs=SYSTEM_ATTRIBUTES)
        failures += [f"faithful copy reported: {d}" for d in diffs]

        # Each deliberate change must be reported.
        changes = {
            "sha256": lambda: write(os.path.join(copy, "plain.txt"), b"plain file!\n"),
            "xattr com.apple.quarantine": lambda: set_xattr(
                os.path.join(copy, "downloaded.pdf"), "com.apple.quarantine", b"0081;0;x;"),
            "xattr com.apple.ResourceFork": lambda: write(
                os.path.join(copy, "with-fork.bin", "..namedfork", "rsrc"), os.urandom(1_600_000)),
            "flags": lambda: os.chflags(os.path.join(copy, "hidden.txt"), 0),
            "acl": lambda: subprocess.run(
                ["/bin/chmod", "-N", os.path.join(copy, "acl-file.txt")], check=True),
            "birthtime": lambda: age(os.path.join(copy, "script.sh"), birth=OLD - 86400),
            "hard links": lambda: (os.unlink(os.path.join(copy, "link-b")),
                                   shutil.copyfile(os.path.join(copy, "link-a"),
                                                   os.path.join(copy, "link-b"))),
            "only in": lambda: os.rename(
                os.path.join(copy, "names", "nfd", unicodedata.normalize("NFD", "été à Zürich.txt")),
                os.path.join(copy, "names", "nfd", unicodedata.normalize("NFC", "été à Zürich.txt"))),
        }
        for needle, change in changes.items():
            change()
            diffs, _ = compare(src, copy, ignore_xattrs=SYSTEM_ATTRIBUTES)
            if not any(needle in d for d in diffs):
                failures.append(f"change not detected: {needle}")
    finally:
        remove(work)
    for line in failures:
        print("FAIL " + line)
    print("selftest " + ("ok" if not failures else "failed"))
    return 0 if not failures else 1


# --- tests against PBS -------------------------------------------------------

class Failed(Exception):
    pass


def check(condition, message):
    if not condition:
        raise Failed(message)


class Server:
    def __init__(self, work):
        self.env = dict(os.environ)
        if not self.env.get("PBS_REPOSITORY") or not self.env.get("PBS_TEST_NS"):
            sys.exit("PBS_REPOSITORY and PBS_TEST_NS must be set; see the top of this file")
        service = self.env.get("PBS_TEST_KEYCHAIN_SERVICE")
        if service:
            found = subprocess.run(["/usr/bin/security", "find-generic-password", "-s", service, "-w"],
                                   capture_output=True, text=True)
            if found.returncode != 0:
                sys.exit(f"no Keychain item for service {service}")
            self.env["PBS_PASSWORD"] = found.stdout.strip()
        self.ns = self.env["PBS_TEST_NS"]
        here = os.path.dirname(os.path.abspath(__file__))
        self.client = os.path.expanduser(self.env.get("PBS_TEST_CLIENT", os.path.join(
            here, "..", "..", "native-target", "release", "proxmox-backup-client")))
        self.keyfile = os.path.join(work, "test.key")
        self.run("key", "create", self.keyfile, "--kdf", "none", scoped=False)

    def run(self, *args, scoped=True, key=True, keyfile=None, ok=True):
        """Runs the client; returns (status, standard output, standard error)."""
        command = [self.client, *args]
        if scoped:
            command += ["--ns", self.ns]
        if scoped and key:
            command += ["--keyfile", keyfile or self.keyfile]
        done = subprocess.run(command, env=self.env, capture_output=True, text=True)
        if ok and done.returncode != 0:
            raise Failed(f"{' '.join(args[:2])} exited {done.returncode}: {done.stderr.strip()[-400:]}")
        return done.returncode, done.stdout, done.stderr

    def backup(self, backup_id, archive, folder, *options):
        """Backs up and returns (snapshot name, client log)."""
        time.sleep(1.1)   # snapshot names have a resolution of one second
        _, out, err = self.run("backup", f"{archive}:{folder}", "--backup-id", backup_id,
                               "--crypt-mode", "encrypt", *options)
        self.records = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        log = out + err
        for line in log.splitlines():
            if line.startswith("Starting backup: "):
                return line.split("]:")[-1].replace("Starting backup: ", "").strip(), log
        raise Failed("the client did not name the snapshot it wrote")

    def listing(self, snapshot, archive, path=None, **kwargs):
        arguments = ["catalog", "list", snapshot, archive] + ([path] if path else [])
        status, out, err = self.run(*arguments, **kwargs)
        return status, (json.loads(out) if status == 0 else None), err


def test_round_trip(server, work, state):
    src, restored = os.path.join(work, "src"), os.path.join(work, "restored")
    make(src)
    snapshot, _ = server.backup("pbs-client-test-roundtrip", "fixture.pxar", src)
    state.update(src=src, snapshot=snapshot)
    server.run("restore", snapshot, "fixture.pxar", restored)
    diffs, count = compare(src, restored, SYSTEM_ATTRIBUTES)
    check(not diffs, f"{len(diffs)} differences after restore: " + "; ".join(diffs[:5]))
    return f"{count} entries identical after restore"


def test_catalog_list(server, work, state):
    snapshot = state["snapshot"]
    started = time.monotonic()
    _, root, _ = server.listing(snapshot, "fixture.pxar")
    elapsed = time.monotonic() - started
    by_name = {entry["name"]: entry for entry in root}
    check(set(by_name) == set(os.listdir(state["src"])), f"root lists {sorted(by_name)}")
    check(by_name["names"]["type"] == "directory" and by_name["symlink"]["type"] == "symlink",
          "wrong entry types in the root listing")
    check(by_name["downloaded.pdf"] == {"name": "downloaded.pdf", "type": "file", "size": 70_000,
                                        "mtime": LATER}, f"downloaded.pdf listed as {by_name['downloaded.pdf']}")
    check(by_name["link-b"]["type"] in ("file", "hardlink"), "hard link missing from the listing")

    _, nested, _ = server.listing(snapshot, "fixture.pxar", "names/nfd")
    check([entry["name"] for entry in nested] == [unicodedata.normalize("NFD", "été à Zürich.txt")],
          f"nested listing is {nested}")

    status, _, err = server.listing(snapshot, "fixture.pxar", "names/missing", ok=False)
    check(status != 0 and "no such path" in err, f"missing path gave status {status}: {err.strip()[-200:]}")
    status, _, err = server.listing(snapshot, "fixture.pxar", "plain.txt", ok=False)
    check(status != 0 and "not a directory" in err, f"a file as path gave status {status}")
    check(elapsed < 5, f"root listing took {elapsed:.1f} s")

    def everything(snapshot, archive, *path, **kwargs):
        _, out, _ = server.run("catalog", "list", snapshot, archive, *path, "--recursive", "true", **kwargs)
        return [json.loads(line) for line in out.splitlines()]

    expected = {os.path.relpath(os.path.join(folder, name), state["src"])
                for folder, folders, files in os.walk(state["src"]) for name in folders + files}
    listed = everything(snapshot, "fixture.pxar")
    check({entry["path"] for entry in listed} == expected and len(listed) == len(expected),
          f"the recursive listing has {len(listed)} entries, the source {len(expected)}")
    check(all(entry["path"].split("/")[-1] == entry["name"] for entry in listed), "a path does not end in its name")
    below = everything(snapshot, "fixture.pxar", "names")
    check({entry["path"] for entry in below} == {path for path in expected if path.startswith("names/")},
          f"the recursive listing below names/ is {sorted(entry['path'] for entry in below)}")

    large = server.env.get("PBS_TEST_LARGE")
    if not large:
        return (f"root, nested, missing path ok; root in {elapsed:.2f} s; all {len(listed)} entries "
                "recursively (no large snapshot given)")
    large_snapshot, large_archive = large.split()
    keyfile = os.path.expanduser(server.env["PBS_TEST_LARGE_KEYFILE"])
    started = time.monotonic()
    _, entries, _ = server.listing(large_snapshot, large_archive, keyfile=keyfile)
    large_elapsed = time.monotonic() - started
    check(large_elapsed < 5, f"listing the large snapshot took {large_elapsed:.1f} s")
    started = time.monotonic()
    count = len(everything(large_snapshot, large_archive, keyfile=keyfile))
    return (f"root, nested, missing path ok; root in {elapsed:.2f} s; "
            f"{len(entries)} entries of {large_snapshot} in {large_elapsed:.2f} s, "
            f"all {count} recursively in {time.monotonic() - started:.2f} s")


def test_catalog_extract(server, work, state):
    snapshot, src = state["snapshot"], state["src"]
    folder_target, file_target = os.path.join(work, "one-folder"), os.path.join(work, "one-file")
    server.run("catalog", "extract", snapshot, "fixture.pxar", "acl-dir", folder_target)
    check(os.listdir(folder_target) == ["acl-dir"], f"target holds {os.listdir(folder_target)}")
    diffs, count = compare(os.path.join(src, "acl-dir"), os.path.join(folder_target, "acl-dir"), SYSTEM_ATTRIBUTES)
    check(not diffs, "folder differs: " + "; ".join(diffs[:5]))

    server.run("catalog", "extract", snapshot, "fixture.pxar", "names/nfd", file_target)
    server.run("catalog", "extract", snapshot, "fixture.pxar", "downloaded.pdf", file_target)
    check(sorted(os.listdir(file_target)) == ["downloaded.pdf", "nfd"], f"target holds {os.listdir(file_target)}")
    file_diffs, _ = compare(os.path.join(src, "downloaded.pdf"), os.path.join(file_target, "downloaded.pdf"),
                            SYSTEM_ATTRIBUTES)
    check(not file_diffs, "file differs: " + "; ".join(file_diffs[:5]))

    status, _, err = server.run("catalog", "extract", snapshot, "fixture.pxar", "nope", folder_target, ok=False)
    check(status != 0 and "no such path" in err, f"missing path gave status {status}")
    return f"one folder ({count} entries) and one file extracted alone, identical"


def test_change_detection(server, work, state):
    tree = os.path.join(work, "attributed")
    os.makedirs(os.path.join(tree, "sub"))
    for number in range(40):
        path = os.path.join(tree, "sub" if number % 2 else "", f"file-{number}.bin")
        write(path, os.urandom(50_000))
        set_xattr(path, "com.apple.quarantine", b"0083;65a1b2c3;Safari;")
        set_xattr(path, "com.apple.metadata:_kMDItemUserTags", plistlib.dumps(["Red\n6"], fmt=plistlib.FMT_BINARY))
    server.backup("pbs-client-test-detect", "tree.pxar", tree, "--change-detection-mode=metadata")
    _, log = server.backup("pbs-client-test-detect", "tree.pxar", tree, "--change-detection-mode=metadata")
    check("- 40 unchanged, reusable files" in log, "second run did not reuse all 40 files:\n" + log[-600:])
    check("- 0 changed or non-reusable files with 0 B data" in log, "second run reread files:\n" + log[-600:])
    payload = next((line for line in log.splitlines() if line.startswith("tree.ppxar: had to backup ")), "")
    uploaded = payload.split("had to backup ")[-1].split(" of ")[0]
    check(uploaded.endswith(" B") and float(uploaded.split()[0]) < 4096,
          f"second run uploaded file data: {payload}")
    return f"40 of 40 files with attributes reused, {uploaded} of padding uploaded"


def human_bytes(text):
    """'1.5 MiB' as a number of bytes."""
    number, unit = text.split()
    return float(number) * 1024 ** ["B", "KiB", "MiB", "GiB", "TiB"].index(unit)


def test_changed_dirs(server, work, state):
    tree, restored = os.path.join(work, "changing"), os.path.join(work, "changing-restored")
    j = lambda *parts: os.path.join(tree, *parts)
    for folder in ("a/deep/deeper", "b/sub", "c", "links", "names/nfd", "quiet/inner", "rec/r1/r2"):
        os.makedirs(j(folder))
    files = ["top.bin", "a/a1.bin", "a/a2.bin", "a/deep/d1.bin", "a/deep/d2.bin", "a/deep/deeper/x.bin",
             "b/b1.bin", "b/sub/s1.bin", "c/c1.bin", "c/c2.bin", "rec/r1/r2/deep.bin",
             "names/nfd/" + unicodedata.normalize("NFD", "été à Zürich.txt")]
    for name in files:
        write(j(name), os.urandom(40_000))
        set_xattr(j(name), "com.apple.quarantine", b"0083;65a1b2c3;Safari;" + name.encode())
    for name in ("quiet/q1.bin", "quiet/q2.bin", "quiet/inner/q3.bin"):     # most of the data
        write(j(name), os.urandom(2_000_000))
        set_xattr(j(name), "com.apple.metadata:_kMDItemUserTags", plistlib.dumps(["Red\n6"], fmt=plistlib.FMT_BINARY))
    write(j("b/with-fork.bin"), b"data fork\n")
    write(j("b/with-fork.bin", "..namedfork", "rsrc"), os.urandom(1_600_000))
    os.symlink("b1.bin", j("b/symlink"))
    # Hard links: within a folder, and across folders of which, in the second run, both are
    # carried over, only the target is, or only the link is.
    write(j("links/link-a"), os.urandom(40_000))
    os.link(j("links/link-a"), j("links/link-b"))
    for target, link in (("quiet/inner/t1.bin", "rec/r1/l1"), ("a/deep/deeper/t2.bin", "c/l2"),
                         ("b/sub/t3.bin", "quiet/l3")):
        write(j(target), os.urandom(40_000))
        os.link(j(target), j(link))
    time.sleep(1.1)     # a change within the same second as the backup is not what is tested

    def run(base, *records):
        """Backs up with a change list of (kind, path) relative to `base`; returns the result record."""
        listing = os.path.join(work, "changed-dirs")
        write(listing, b"".join(kind.encode() + os.fsencode(path) + b"\0" for kind, path in records))
        snapshot, log = server.backup("pbs-client-test-changed", "tree.pxar", tree,
                                      "--change-detection-mode=metadata", "--progress-json", "true",
                                      "--changed-dirs", listing, "--changed-dirs-base", base.split("/")[-1])
        result = server.records[-1]
        result["log"] = log
        return snapshot, result

    def same_as_source(snapshot, what):
        remove(restored)
        server.run("restore", snapshot, "tree.pxar", restored)
        diffs, count = compare(tree, restored, SYSTEM_ATTRIBUTES)
        check(not diffs, f"{what}: {len(diffs)} differences after restore: " + "; ".join(diffs[:5]))
        return count

    def restored_file(snapshot, path):
        target = os.path.join(work, "changing-one")
        remove(target)
        server.run("catalog", "extract", snapshot, "tree.pxar", path, target)
        return sha256_file(os.path.join(target, os.path.basename(path)))

    # No previous snapshot: the list cannot be used, everything is read.
    first, result = run("host/x/2020-01-01T00:00:00Z", ("d", j("a")))
    check(result["change_list"].startswith("ignored") and result["carried_dirs"] == 0,
          f"first backup: change list {result['change_list']}, {result['carried_dirs']} carried")
    same_as_source(first, "first backup")

    # A file changed in place, one added, one deleted, the mode of two folders changed.
    write(j("a/deep/d1.bin"), os.urandom(40_000))
    write(j("c/new.bin"), os.urandom(40_000))
    set_xattr(j("c/new.bin"), "org.example.new", b"new attribute value")
    os.remove(j("a/a1.bin"))
    os.chmod(j("names"), 0o700)       # reported for its parent, the root
    os.chmod(j("b/sub"), 0o700)       # reported for the folder itself
    second, result = run(first, ("d", j("a/deep")), ("d", os.path.realpath(j("c"))), ("d", j("a")),
                         ("d", tree), ("d", j("b/sub")), ("d", j("gone/never/was")), ("d", "/elsewhere"))
    check(result["change_list"] == "used", f"second backup: change list {result['change_list']}")
    check(result["carried_dirs"] >= 8, f"only {result['carried_dirs']} directories carried over")
    check(result["walked_dirs"] <= 8, f"{result['walked_dirs']} directories read")
    payload = next(line for line in result["log"].splitlines() if line.startswith("tree.ppxar: had to backup "))
    uploaded = human_bytes(payload.split("had to backup ")[-1].split(" of ")[0])
    check(uploaded < 1_000_000, f"carried files were uploaded again: {payload}")
    count = same_as_source(second, "second backup")
    _, out, _ = server.run("catalog", "list", second, "tree.pxar", "--recursive", "true")
    listed = len(out.splitlines())
    check(listed == count - 1, f"the listing has {listed} entries, the tree {count - 1}")

    # A third run on top of one that carried directories over; and an 'r' record: a change deep
    # below it, in a folder not named itself, is picked up.
    # A new folder that the list names while it leaves out the folder it was made in: that
    # one is read all the same.
    write(j("rec/r1/r2/deep.bin"), os.urandom(40_000))
    write(j("b/b1.bin"), os.urandom(40_000))
    os.makedirs(j("names/nfd/made/since"))
    write(j("names/nfd/made/since/late.bin"), os.urandom(1_000))
    third, result = run(second, ("r", j("rec")), ("d", j("b")), ("d", j("names/nfd/made/since")))
    check(result["change_list"] == "used" and result["carried_dirs"] >= 6,
          f"third backup: change list {result['change_list']}, {result['carried_dirs']} carried")
    same_as_source(third, "third backup")

    # What is not named is not looked at: a folder that cannot even be opened is carried over,
    # and a file replaced behind the list's back keeps its previous contents in the snapshot.
    before = sha256_file(j("quiet/q1.bin"))
    stamp = os.stat(j("quiet/q1.bin"))
    write(j("quiet/q1.bin"), os.urandom(2_000_000))
    os.utime(j("quiet/q1.bin"), ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    os.chmod(j("quiet/inner"), 0)
    try:
        fourth, result = run(third, ("d", j("c")))
    finally:
        os.chmod(j("quiet/inner"), 0o755)
    check(result["change_list"] == "used" and not result["warnings"],
          f"fourth backup: change list {result['change_list']}, warnings {result['warnings']}")
    check(restored_file(fourth, "quiet/q1.bin") == before, "an unnamed folder was read from disk")
    check(restored_file(fourth, "quiet/inner/q3.bin") == sha256_file(j("quiet/inner/q3.bin")),
          "a folder that was not readable is not carried over whole")

    # A list relative to another snapshot than the previous one: ignored, everything is read.
    # The replaced file has its old size and dates, so only its contents tell; a full walk in
    # metadata mode trusts those too. Give it a new date, as any real change would.
    os.utime(j("quiet/q1.bin"))
    fifth, result = run(second, ("d", j("c")))
    check(result["change_list"].startswith("ignored") and result["carried_dirs"] == 0,
          f"wrong base: change list {result['change_list']}, {result['carried_dirs']} carried")
    same_as_source(fifth, "backup with a list for another snapshot")

    # More entries than are held back at once while carrying over, in folders nothing names.
    many, listing = os.path.join(work, "many"), os.path.join(work, "changed-dirs")
    for folder in ("one", "one/two", "three"):
        os.makedirs(os.path.join(many, folder))
        for number in range(3000):
            write(os.path.join(many, folder, f"file-{number:04d}"), b"%d" % number)
    time.sleep(1.1)
    options = ("--change-detection-mode=metadata", "--progress-json", "true")
    full, _ = server.backup("pbs-client-test-changed-many", "many.pxar", many, *options)
    write(os.path.join(many, "three", "file-1500"), b"changed")
    write(listing, b"d" + os.fsencode(os.path.join(many, "three")) + b"\0")
    carried, _ = server.backup("pbs-client-test-changed-many", "many.pxar", many, *options,
                               "--changed-dirs", listing, "--changed-dirs-base", full.split("/")[-1])
    result = server.records[-1]
    check(result["change_list"] == "used" and result["carried_dirs"] == 2 and result["walked_dirs"] == 2,
          f"many entries: {result['carried_dirs']} carried, {result['walked_dirs']} read")
    remove(restored)
    server.run("restore", carried, "many.pxar", restored)
    diffs, many_count = compare(many, restored, SYSTEM_ATTRIBUTES)
    check(not diffs, f"many entries: {len(diffs)} differences after restore: " + "; ".join(diffs[:5]))

    # A list without the snapshot it is relative to, and a file that is no list, are refused.
    status, _, err = server.run("backup", f"tree.pxar:{tree}", "--backup-id", "pbs-client-test-changed",
                                "--changed-dirs", listing, ok=False)
    check(status != 0 and "only used together" in err, f"a list without its base gave status {status}")
    write(listing, b"x/not/a/record\0")
    status, _, err = server.run("backup", f"tree.pxar:{tree}", "--backup-id", "pbs-client-test-changed",
                                "--changed-dirs", listing, "--changed-dirs-base", fifth.split("/")[-1], ok=False)
    check(status != 0 and "unknown record kind" in err, f"a file that is no list gave status {status}")
    return (f"{count} entries identical after one and two carried runs, hard links kept; an unreadable "
            f"and a silently replaced folder carried over; {many_count} entries carried in one go; "
            f"wrong base ignored")


def test_progress_records(server, work, state):
    tree = os.path.join(work, "slow")
    os.makedirs(tree)
    for number in range(8):
        write(os.path.join(tree, f"blob-{number}"), os.urandom(1_000_000))
    # Slowed down so that the upload takes a few seconds.
    snapshot, _ = server.backup("pbs-client-test-progress", "slow.pxar", tree,
                                "--progress-json", "true", "--rate", "2MiB", "--burst", "2MiB")
    progress = [record for record in server.records if record["type"] == "progress"]
    results = [record for record in server.records if record["type"] == "result"]
    check(len(results) == 1 and server.records[-1] is results[0], "no single result record at the end")
    result = results[0]
    check(len(progress) >= 2, f"only {len(progress)} progress records in {result['duration']} s")
    times = [0.0] + [record["elapsed"] for record in progress] + [result["duration"]]
    gap = max(later - earlier for earlier, later in zip(times, times[1:]))
    check(gap <= 2.0, f"{gap:.1f} s without a record")
    sent = [record.get("bytes_sent", -1) for record in progress] + [result.get("bytes_sent", -1)]
    check(sent == sorted(sent) and sent[0] >= 0 and sent[-1] > 0, f"bytes sent over the network go {sent}")
    check(all({"entries", "bytes_processed", "bytes_uploaded", "path"} <= set(record) for record in progress),
          "a progress record lacks a field")
    check(any(record["path"].lstrip("/").startswith("blob-") for record in progress),
          f"no progress record names a file: {[record['path'] for record in progress]}")
    check(result["ok"] is True and result["snapshot"] == snapshot and result["namespace"] == server.ns,
          f"result names {result.get('snapshot')} in {result.get('namespace')}, backup wrote {snapshot}")
    check(result["entries"] == 8, f"result counts {result['entries']} entries")
    check(result["bytes_processed"] >= 8_000_000 and result["bytes_uploaded"] >= 8_000_000,
          f"result counts {result['bytes_processed']} processed, {result['bytes_uploaded']} uploaded")
    check(result["skipped_placeholder_count"] == 0 and result["time_machine_excluded"] == 0,
          "result reports skipped items in a plain tree")

    _, out, _ = server.run("snapshot", "list", "host/pbs-client-test-progress",
                           "--output-format", "json", key=False)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(max(s["backup-time"] for s in json.loads(out))))
    check(snapshot.endswith("/" + stamp), f"server's newest snapshot is {stamp}, result says {snapshot}")

    status, out, _ = server.run("backup", f"gone.pxar:{tree}-missing", "--backup-id",
                                "pbs-client-test-progress", "--progress-json", "true", ok=False)
    check(status != 0, "a backup of a missing folder exited 0")
    return f"{len(progress)} progress records, longest gap {gap:.1f} s, result matches the server"


def test_time_machine_exclusions(server, work, state):
    tree = os.path.join(work, "excluding")
    os.makedirs(os.path.join(tree, "build", "sub"))
    os.makedirs(os.path.join(tree, "other"))
    for name in ("keep.txt", "cache.bin", "build/a", "build/sub/b", "other/keep-too.txt"):
        write(os.path.join(tree, name), b"x" * 2000)
    marker = plistlib.dumps("com.apple.backupd", fmt=plistlib.FMT_BINARY)
    for name in ("build", "cache.bin"):
        set_xattr(os.path.join(tree, name), "com.apple.metadata:com_apple_backup_excludeItem", marker)

    snapshot, _ = server.backup("pbs-client-test-exclude", "tree.pxar", tree,
                                "--skip-tm-excluded", "true", "--progress-json", "true")
    result = server.records[-1]
    check(result["time_machine_excluded"] == 2, f"result counts {result['time_machine_excluded']} excluded")
    _, root, _ = server.listing(snapshot, "tree.pxar")
    check({entry["name"] for entry in root} == {"keep.txt", "other"},
          f"snapshot root holds {[entry['name'] for entry in root]}")

    snapshot, _ = server.backup("pbs-client-test-exclude", "tree.pxar", tree)
    _, root, _ = server.listing(snapshot, "tree.pxar")
    check({entry["name"] for entry in root} == {"keep.txt", "other", "build", "cache.bin"},
          "without the option the marked entries are missing too")
    return "a marked folder with its contents and a marked file left out and counted as 2"


def test_unreadable_files(server, work, state):
    tree = os.path.join(work, "guarded")
    os.makedirs(tree)
    write(os.path.join(tree, "open.txt"), b"readable")
    write(os.path.join(tree, "closed.txt"), b"not readable")
    os.chmod(os.path.join(tree, "closed.txt"), 0)
    # A socket cannot be opened at all on macOS, and a pipe nobody writes to must not make the
    # backup wait. The socket's path has a short limit, so it is bound from inside the folder.
    os.mkfifo(os.path.join(tree, "pipe"))
    listening = socket.socket(socket.AF_UNIX)
    here = os.getcwd()
    os.chdir(tree)
    try:
        listening.bind("listening")
    finally:
        os.chdir(here)
    try:
        snapshot, _ = server.backup("pbs-client-test-unreadable", "tree.pxar", tree, "--progress-json", "true")
    finally:
        os.chmod(os.path.join(tree, "closed.txt"), 0o600)
        listening.close()
    result = server.records[-1]
    check(result["ok"] is True, "the backup failed because of one unreadable file")
    check(any("closed.txt" in warning for warning in result["warnings"]), f"warnings are {result['warnings']}")
    _, root, _ = server.listing(snapshot, "tree.pxar")
    check(sorted(entry["name"] for entry in root) == ["open.txt", "pipe"], f"snapshot holds {[entry['name'] for entry in root]}")
    check(len(result["warnings"]) == 1, f"warnings are {result['warnings']}")
    return "one unreadable file left out and named, a socket left out, the rest backed up with a pipe"


def test_placeholders(server, work, state):
    folder = server.env.get("PBS_TEST_PLACEHOLDER_DIR")
    if not folder:
        return "SKIPPED, no PBS_TEST_PLACEHOLDER_DIR"
    folder = os.path.expanduser(folder)
    dataless = [name for name in os.listdir(folder)
                if os.lstat(os.path.join(folder, name)).st_flags & 0x40000000]
    check(dataless, f"{folder} holds no placeholder")
    snapshot, _ = server.backup("pbs-client-test-placeholder", "cloud.pxar", folder,
                                "--skip-placeholders", "true", "--progress-json", "true")
    result = server.records[-1]
    check(result["ok"] and result["skipped_placeholder_count"] >= len(dataless),
          f"result counts {result['skipped_placeholder_count']} placeholders, the folder has {len(dataless)}")
    check(all(any(path.endswith(name) for path in result["skipped_placeholders"]) for name in dataless),
          f"result names {result['skipped_placeholders']}, expected {dataless}")
    _, root, _ = server.listing(snapshot, "cloud.pxar")
    check(not {entry["name"] for entry in root} & set(dataless), "a placeholder is in the snapshot")
    still = [name for name in dataless if os.lstat(os.path.join(folder, name)).st_flags & 0x40000000]
    check(still == dataless, "the backup downloaded a placeholder")
    time.sleep(1.1)   # not in the same second as the snapshot above
    status, _, err = server.run("backup", f"cloud.pxar:{folder}", "--backup-id",
                                "pbs-client-test-placeholder", "--crypt-mode", "encrypt", ok=False)
    check(status != 0 and "dataless" in err,
          f"without the option the backup exited {status}: {err.strip()[-200:]}")
    return f"{len(dataless)} placeholder(s) left out, named, not downloaded"


FUSE_T_LIBRARY = "/usr/local/lib/libfuse3.dylib"


def mounted_view(root):
    """What a mount shows of every entry below root. Names are compared composed, because the
    mount goes through NFS and macOS may hand names back in another normalization."""
    seen = {}
    for folder, folders, files in os.walk(root):
        for name in folders + files:
            path = os.path.join(folder, name)
            info = os.lstat(path)
            rel = unicodedata.normalize("NFC", os.path.relpath(path, root))
            if stat.S_ISLNK(info.st_mode):
                seen[rel] = ("link", os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                seen[rel] = ("folder", int(info.st_mtime))
            else:
                seen[rel] = ("file", sha256_file(path), info.st_size, stat.S_IMODE(info.st_mode), int(info.st_mtime))
    return seen


def is_mounted(path):
    return os.stat(path).st_dev != os.stat(os.path.dirname(path)).st_dev


def test_mount(server, work, state):
    if not os.path.exists(FUSE_T_LIBRARY):
        return "SKIPPED (FUSE-T is not installed)"
    src = state["src"]
    split, _ = server.backup("pbs-client-test-roundtrip", "fixture.pxar", src, "--change-detection-mode=metadata")
    expected = mounted_view(src)
    for kind, snapshot in (("plain", state["snapshot"]), ("split", split)):
        target = os.path.join(work, f"mounted-{kind}")
        os.mkdir(target)
        server.run("mount", snapshot, "fixture.pxar", target)
        try:
            check(is_mounted(target), f"{kind}: mount returned but nothing is mounted")
            shown = mounted_view(target)
            wrong = sorted(name for name in set(expected) | set(shown) if expected.get(name) != shown.get(name))
            check(not wrong, f"{kind}: {len(wrong)} entries differ from the source: " + "; ".join(wrong[:5]))
            try:
                write(os.path.join(target, "new-file"), b"x")
                raise Failed(f"{kind}: a file could be created in the mount")
            except OSError:
                pass
        finally:
            subprocess.run(["/sbin/umount", target], capture_output=True)
        for _ in range(50):
            running = subprocess.run(["/usr/bin/pgrep", "-f", f"proxmox-backup-client mount .* {target}"],
                                     capture_output=True).returncode == 0
            if not running and not is_mounted(target):
                break
            time.sleep(0.1)
        check(not running, f"{kind}: the client kept running after the unmount")
    status, _, err = server.run("mount", "host/pbs-client-test-roundtrip/2001-01-01T00:00:00Z", "fixture.pxar",
                                target, ok=False)
    check(status != 0, "mounting a snapshot that does not exist reported success")
    return f"plain and split archive mounted, {len(expected)} entries each identical to the source, read-only"


def test_without_fuse_t(server, work, state):
    """Points a copy of the client at a library path that does not exist, which is what the
    client finds on a Mac without FUSE-T."""
    copy = os.path.join(work, "client-without-fuse-t")
    shutil.copy(server.client, copy)
    subprocess.run(["/usr/bin/install_name_tool", "-change", "@rpath/libfuse3.4.dylib",
                    "/nonexistent/libfuse3.4.dylib", copy], check=True, capture_output=True)
    subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", copy], check=True, capture_output=True)
    target = os.path.join(work, "not-mounted")
    os.mkdir(target)
    original, server.client = server.client, copy
    try:
        _, entries, _ = server.listing(state["snapshot"], "fixture.pxar")
        check(entries, "the client without FUSE-T did not list the snapshot")
        status, _, err = server.run("mount", state["snapshot"], "fixture.pxar", target, ok=False)
    finally:
        server.client = original
    check(status != 0, "mount without FUSE-T reported success")
    check("FUSE-T" in err, f"mount without FUSE-T does not name it: {err.strip()[-200:]}")
    check(not is_mounted(target), "something is mounted")
    return "listing works; mount fails and names FUSE-T"


def run_all():
    work = tempfile.mkdtemp(prefix="pbs-client-test-")
    failed = 0
    try:
        server = Server(work)
        state = {}
        for test in (test_round_trip, test_catalog_list, test_catalog_extract, test_change_detection,
                     test_changed_dirs, test_progress_records, test_time_machine_exclusions, test_unreadable_files,
                     test_placeholders, test_mount, test_without_fuse_t):
            name = test.__name__[5:].replace("_", " ")
            try:
                outcome = test(server, work, state)
                print(f"{'skip ' if outcome.startswith('SKIPPED') else 'ok   '} {name}: {outcome}")
            except (Failed, KeyError, OSError, subprocess.CalledProcessError) as error:
                failed += 1
                print(f"FAIL  {name}: {error}")
    finally:
        remove(work)
    print("all tests passed" if not failed else f"{failed} test(s) failed")
    return 0 if not failed else 1


def main(argv):
    if argv[1:] == ["selftest"]:
        return selftest()
    if len(argv) == 1:
        return run_all()
    sys.exit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
