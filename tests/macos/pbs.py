#!/usr/bin/python3
"""Tests of the macOS client against a Proxmox Backup Server namespace.

  pbs.py            run all tests; exit status 0 only when every one passed
  pbs.py selftest   check the comparison itself, without a server

What is tested:
  round trip         a fixture with Mac metadata is backed up encrypted, restored and compared:
                     contents, names byte for byte, modes, owners, BSD flags, modification and
                     creation times, every extended attribute including the resource fork,
                     ACLs, link targets and hard links
  catalog list       one directory as JSON: root, nested path, missing path
  catalog extract    one folder and one file, each into an empty target, with their metadata
  change detection   a second run over an unchanged tree in which every file carries an
                     extended attribute reuses everything and uploads no file data

Environment:
  PBS_REPOSITORY             as for the client (required)
  PBS_PASSWORD, PBS_PASSWORD_FILE ...  as for the client; or
  PBS_TEST_KEYCHAIN_SERVICE  name of a login Keychain item holding the token secret
  PBS_TEST_NS                namespace to write to (required); the token needs DatastoreBackup there
  PBS_TEST_CLIENT            client binary (default native-target/release/proxmox-backup-client)
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
        diffs, count = compare(src, copy, ignore_xattrs=("com.apple.provenance",))
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
            diffs, _ = compare(src, copy, ignore_xattrs=("com.apple.provenance",))
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

    def run(self, *args, scoped=True, keyfile=None, ok=True):
        """Runs the client; returns (status, standard output, standard error)."""
        command = [self.client, *args]
        if scoped:
            command += ["--ns", self.ns, "--keyfile", keyfile or self.keyfile]
        done = subprocess.run(command, env=self.env, capture_output=True, text=True)
        if ok and done.returncode != 0:
            raise Failed(f"{' '.join(args[:2])} exited {done.returncode}: {done.stderr.strip()[-400:]}")
        return done.returncode, done.stdout, done.stderr

    def backup(self, backup_id, archive, folder, *options):
        """Backs up and returns (snapshot name, client log)."""
        time.sleep(1.1)   # snapshot names have a resolution of one second
        _, out, err = self.run("backup", f"{archive}:{folder}", "--backup-id", backup_id,
                               "--crypt-mode", "encrypt", *options)
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
    diffs, count = compare(src, restored)
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

    large = server.env.get("PBS_TEST_LARGE")
    if not large:
        return f"root, nested, missing path ok; root in {elapsed:.2f} s (no large snapshot given)"
    large_snapshot, large_archive = large.split()
    started = time.monotonic()
    _, entries, _ = server.listing(large_snapshot, large_archive,
                                   keyfile=os.path.expanduser(server.env["PBS_TEST_LARGE_KEYFILE"]))
    large_elapsed = time.monotonic() - started
    check(large_elapsed < 5, f"listing the large snapshot took {large_elapsed:.1f} s")
    return (f"root, nested, missing path ok; root in {elapsed:.2f} s; "
            f"{len(entries)} entries of {large_snapshot} in {large_elapsed:.2f} s")


def test_catalog_extract(server, work, state):
    snapshot, src = state["snapshot"], state["src"]
    folder_target, file_target = os.path.join(work, "one-folder"), os.path.join(work, "one-file")
    server.run("catalog", "extract", snapshot, "fixture.pxar", "acl-dir", folder_target)
    check(os.listdir(folder_target) == ["acl-dir"], f"target holds {os.listdir(folder_target)}")
    diffs, count = compare(os.path.join(src, "acl-dir"), os.path.join(folder_target, "acl-dir"))
    check(not diffs, "folder differs: " + "; ".join(diffs[:5]))

    server.run("catalog", "extract", snapshot, "fixture.pxar", "names/nfd", file_target)
    server.run("catalog", "extract", snapshot, "fixture.pxar", "downloaded.pdf", file_target)
    check(sorted(os.listdir(file_target)) == ["downloaded.pdf", "nfd"], f"target holds {os.listdir(file_target)}")
    file_diffs, _ = compare(os.path.join(src, "downloaded.pdf"), os.path.join(file_target, "downloaded.pdf"))
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


def run_all():
    work = tempfile.mkdtemp(prefix="pbs-client-test-")
    failed = 0
    try:
        server = Server(work)
        state = {}
        for test in (test_round_trip, test_catalog_list, test_catalog_extract, test_change_detection):
            name = test.__name__[5:].replace("_", " ")
            try:
                print(f"ok    {name}: {test(server, work, state)}")
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
