//! Versioned native metadata carried by ordinary PXAR xattrs and payload files.
//! Server protocols and the PXAR wire format remain unchanged.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Error, bail};
use openssl::sha::{Sha256, sha256};
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};

use super::Flags;
use super::darwin_metadata::{Acl, BirthTime, ForkReader, ForkWriter};

const PREFIX: &str = "user.proxmox.macos.v1";
const PART: usize = 60 * 1024;
const MAX_HEADER: usize = 4 * 1024 * 1024;
const MAX_ATTRIBUTES: usize = 4096;
/// A value up to this size is kept in memory, not in a spool file: most attributes are a few
/// dozen bytes, and a file for each costs far more than the value. Up to this much in all.
const IN_MEMORY: usize = 4096;
const IN_MEMORY_TOTAL: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub key: String,
    pub length: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attribute {
    name: Vec<u8>,
    payload: Payload,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeMetadata {
    version: u32,
    birthtime: BirthTime,
    acl: Option<Acl>,
    flags: u32,
    attributes: Vec<Attribute>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    bytes: usize,
    parts: usize,
    sha256: String,
}

#[derive(Clone)]
struct EncryptedPayload {
    length: u64,
    nonce: [u8; 12],
    tag: [u8; 16],
    /// An entry of this backup refers to it. Payloads taken in from the previous snapshot are
    /// only written to the new payload archive when an entry carried over still refers to them.
    used: bool,
    /// The value itself when it is small; then there is no spool file, nonce or tag.
    memory: Option<Vec<u8>>,
}

/// Local spool is encrypted with an ephemeral process-local key. Its encrypted
/// bytes, key and nonce are never uploaded. PXAR receives authenticated plaintext
/// streams, then normal PBS encryption/deduplication applies as selected by CLI.
/// Small values do not go to the spool; they stay in memory, where they were read to.
pub struct NativePayloads {
    directory: tempfile::TempDir,
    directory_fd: File,
    key: [u8; 32],
    records: Mutex<BTreeMap<String, EncryptedPayload>>,
    memory_bytes: std::sync::atomic::AtomicUsize,
}

impl NativePayloads {
    pub fn new() -> Result<Arc<Self>, Error> {
        let mut key = [0; 32];
        openssl::rand::rand_bytes(&mut key)?;
        let directory = tempfile::tempdir()?;
        let directory_fd = File::open(directory.path())?;
        Ok(Arc::new(Self {
            directory,
            directory_fd,
            key,
            records: Mutex::new(BTreeMap::new()),
            memory_bytes: Default::default(),
        }))
    }
    pub fn is_empty(&self) -> bool {
        !self
            .records
            .lock()
            .unwrap()
            .values()
            .any(|record| record.used)
    }
    /// Everything stored so far came from the previous snapshot: nothing refers to it yet.
    pub fn forget_use(&self) {
        for record in self.records.lock().unwrap().values_mut() {
            record.used = false;
        }
    }
    /// Notes that an entry refers to this payload. False when the payload is not stored.
    fn keep(&self, value: &Payload) -> bool {
        match self.records.lock().unwrap().get_mut(&value.key) {
            Some(record) if record.length == value.length => {
                record.used = true;
                true
            }
            _ => false,
        }
    }
    fn put(&self, input: &mut dyn Read) -> Result<Payload, Error> {
        use std::sync::atomic::Ordering;
        let mut head = Vec::new();
        input.take(IN_MEMORY as u64 + 1).read_to_end(&mut head)?;
        if head.len() <= IN_MEMORY
            && self.memory_bytes.load(Ordering::Relaxed) + head.len() <= IN_MEMORY_TOTAL
        {
            let key = hex::encode(sha256(&head));
            let length = head.len() as u64;
            let mut records = self.records.lock().unwrap();
            if let Some(previous) = records.get_mut(&key) {
                if previous.length != length {
                    bail!("native payload digest collision");
                }
                previous.used = true;
            } else {
                self.memory_bytes.fetch_add(head.len(), Ordering::Relaxed);
                records.insert(
                    key.clone(),
                    EncryptedPayload {
                        length,
                        nonce: [0; 12],
                        tag: [0; 16],
                        used: true,
                        memory: Some(head),
                    },
                );
            }
            return Ok(Payload { key, length });
        }
        let mut nonce = [0; 12];
        openssl::rand::rand_bytes(&mut nonce)?;
        let mut cipher = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Encrypt,
            &self.key,
            Some(&nonce),
        )?;
        let mut file = tempfile::NamedTempFile::new_in(self.directory.path())?;
        let mut buffer = [0; 65536];
        let mut encrypted = [0; 65552];
        let mut hash = Sha256::new();
        hash.update(&head);
        let mut length = head.len() as u64;
        let size = cipher.update(&head, &mut encrypted)?;
        file.write_all(&encrypted[..size])?;
        loop {
            let size = input.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            hash.update(&buffer[..size]);
            length = length
                .checked_add(size as u64)
                .context("native payload length overflow")?;
            let size = cipher.update(&buffer[..size], &mut encrypted)?;
            file.write_all(&encrypted[..size])?;
        }
        let size = cipher.finalize(&mut encrypted)?;
        file.write_all(&encrypted[..size])?;
        let mut tag = [0; 16];
        cipher.get_tag(&mut tag)?;
        let key = hex::encode(hash.finish());
        let mut records = self.records.lock().unwrap();
        if let Some(previous) = records.get_mut(&key) {
            if previous.length != length {
                bail!("native payload digest collision");
            }
            previous.used = true;
        } else {
            file.persist_noclobber(self.directory.path().join(&key))?;
            records.insert(
                key.clone(),
                EncryptedPayload {
                    length,
                    nonce,
                    tag,
                    used: true,
                    memory: None,
                },
            );
        }
        Ok(Payload { key, length })
    }
    pub fn totals(&self) -> (usize, u64) {
        let records = self.records.lock().unwrap();
        let used = || records.values().filter(|record| record.used);
        (used().count(), used().map(|record| record.length).sum())
    }
    pub fn write_archive(&self, mut writer: impl Write) -> Result<(), Error> {
        let root = basic_metadata(true);
        let mut encoder = pxar::encoder::sync::Encoder::from_std(&mut writer, &root)?;
        let records: Vec<_> = self
            .records
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, value)| value.used)
            .map(|(key, value)| (key.clone(), value.length))
            .collect();
        for (key, length) in records {
            let mut source = self.reader(&Payload {
                key: key.clone(),
                length,
            })?;
            let mut output = encoder.create_file(&basic_metadata(false), &key, length)?;
            let written = std::io::copy(&mut source, &mut output)?;
            if written != length {
                bail!("native payload length changed");
            }
        }
        encoder.finish()?;
        encoder.close()?;
        writer.flush()?;
        Ok(())
    }
}

unsafe extern "C" {
    fn OPENSSL_cleanse(pointer: *mut std::ffi::c_void, length: usize);
}
impl Drop for NativePayloads {
    fn drop(&mut self) {
        unsafe {
            OPENSSL_cleanse(self.key.as_mut_ptr().cast(), self.key.len());
        }
        for record in self.records.lock().unwrap().values_mut() {
            if let Some(value) = record.memory.as_mut() {
                unsafe { OPENSSL_cleanse(value.as_mut_ptr().cast(), value.len()) }
            }
        }
    }
}

struct DecryptedPayload {
    file: File,
    cipher: Crypter,
    pending: Vec<u8>,
    offset: usize,
    finished: bool,
    hash: Option<Sha256>,
    expected: Payload,
    read: u64,
}
/// A stored value, from memory or from the spool.
enum StoredPayload {
    Memory(io::Cursor<Vec<u8>>),
    Spool(Box<DecryptedPayload>),
}
impl Read for StoredPayload {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        match self {
            StoredPayload::Memory(value) => value.read(target),
            StoredPayload::Spool(file) => file.read(target),
        }
    }
}
impl Read for DecryptedPayload {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        if target.is_empty() {
            return Ok(0);
        }
        loop {
            if self.offset < self.pending.len() {
                let count = target.len().min(self.pending.len() - self.offset);
                target[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
                self.offset += count;
                return Ok(count);
            }
            if self.finished {
                return Ok(0);
            }
            let mut input = [0; 65536];
            let count = self.file.read(&mut input)?;
            self.pending.resize(count + 16, 0);
            let size = if count == 0 {
                self.cipher.finalize(&mut self.pending)
            } else {
                self.cipher.update(&input[..count], &mut self.pending)
            }
            .map_err(io::Error::other)?;
            self.pending.truncate(size);
            self.offset = 0;
            self.read += size as u64;
            self.hash.as_mut().unwrap().update(&self.pending);
            if self.read > self.expected.length {
                return Err(io::Error::other("native payload size exceeded"));
            }
            if count == 0 {
                self.finished = true;
                if self.read != self.expected.length
                    || hex::encode(self.hash.take().unwrap().finish()) != self.expected.key
                {
                    return Err(io::Error::other("native payload integrity failure"));
                }
            }
        }
    }
}
impl NativePayloads {
    pub fn is_spool(&self, stat: &nix::sys::stat::FileStat) -> bool {
        let own = nix::sys::stat::fstat(self.directory_fd.as_raw_fd())
            .expect("owned native spool descriptor");
        own.st_dev == stat.st_dev && own.st_ino == stat.st_ino
    }
    fn reader(&self, value: &Payload) -> Result<StoredPayload, Error> {
        validate_payload(value)?;
        let record = self
            .records
            .lock()
            .unwrap()
            .get(&value.key)
            .cloned()
            .context("native payload is missing")?;
        if record.length != value.length {
            bail!("native payload length mismatch");
        }
        if let Some(memory) = record.memory {
            // its key is the digest it was stored under
            return Ok(StoredPayload::Memory(io::Cursor::new(memory)));
        }
        let fd = proxmox_sys::fd::openat(
            &self.directory_fd,
            Path::new(&value.key),
            nix::fcntl::OFlag::O_RDONLY
                | nix::fcntl::OFlag::O_NOFOLLOW
                | nix::fcntl::OFlag::O_CLOEXEC,
            nix::sys::stat::Mode::empty(),
        )?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() || file.metadata()?.len() != value.length {
            bail!("invalid native spool file");
        }
        let mut cipher = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Decrypt,
            &self.key,
            Some(&record.nonce),
        )?;
        cipher.set_tag(&record.tag)?;
        Ok(StoredPayload::Spool(Box::new(DecryptedPayload {
            file,
            cipher,
            pending: Vec::new(),
            offset: 0,
            finished: false,
            hash: Some(Sha256::new()),
            expected: value.clone(),
            read: 0,
        })))
    }
}

fn basic_metadata(directory: bool) -> pxar::Metadata {
    pxar::Metadata {
        stat: pxar::Stat {
            mode: if directory {
                pxar::mode::IFDIR | 0o700
            } else {
                pxar::mode::IFREG | 0o600
            },
            flags: 0,
            uid: 0,
            gid: 0,
            mtime: pxar::format::StatxTimestamp::new(0, 0),
        },
        ..Default::default()
    }
}

pub fn capture(
    fd: RawFd,
    stat: &nix::sys::stat::FileStat,
    flags: Flags,
    payloads: Option<&Arc<NativePayloads>>,
) -> Result<pxar::Metadata, Error> {
    if stat.st_flags & 0x40000000 != 0 {
        bail!("dataless placeholder requires an explicit backup policy");
    }
    let before = nix::sys::stat::fstat(fd)?;
    if before.st_ino != stat.st_ino
        || before.st_dev != stat.st_dev
        || before.st_mode != stat.st_mode
    {
        bail!("source identity changed while opening entry");
    }
    let mut native = NativeMetadata {
        version: 1,
        birthtime: BirthTime::capture(fd)?,
        acl: if flags.contains(Flags::WITH_ACL) {
            Some(Acl::capture(fd)?)
        } else {
            None
        },
        flags: stat.st_flags,
        attributes: Vec::new(),
    };
    if flags.contains(Flags::WITH_XATTRS) {
        let names = proxmox_sys::fs::xattr::flistxattr(fd)?;
        let mut names: Vec<_> = (&names).into_iter().map(|name| name.to_owned()).collect();
        names.sort_by(|a, b| a.to_bytes().cmp(b.to_bytes()));
        if names.len() > MAX_ATTRIBUTES {
            bail!("too many native attributes");
        }
        for name in names {
            let store = payloads.context("native metadata payload store is required")?;
            let payload = if name.to_bytes() == b"com.apple.ResourceFork" {
                let mut reader = ForkReader::open(fd)?.context("resource fork vanished")?;
                let payload = store.put(&mut reader)?;
                reader.verify_stable()?;
                payload
            } else {
                let value = proxmox_sys::fs::xattr::fgetxattr(fd, &name)?;
                store.put(&mut value.as_slice())?
            };
            native.attributes.push(Attribute {
                name: name.to_bytes().to_vec(),
                payload,
            });
        }
    }
    let after = nix::sys::stat::fstat(fd)?;
    if (before.st_ctime, before.st_ctime_nsec) != (after.st_ctime, after.st_ctime_nsec) {
        bail!("source metadata changed during capture");
    }
    let data = serde_json::to_vec(&native)?;
    if data.len() > MAX_HEADER {
        bail!("native metadata header exceeds limit");
    }
    let envelope = Envelope {
        version: 1,
        bytes: data.len(),
        parts: data.len().div_ceil(PART),
        sha256: hex::encode(sha256(&data)),
    };
    let mut result = pxar::Metadata {
        stat: pxar::Stat {
            mode: stat.st_mode as u64,
            flags: 0,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mtime: pxar::format::StatxTimestamp::new(stat.st_mtime, stat.st_mtime_nsec as u32),
        },
        ..Default::default()
    };
    result.xattrs.push(pxar::format::XAttr::new(
        PREFIX.as_bytes(),
        serde_json::to_vec(&envelope)?,
    ));
    for (index, part) in data.chunks(PART).enumerate() {
        result.xattrs.push(pxar::format::XAttr::new(
            format!("{PREFIX}.{index:08x}").as_bytes(),
            part.to_vec(),
        ));
    }
    Ok(result)
}

pub fn decode(metadata: &pxar::Metadata) -> Result<Option<NativeMetadata>, Error> {
    let controls: Vec<_> = metadata
        .xattrs
        .iter()
        .filter(|a| a.name().to_bytes() == PREFIX.as_bytes())
        .collect();
    if controls.is_empty() {
        return Ok(None);
    }
    if controls.len() != 1 {
        bail!("duplicate native metadata envelope");
    }
    let envelope: Envelope = serde_json::from_slice(controls[0].value())?;
    if envelope.version != 1
        || envelope.bytes == 0
        || envelope.bytes > MAX_HEADER
        || envelope.parts != envelope.bytes.div_ceil(PART)
    {
        bail!("invalid native metadata envelope");
    }
    let mut data = Vec::with_capacity(envelope.bytes);
    for index in 0..envelope.parts {
        let name = format!("{PREFIX}.{index:08x}");
        let parts: Vec<_> = metadata
            .xattrs
            .iter()
            .filter(|a| a.name().to_bytes() == name.as_bytes())
            .collect();
        if parts.len() != 1 || parts[0].value().len() != PART.min(envelope.bytes - index * PART) {
            bail!("invalid native metadata part");
        }
        data.extend_from_slice(parts[0].value());
    }
    if hex::encode(sha256(&data)) != envelope.sha256 {
        bail!("native metadata checksum mismatch");
    }
    let native: NativeMetadata = serde_json::from_slice(&data)?;
    if native.version != 1 || native.attributes.len() > MAX_ATTRIBUTES {
        bail!("unsupported native metadata version or attribute count");
    }
    let mut names = std::collections::HashSet::new();
    for attribute in &native.attributes {
        if attribute.name.is_empty()
            || attribute.name.len() > 127
            || !names.insert(attribute.name.clone())
            || attribute.name.contains(&0)
        {
            bail!("invalid native attribute name");
        }
        validate_payload(&attribute.payload)?;
    }
    Ok(Some(native))
}

/// For an entry carried over from the previous snapshot: notes that its attribute values are
/// still referred to. False when one of them is not in `store`; the entry then has to be read
/// from disk, or the new snapshot could not restore it.
pub fn keep_payloads(metadata: &pxar::Metadata, store: &NativePayloads) -> Result<bool, Error> {
    let Some(native) = decode(metadata)? else {
        return Ok(true);
    };
    Ok(native
        .attributes
        .iter()
        .all(|attribute| store.keep(&attribute.payload)))
}

fn validate_payload(value: &Payload) -> Result<(), Error> {
    if value.key.len() != 64
        || !value
            .key
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        || value.length > u32::MAX as u64 + 1
    {
        bail!("invalid native payload reference");
    }
    Ok(())
}

thread_local! { static RESTORE: RefCell<Option<Arc<NativePayloads>>> = const { RefCell::new(None) }; }
pub fn with_restore_payloads<T>(
    directory: Option<Arc<NativePayloads>>,
    action: impl FnOnce() -> T,
) -> T {
    struct Reset(Option<Arc<NativePayloads>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            RESTORE.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }
    let old = RESTORE.with(|slot| slot.replace(directory));
    let _reset = Reset(old);
    action()
}

pub(crate) fn restoring_native_metadata() -> bool {
    RESTORE.with(|slot| slot.borrow().is_some())
}

fn payload_file(value: &Payload) -> Result<StoredPayload, Error> {
    let root = RESTORE
        .with(|slot| slot.borrow().clone())
        .context("native payload archive was not loaded")?;
    root.reader(value)
}

impl NativeMetadata {
    pub fn restore_attributes(&self, fd: RawFd, flags: Flags) -> Result<(), Error> {
        if !flags.contains(Flags::WITH_XATTRS) {
            return Ok(());
        }
        for attribute in &self.attributes {
            let name = CString::new(attribute.name.clone())?;
            let mut source = payload_file(&attribute.payload)?;
            let mut hash = Sha256::new();
            if name.to_bytes() == b"com.apple.ResourceFork" {
                let mut writer = ForkWriter::create(fd, attribute.payload.length)?;
                let mut buffer = [0; 65536];
                loop {
                    let count = source.read(&mut buffer)?;
                    if count == 0 {
                        break;
                    }
                    hash.update(&buffer[..count]);
                    writer.write_all(&buffer[..count])?;
                }
                writer.finish()?;
            } else {
                if attribute.payload.length > 64 * 1024 * 1024 {
                    bail!("ordinary native xattr exceeds kernel size limit");
                }
                let mut value = Vec::new();
                source
                    .take(attribute.payload.length + 1)
                    .read_to_end(&mut value)?;
                if value.len() as u64 != attribute.payload.length {
                    bail!("native xattr payload size changed");
                }
                hash.update(&value);
                if let Err(error) = proxmox_sys::fs::xattr::fsetxattr(fd, &name, &value) {
                    if error == nix::errno::Errno::EPERM
                        && matches!(name.to_bytes(), b"com.apple.provenance" | b"com.apple.macl")
                    {
                        proxmox_log::warn!(
                            "System-managed attribute {name:?} retained in archive; destination value remains managed by macOS"
                        );
                    } else {
                        return Err(error.into());
                    }
                }
            }
            if hex::encode(hash.finish()) != attribute.payload.key {
                bail!("native payload checksum mismatch");
            }
        }
        Ok(())
    }
    pub fn restore_acl(&self, fd: RawFd, flags: Flags) -> Result<(), Error> {
        if flags.contains(Flags::WITH_ACL) {
            if let Some(acl) = &self.acl {
                acl.apply(fd)?;
            }
        }
        Ok(())
    }
    pub fn restore_birthtime(&self, fd: RawFd) -> Result<(), Error> {
        Ok(self.birthtime.apply(fd)?)
    }
    pub fn restore_flags(&self, fd: RawFd) -> Result<(), Error> {
        // Compression is a physical representation: file reads already yielded
        // decompressed data. Never apply UF_COMPRESSED to that plain data.
        let flags = self.flags & !0x20;
        super::darwin_metadata::apply_user_flags(fd, flags)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeBackupMap {
    pub version: u32,
    pub primary_archives: Vec<pbs_api_types::BackupArchiveName>,
    pub payload_archive: Option<pbs_api_types::BackupArchiveName>,
    pub payload_count: usize,
    pub payload_bytes: u64,
}

/// Extract only flat, content-addressed regular payload files. Never apply
/// auxiliary archive ownership, ACLs, xattrs, links, devices or directories.
pub fn unpack_payloads<R: pxar::decoder::SeqRead>(
    mut decoder: pxar::decoder::Decoder<R>,
    store: &Arc<NativePayloads>,
    count: usize,
    bytes: u64,
) -> Result<(), Error> {
    let (root, _) = super::tools::handle_root_with_optional_format_version_prelude(&mut decoder)?;
    if !root.is_dir() {
        bail!("native payload archive has no root directory");
    }
    let mut seen = std::collections::HashSet::new();
    let mut total = 0u64;
    while let Some(entry) = decoder.next() {
        let entry = entry?;
        let size = match entry.kind() {
            pxar::EntryKind::File { size, .. } => *size,
            _ => bail!("unexpected native payload entry type"),
        };
        let name = entry
            .path()
            .file_name()
            .context("missing native payload name")?;
        let key = name.to_str().context("invalid native payload name")?;
        validate_payload(&Payload {
            key: key.to_string(),
            length: size,
        })?;
        if entry
            .path()
            .components()
            .filter(|part| matches!(part, std::path::Component::Normal(_)))
            .count()
            != 1
            || !seen.insert(key.to_string())
            || seen.len() > count
        {
            bail!("invalid native payload path/count");
        }
        total = total
            .checked_add(size)
            .context("native payload size overflow")?;
        if total > bytes {
            bail!("native payload byte budget exceeded");
        }
        let mut source = decoder
            .contents()?
            .context("native payload contents missing")?;
        let saved = store.put(&mut source)?;
        if saved.length != size || saved.key != key {
            bail!("native payload integrity failure");
        }
    }
    if seen.len() != count || total != bytes {
        bail!("native payload archive is incomplete");
    }
    Ok(())
}
