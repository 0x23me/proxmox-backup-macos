use std::collections::HashSet;
use std::ffi::CString;
use std::ops::Range;
use std::os::unix::io::OwnedFd;
use std::path::PathBuf;

use nix::sys::stat::FileStat;

use pxar::Metadata;
use pxar::encoder::PayloadOffset;

use super::create::*;

const DEFAULT_CACHE_SIZE: usize = 512;

pub(crate) struct CacheEntryData {
    pub(crate) fd: OwnedFd,
    pub(crate) c_file_name: CString,
    pub(crate) stat: FileStat,
    pub(crate) metadata: Metadata,
    pub(crate) payload_offset: PayloadOffset,
}

pub(crate) enum CacheEntry {
    RegEntry(CacheEntryData),
    DirEntry(CacheEntryData),
    DirEnd,
    Carried(CarriedEntry),
}

/// An entry taken over from the previous archive as it is there, without a look at the disk.
/// A directory is closed by a `DirEnd`, like one read from disk.
pub(crate) struct CarriedEntry {
    pub(crate) c_file_name: CString,
    pub(crate) metadata: Metadata,
    pub(crate) kind: CarriedKind,
}

pub(crate) enum CarriedKind {
    Directory,
    /// `payload_offset` is relative to the start of the cached range, as for a `RegEntry`.
    /// `link_target` is where to note the file's place in the new archive, for a hard link
    /// to it that is carried over later.
    File {
        size: u64,
        payload_offset: PayloadOffset,
        link_target: Option<usize>,
    },
    /// A hard link to a file carried over before it; `path` is that file's.
    Hardlink {
        link_target: usize,
        path: std::ffi::OsString,
    },
    Symlink(std::ffi::OsString),
    Device(pxar::format::Device),
    Fifo,
    Socket,
}

/// A carried entry holds no file descriptor, but its metadata: this many are kept at most.
const CARRIED_ENTRIES_MAX: usize = 8192;

pub(crate) struct PxarLookaheadCache {
    // Current state of the cache
    enabled: bool,
    // Cached entries
    entries: Vec<CacheEntry>,
    // Entries encountered having more than one link given by stat
    hardlinks: HashSet<HardLinkInfo>,
    // Payload range covered by the currently cached entries
    range: Range<u64>,
    // Possible held back last chunk from last flush, used for possible chunk continuation
    last_chunk: Option<ReusableDynamicEntry>,
    // Path when started caching
    start_path: PathBuf,
    // Number of entries with file descriptors
    fd_entries: usize,
    // Max number of entries with file descriptors
    cache_size: usize,
    // Number of entries carried over from the previous archive, and how many of them are files
    carried_entries: usize,
    carried_files: usize,
}

impl PxarLookaheadCache {
    pub(crate) fn new(size: Option<usize>) -> Self {
        Self {
            enabled: false,
            entries: Vec::new(),
            hardlinks: HashSet::new(),
            range: 0..0,
            last_chunk: None,
            start_path: PathBuf::new(),
            fd_entries: 0,
            cache_size: size.unwrap_or(DEFAULT_CACHE_SIZE),
            carried_entries: 0,
            carried_files: 0,
        }
    }

    pub(crate) fn is_full(&self) -> bool {
        self.fd_entries >= self.cache_size || self.carried_entries >= CARRIED_ENTRIES_MAX
    }

    /// Carried files cannot be encoded again from disk: a range with one in it is reused.
    pub(crate) fn has_carried_files(&self) -> bool {
        self.carried_files > 0
    }

    /// `parent` is the path of the directory the entry is in.
    pub(crate) fn insert_carried(&mut self, entry: CarriedEntry, parent: &std::path::Path) {
        if !self.enabled {
            self.start_path = parent.to_path_buf();
        }
        self.enabled = true;
        self.carried_entries += 1;
        if let CarriedKind::File { .. } = entry.kind {
            self.carried_files += 1;
        }
        self.entries.push(CacheEntry::Carried(entry));
    }

    pub(crate) fn caching_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn insert(
        &mut self,
        fd: OwnedFd,
        c_file_name: CString,
        stat: FileStat,
        metadata: Metadata,
        payload_offset: PayloadOffset,
        path: PathBuf,
    ) {
        if !self.enabled {
            self.start_path = path;
            if !metadata.is_dir() {
                self.start_path.pop();
            }
        }
        self.enabled = true;
        self.fd_entries += 1;
        if metadata.is_dir() {
            self.entries.push(CacheEntry::DirEntry(CacheEntryData {
                fd,
                c_file_name,
                stat,
                metadata,
                payload_offset,
            }))
        } else {
            self.entries.push(CacheEntry::RegEntry(CacheEntryData {
                fd,
                c_file_name,
                stat,
                metadata,
                payload_offset,
            }))
        }
    }

    pub(crate) fn insert_dir_end(&mut self) {
        self.entries.push(CacheEntry::DirEnd);
    }

    pub(crate) fn take_and_reset(&mut self) -> (Vec<CacheEntry>, PathBuf) {
        self.fd_entries = 0;
        self.carried_entries = 0;
        self.carried_files = 0;
        self.enabled = false;
        // keep end for possible continuation if cache has been cleared because
        // it was full, but further caching would be fine
        self.range = self.range.end..self.range.end;
        (
            std::mem::take(&mut self.entries),
            std::mem::take(&mut self.start_path),
        )
    }

    pub(crate) fn contains_hardlink(&self, info: &HardLinkInfo) -> bool {
        self.hardlinks.contains(info)
    }

    pub(crate) fn insert_hardlink(&mut self, info: HardLinkInfo) -> bool {
        self.hardlinks.insert(info)
    }

    pub(crate) fn range(&self) -> &Range<u64> {
        &self.range
    }

    pub(crate) fn update_range(&mut self, range: Range<u64>) {
        self.range = range;
    }

    pub(crate) fn try_extend_range(&mut self, range: Range<u64>) -> bool {
        if self.range.end == 0 {
            // initialize first range to start and end with start of new range
            self.range.start = range.start;
            self.range.end = range.start;
        }

        // range continued, update end
        if self.range.end == range.start {
            self.range.end = range.end;
            return true;
        }

        false
    }

    pub(crate) fn take_last_chunk(&mut self) -> Option<ReusableDynamicEntry> {
        self.last_chunk.take()
    }

    pub(crate) fn update_last_chunk(&mut self, chunk: Option<ReusableDynamicEntry>) {
        self.last_chunk = chunk;
    }
}
