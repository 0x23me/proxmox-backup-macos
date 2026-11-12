//! Which directories changed since the previous backup, as told by the caller.
//!
//! The caller, which has a change log to ask (FSEvents on macOS), names the directories that
//! changed since a previous snapshot. A backup in metadata change detection mode then reads
//! only those from disk and takes every other directory over from the previous snapshot's
//! metadata archive, without looking at it on disk.
//!
//! The list is a file of records, each ended by a NUL byte: one byte for the kind, then an
//! absolute path as this client sees it.
//!
//! * `d`: entries directly in this directory changed. The directory is read from disk. A
//!   directory in it is carried over unless it is named itself, has a named directory below
//!   it, or its own metadata differs from the previous snapshot.
//! * `r`: everything at and below this path is read from disk.
//!
//! A path outside the directory being archived is ignored, so one list serves several
//! archives. An `r` record for the archived directory or one above it reads everything.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{Error, bail};

#[derive(Default)]
struct Node {
    named: bool,
    recursive: bool,
    children: HashMap<OsString, Node>,
}

/// What the list says about one directory.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    /// It is named, or lies at or below an `r` record: read it from disk.
    Read,
    /// It is not named, but a directory below it is.
    Below,
    /// Neither it nor anything below it is named.
    Untouched,
}

/// The records of a change list that concern one archived directory.
#[derive(Default)]
pub struct ChangedDirs {
    root: Node,
}

/// The records of a change list: `(recursive, path)`.
fn records(data: &[u8]) -> Result<Vec<(bool, &Path)>, Error> {
    let mut result = Vec::new();
    for record in data.split(|byte| *byte == 0) {
        let Some((kind, path)) = record.split_first() else {
            continue; // the end of the file, or an empty record
        };
        let recursive = match kind {
            b'd' => false,
            b'r' => true,
            other => bail!("change list: unknown record kind {:?}", *other as char),
        };
        let path = Path::new(OsStr::from_bytes(path));
        if !path.is_absolute() {
            bail!("change list: {path:?} is not an absolute path");
        }
        if path.components().any(|part| part == Component::ParentDir) {
            bail!("change list: {path:?} contains '..'");
        }
        result.push((recursive, path));
    }
    Ok(result)
}

impl ChangedDirs {
    /// Fails when `data` is not a change list.
    pub fn check(data: &[u8]) -> Result<(), Error> {
        records(data).map(|_| ())
    }

    /// The records of `data` at and below `source`, the directory being archived. Records are
    /// matched against `source` as given and with its symbolic links resolved.
    pub fn parse(data: &[u8], source: &Path) -> Result<Self, Error> {
        let mut sources: Vec<PathBuf> = Vec::new();
        if let Ok(path) = std::path::absolute(source) {
            sources.push(path);
        }
        if let Ok(path) = std::fs::canonicalize(source) {
            if !sources.contains(&path) {
                sources.push(path);
            }
        }
        let mut list = Self::default();
        for (recursive, path) in records(data)? {
            if let Some(below) = sources
                .iter()
                .find_map(|source| path.strip_prefix(source).ok())
            {
                let mut node = &mut list.root;
                for part in below.components() {
                    if let Component::Normal(name) = part {
                        node = node.children.entry(name.to_owned()).or_default();
                    }
                }
                node.named = true;
                node.recursive |= recursive;
            } else if recursive && sources.iter().any(|source| source.starts_with(path)) {
                list.root.named = true;
                list.root.recursive = true;
            }
        }
        Ok(list)
    }

    /// The names directly in the directory at `path` that the list names or names something
    /// below. A directory that is taken from the previous snapshot has to have them all, or
    /// the list knows of something in it that the previous snapshot does not.
    pub fn named_in(&self, path: &Path) -> Vec<&OsStr> {
        let mut node = &self.root;
        for part in path.components() {
            let Component::Normal(name) = part else {
                continue;
            };
            match node.children.get(name) {
                Some(child) => node = child,
                None => return Vec::new(),
            }
        }
        node.children.keys().map(|name| name.as_os_str()).collect()
    }

    /// What the list says about the directory at `path`, relative to the archived directory.
    pub fn state(&self, path: &Path) -> Change {
        let mut node = &self.root;
        for part in path.components() {
            if node.recursive {
                return Change::Read;
            }
            let Component::Normal(name) = part else {
                continue;
            };
            match node.children.get(name) {
                Some(child) => node = child,
                None => return Change::Untouched,
            }
        }
        if node.named {
            Change::Read
        } else {
            Change::Below
        }
    }
}
