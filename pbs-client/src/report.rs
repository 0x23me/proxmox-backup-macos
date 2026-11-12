//! Machine-readable progress and result records.
//!
//! With `--progress-json` the backup and restore commands print one JSON object per line on
//! standard output; the human-readable log stays on standard error. Two kinds of record:
//!
//! ```text
//! {"type":"progress","entries":1291,"bytes_processed":46254325760,"bytes_uploaded":44651675648,
//!  "bytes_sent":34201638912,"path":"Projects/report.pdf","elapsed":12.0}
//! {"type":"result","ok":true,"snapshot":"host/mac/2026-11-12T08:00:00Z","namespace":"laptops",
//!  "entries":1474,"bytes_processed":46254325760,"bytes_reused":46254325728,"bytes_uploaded":32,
//!  "skipped_placeholders":["iCloud/draft.pages"],"skipped_placeholder_count":1,
//!  "time_machine_excluded":3,"warnings":[],"duration":0.62}
//! ```
//!
//! A progress record is printed every second while the operation runs. Exactly one result
//! record is printed last; on failure it has `"ok":false` and an `error` text, and the process
//! exits non-zero. `bytes_processed` counts archive data handled so far, `bytes_reused` the part
//! of it the server already had, `bytes_uploaded` the part the server did not have, `bytes_sent` what that
//! came to on the network after compression and encryption (the number to derive an upload
//! speed from). `path` is relative to the archive root. `skipped_placeholders` lists at most 1000 paths; the count is always complete.
//! A restore reports `entries`, `bytes_processed` and `path` only.
//!
//! A backup given `--changed-dirs` adds three fields to its result record: `change_list` is
//! `"used"` or `"ignored: <reason>"`, `carried_dirs` counts the directories taken over from
//! the previous snapshot without reading them, `walked_dirs` those read from disk.
//!
//! The counters are kept whether or not records are requested, so the hooks cost a few atomic
//! additions; the current path is only stored while records are on.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde_json::json;

static ENABLED: AtomicBool = AtomicBool::new(false);
static RUNNING: AtomicBool = AtomicBool::new(false);
static ENTRIES: AtomicU64 = AtomicU64::new(0);
static BYTES_PROCESSED: AtomicU64 = AtomicU64::new(0);
static BYTES_REUSED: AtomicU64 = AtomicU64::new(0);
static BYTES_UPLOADED: AtomicU64 = AtomicU64::new(0);
static BYTES_SENT: AtomicU64 = AtomicU64::new(0);
static PLACEHOLDERS: AtomicU64 = AtomicU64::new(0);
static TIME_MACHINE_EXCLUDED: AtomicU64 = AtomicU64::new(0);
static START: OnceLock<Instant> = OnceLock::new();
static PATH: Mutex<String> = Mutex::new(String::new());
static PLACEHOLDER_PATHS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static CARRIED_DIRS: AtomicU64 = AtomicU64::new(0);
static WALKED_DIRS: AtomicU64 = AtomicU64::new(0);
/// None without a change list; else why it was not used, per archive, empty when it was.
static CHANGE_LIST: Mutex<Option<Vec<String>>> = Mutex::new(None);

const LISTED: usize = 1000;

/// An entry is being archived or extracted.
pub fn entry(path: &Path) {
    ENTRIES.fetch_add(1, Ordering::Relaxed);
    if ENABLED.load(Ordering::Relaxed) {
        let mut current = PATH.lock().unwrap();
        current.clear();
        current.push_str(&path.to_string_lossy());
    }
}

/// Archive data went through, `reused` when the server has it already.
pub fn processed(bytes: usize, reused: bool) {
    BYTES_PROCESSED.fetch_add(bytes as u64, Ordering::Relaxed);
    if reused {
        BYTES_REUSED.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

pub fn uploaded(bytes: usize) {
    BYTES_UPLOADED.fetch_add(bytes as u64, Ordering::Relaxed);
}

/// The server acknowledged a chunk of this size on the wire (compressed and encrypted).
pub fn sent(bytes: usize) {
    BYTES_SENT.fetch_add(bytes as u64, Ordering::Relaxed);
}

/// A file whose contents are not on disk was left out.
pub fn skipped_placeholder(path: &Path) {
    PLACEHOLDERS.fetch_add(1, Ordering::Relaxed);
    let mut paths = PLACEHOLDER_PATHS.lock().unwrap();
    if paths.len() < LISTED {
        paths.push(path.to_string_lossy().into_owned());
    }
}

/// An entry carrying the Time Machine exclusion attribute was left out, with all below it.
pub fn excluded_by_time_machine() {
    TIME_MACHINE_EXCLUDED.fetch_add(1, Ordering::Relaxed);
}

pub fn warning(text: String) {
    let mut warnings = WARNINGS.lock().unwrap();
    if warnings.len() < LISTED {
        warnings.push(text);
    }
}

/// A directory was taken over from the previous snapshot without reading it from disk.
pub fn carried_dir() {
    CARRIED_DIRS.fetch_add(1, Ordering::Relaxed);
}

/// A directory was read from disk.
pub fn walked_dir() {
    WALKED_DIRS.fetch_add(1, Ordering::Relaxed);
}

/// The backup was given a list of changed directories.
pub fn change_list_given() {
    CHANGE_LIST.lock().unwrap().get_or_insert_with(Vec::new);
}

/// The list of changed directories is not used, for everything or for one archive.
pub fn change_list_ignored(reason: String) {
    CHANGE_LIST
        .lock()
        .unwrap()
        .get_or_insert_with(Vec::new)
        .push(reason);
}

/// `(what became of the change list, directories carried over, directories read)`, when the
/// backup was given a change list.
pub fn change_list() -> Option<(String, u64, u64)> {
    let reasons = CHANGE_LIST.lock().unwrap();
    let reasons = reasons.as_ref()?;
    let state = if reasons.is_empty() {
        "used".to_string()
    } else {
        format!("ignored: {}", reasons.join("; "))
    };
    Some((
        state,
        CARRIED_DIRS.load(Ordering::Relaxed),
        WALKED_DIRS.load(Ordering::Relaxed),
    ))
}

fn elapsed() -> f64 {
    START.get().map(|start| start.elapsed().as_secs_f64()).unwrap_or(0.0)
}

fn progress_record() -> serde_json::Value {
    json!({
        "type": "progress",
        "entries": ENTRIES.load(Ordering::Relaxed),
        "bytes_processed": BYTES_PROCESSED.load(Ordering::Relaxed),
        "bytes_uploaded": BYTES_UPLOADED.load(Ordering::Relaxed),
        "bytes_sent": BYTES_SENT.load(Ordering::Relaxed),
        "path": PATH.lock().unwrap().clone(),
        "elapsed": (elapsed() * 10.0).round() / 10.0,
    })
}

/// Returned by [`start`]. Dropping it without a call to [`finish`] means the operation failed
/// on the way, and prints the failure record.
pub struct Report;

impl Drop for Report {
    fn drop(&mut self) {
        finish(None, Some("failed; the reason is on standard error".to_string()));
    }
}

/// Starts printing a progress record every second until [`finish`] is called.
pub fn start() -> Report {
    START.get_or_init(Instant::now);
    ENABLED.store(true, Ordering::Relaxed);
    RUNNING.store(true, Ordering::Relaxed);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));
            if !RUNNING.load(Ordering::Relaxed) {
                break;
            }
            println!("{}", progress_record());
        }
    });
    Report
}

/// Prints the result record, once; does nothing when records were not started. `snapshot` is
/// `(name, namespace)` of a backup; `error` the failure.
pub fn finish(snapshot: Option<(String, String)>, error: Option<String>) {
    if !RUNNING.swap(false, Ordering::Relaxed) {
        return;
    }
    let mut record = json!({
        "type": "result",
        "ok": error.is_none(),
        "entries": ENTRIES.load(Ordering::Relaxed),
        "bytes_processed": BYTES_PROCESSED.load(Ordering::Relaxed),
        "bytes_reused": BYTES_REUSED.load(Ordering::Relaxed),
        "bytes_uploaded": BYTES_UPLOADED.load(Ordering::Relaxed),
        "bytes_sent": BYTES_SENT.load(Ordering::Relaxed),
        "skipped_placeholders": *PLACEHOLDER_PATHS.lock().unwrap(),
        "skipped_placeholder_count": PLACEHOLDERS.load(Ordering::Relaxed),
        "time_machine_excluded": TIME_MACHINE_EXCLUDED.load(Ordering::Relaxed),
        "warnings": *WARNINGS.lock().unwrap(),
        "duration": (elapsed() * 100.0).round() / 100.0,
    });
    if let Some((state, carried, walked)) = change_list() {
        record["change_list"] = state.into();
        record["carried_dirs"] = carried.into();
        record["walked_dirs"] = walked.into();
    }
    if let Some((name, namespace)) = snapshot {
        record["snapshot"] = name.into();
        record["namespace"] = namespace.into();
    }
    if let Some(error) = error {
        record["error"] = error.into();
    }
    println!("{record}");
}
