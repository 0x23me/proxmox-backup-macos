//! The list of changed directories a backup can be given: which directories it says to read.
use std::path::Path;

use pbs_client::pxar::changed_dirs::{Change, ChangedDirs};

fn list(records: &[&str]) -> ChangedDirs {
    let mut data = Vec::new();
    for record in records {
        data.extend_from_slice(record.as_bytes());
        data.push(0);
    }
    ChangedDirs::parse(&data, Path::new("/nonexistent/source")).unwrap()
}

#[test]
fn named_directories_are_read_and_the_way_to_them_is_known() {
    let list = list(&["d/nonexistent/source/a/b", "d/nonexistent/other/x"]);
    assert_eq!(list.state(Path::new("a/b")), Change::Read);
    assert_eq!(list.state(Path::new("a")), Change::Below);
    assert_eq!(list.state(Path::new("")), Change::Below);
    assert_eq!(list.state(Path::new("a/b/c")), Change::Untouched);
    assert_eq!(list.state(Path::new("a/c")), Change::Untouched);
    assert_eq!(list.state(Path::new("x")), Change::Untouched);
    assert_eq!(list.named_in(Path::new("a")), ["b"]);
    assert_eq!(list.named_in(Path::new("")), ["a"]);
    assert!(list.named_in(Path::new("a/b")).is_empty());
    assert!(list.named_in(Path::new("x")).is_empty());
}

#[test]
fn everything_below_a_recursive_record_is_read() {
    let list = list(&["r/nonexistent/source/a", "d/nonexistent/source/a/b/c"]);
    assert_eq!(list.state(Path::new("a")), Change::Read);
    assert_eq!(list.state(Path::new("a/b")), Change::Read);
    assert_eq!(list.state(Path::new("a/x/y")), Change::Read);
    assert_eq!(list.state(Path::new("b")), Change::Untouched);
}

#[test]
fn a_recursive_record_above_the_source_reads_everything() {
    let list = list(&["r/nonexistent", "d/nonexistent"]);
    assert_eq!(list.state(Path::new("")), Change::Read);
    assert_eq!(list.state(Path::new("a/b")), Change::Read);
    let list = ChangedDirs::parse(b"d/nonexistent\0", Path::new("/nonexistent/source")).unwrap();
    assert_eq!(list.state(Path::new("a")), Change::Untouched);
}

#[test]
fn records_that_are_no_paths_are_refused() {
    assert!(ChangedDirs::check(b"d/a\0r/b\0").is_ok());
    assert!(ChangedDirs::check(b"d/a\0\0").is_ok());
    assert!(ChangedDirs::check(b"x/a\0").is_err());
    assert!(ChangedDirs::check(b"da/b\0").is_err());
    assert!(ChangedDirs::check(b"d/a/../b\0").is_err());
}
