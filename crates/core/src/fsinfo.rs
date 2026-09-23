//! Where the database could live: RAM-backed mounts, free space, and whether
//! ferrite can actually write there.
//!
//! `storage.path` is a decision about what the query log costs — writes on a
//! flash card, or RAM that a reboot clears. Someone making that decision from
//! the panel should not have to know their box's mount table by heart, so this
//! finds the plausible destinations and reports what is actually free.
//!
//! Detection is Linux-only, because that is where a RAM-backed mount is
//! standard (`/dev/shm`, `/run`, and `/tmp` under systemd). macOS has no tmpfs
//! — a RAM disk there is a deliberate `hdiutil` device — so the list comes back
//! empty and the panel just offers the manual field. Free space and the
//! writability probe work everywhere.

use std::path::{Path, PathBuf};

/// A place the database could be put.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// Directory the database would live in.
    pub dir: PathBuf,
    /// Filesystem type as the OS reports it (`tmpfs`, `ext4`, `apfs`, …).
    pub fstype: String,
    /// Does this filesystem live in RAM? Fast and free of flash wear, and
    /// empty again after a reboot.
    pub ram_backed: bool,
}

/// Free space on the filesystem holding a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Space {
    pub total_bytes: u64,
    pub available_bytes: u64,
}

/// RAM-backed mounts worth offering, most free space first.
///
/// Only mounts ferrite can actually write to are returned: a listed path the
/// panel then fails to use would be worse than no suggestion at all.
pub fn ram_backed_locations() -> Vec<Location> {
    let mut found: Vec<Location> = read_mounts()
        .into_iter()
        .filter(|m| m.ram_backed && is_usable_mount(&m.dir) && probe_writable(&m.dir))
        .collect();

    found.sort_by_key(|m| std::cmp::Reverse(space_for(&m.dir).map_or(0, |s| s.available_bytes)));
    found.dedup_by(|a, b| a.dir == b.dir);
    found
}

/// Free space on the filesystem holding `path`, or its nearest existing
/// ancestor — asking about a database file that isn't there yet still has an
/// answer, and it is the one the caller wants.
pub fn space_for(path: &Path) -> Option<Space> {
    let existing = nearest_existing(path)?;
    statvfs_space(&existing)
}

/// Can ferrite create files in `dir`?
///
/// Answered by writing one and removing it, not by reading permission bits:
/// bits say nothing about a read-only mount, a full filesystem, SELinux, or
/// the many ways root's apparent access differs from its real access.
pub fn probe_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".ferrite-write-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// The deepest ancestor of `path` (including itself) that exists. Used to ask
/// the filesystem about a location before anything has been created there.
pub fn nearest_existing(path: &Path) -> Option<PathBuf> {
    let mut cursor = Some(path);
    while let Some(p) = cursor {
        if p.exists() {
            return Some(p.to_path_buf());
        }
        cursor = p.parent();
    }
    None
}

// ── Mount table ──────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn read_mounts() -> Vec<Location> {
    let Ok(raw) = std::fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    raw.lines().filter_map(parse_mount_line).collect()
}

#[cfg(not(target_os = "linux"))]
fn read_mounts() -> Vec<Location> {
    // No tmpfs to find. A RAM disk on macOS is an explicit `hdiutil` device
    // with an arbitrary mount point, which is not something to guess at — the
    // operator types the path.
    Vec::new()
}

/// One `/proc/mounts` line: `device mountpoint fstype options dump pass`.
/// Returns `None` for anything unparseable or not mounted read-write.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_mount_line(line: &str) -> Option<Location> {
    let mut fields = line.split_whitespace();
    let _device = fields.next()?;
    let mountpoint = fields.next()?;
    let fstype = fields.next()?;
    let options = fields.next().unwrap_or("");

    // A read-only mount can't hold a database whatever else it is.
    if !options.split(',').any(|o| o == "rw") {
        return None;
    }

    Some(Location {
        dir: PathBuf::from(unescape_mount_path(mountpoint)),
        ram_backed: matches!(fstype, "tmpfs" | "ramfs"),
        fstype: fstype.to_string(),
    })
}

/// `/proc/mounts` escapes space, tab, newline and backslash as octal.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn unescape_mount_path(raw: &str) -> String {
    if !raw.contains('\\') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let octal: String = chars.clone().take(3).collect();
        match u8::from_str_radix(&octal, 8) {
            Ok(byte) if octal.len() == 3 => {
                out.push(byte as char);
                for _ in 0..3 {
                    chars.next();
                }
            }
            _ => out.push('\\'),
        }
    }
    out
}

/// Is this mount somewhere a person would put a database?
///
/// The kernel mounts a lot of tmpfs that exists for the kernel: cgroup trees,
/// `/sys` and `/proc` scaffolding, `/run/lock` (tiny, and for lock files),
/// per-user `/run/user/N` (which goes away with the session). Offering those
/// would bury the two that matter.
fn is_usable_mount(dir: &Path) -> bool {
    let Some(path) = dir.to_str() else {
        return false;
    };
    if path == "/dev/shm" {
        return true;
    }
    const REJECTED_PREFIXES: [&str; 5] = ["/sys", "/proc", "/dev", "/run/lock", "/run/user"];
    !REJECTED_PREFIXES
        .iter()
        .any(|p| path == *p || path.starts_with(&format!("{p}/")))
}

// ── Free space ───────────────────────────────────────────────────────────────

fn statvfs_space(path: &Path) -> Option<Space> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `stat` is a valid, correctly-sized destination, and `c_path` is a
    // NUL-terminated string that outlives the call. `statvfs` only reads it.
    let stat = unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return None;
        }
        stat
    };

    // `f_frsize` is the fragment size blocks are counted in; `f_bsize` is the
    // preferred I/O size and is not the right multiplier, though they usually
    // match. `f_bavail` excludes the reserve only root may use, which is what
    // an unprivileged write actually gets.
    let unit = if stat.f_frsize > 0 {
        stat.f_frsize as u64
    } else {
        stat.f_bsize as u64
    };
    Some(Space {
        total_bytes: stat.f_blocks as u64 * unit,
        available_bytes: stat.f_bavail as u64 * unit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_lines_parse_into_locations() {
        let tmpfs = parse_mount_line("tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0").unwrap();
        assert_eq!(tmpfs.dir, PathBuf::from("/dev/shm"));
        assert_eq!(tmpfs.fstype, "tmpfs");
        assert!(tmpfs.ram_backed);

        let disk = parse_mount_line("/dev/sda1 / ext4 rw,relatime 0 0").unwrap();
        assert!(!disk.ram_backed);
        assert_eq!(disk.fstype, "ext4");
    }

    /// A read-only mount cannot hold a database, however RAM-backed it is.
    #[test]
    fn read_only_mounts_are_skipped() {
        assert!(parse_mount_line("tmpfs /mnt/ro tmpfs ro,nosuid 0 0").is_none());
        // `rw` must be its own option, not a substring of another one.
        assert!(parse_mount_line("tmpfs /mnt/x tmpfs rwmode,nosuid 0 0").is_none());
    }

    #[test]
    fn octal_escapes_in_mount_paths_are_decoded() {
        assert_eq!(unescape_mount_path("/mnt/my\\040disk"), "/mnt/my disk");
        assert_eq!(unescape_mount_path("/dev/shm"), "/dev/shm");
        // A lone backslash is kept rather than swallowed.
        assert_eq!(unescape_mount_path("/mnt/odd\\x"), "/mnt/odd\\x");
    }

    /// The kernel's own tmpfs mounts are not offered as places for a database.
    #[test]
    fn kernel_scaffolding_mounts_are_not_offered() {
        for rejected in [
            "/sys/fs/cgroup",
            "/proc/sys/fs/binfmt_misc",
            "/run/lock",
            "/run/user/1000",
            "/dev",
        ] {
            assert!(
                !is_usable_mount(Path::new(rejected)),
                "{rejected} should not be offered"
            );
        }
        for accepted in ["/dev/shm", "/run", "/tmp", "/mnt/ram"] {
            assert!(
                is_usable_mount(Path::new(accepted)),
                "{accepted} should be offered"
            );
        }
    }

    /// A real `/proc/mounts`, taken verbatim from a Linux container. The
    /// kernel mounts tmpfs in places that are emphatically not for a database
    /// — `/dev` itself, three files under `/proc`, a read-only one under
    /// `/sys` — and only `/dev/shm` is a genuine answer. Synthetic lines would
    /// not have caught `/proc/interrupts`.
    #[test]
    fn a_real_linux_mount_table_yields_only_the_usable_ram_mounts() {
        const MOUNTS: &str = "\
overlay / overlay rw,relatime,lowerdir=/var/lib/docker/x,upperdir=/var/lib/docker/y 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666 0 0
sysfs /sys sysfs ro,nosuid,nodev,noexec,relatime 0 0
cgroup /sys/fs/cgroup cgroup2 ro,nosuid,nodev,noexec,relatime 0 0
mqueue /dev/mqueue mqueue rw,nosuid,nodev,noexec,relatime 0 0
shm /dev/shm tmpfs rw,nosuid,nodev,noexec,relatime,inode64 0 0
/dev/vda /etc/hostname ext4 rw,relatime 0 0
proc /proc/sys proc ro,nosuid,nodev,noexec,relatime 0 0
tmpfs /proc/interrupts tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/keys tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /proc/timer_list tmpfs rw,nosuid,size=65536k,mode=755,inode64 0 0
tmpfs /sys/firmware tmpfs ro,relatime,size=16k,nr_inodes=1,inode64 0 0
tmpfs /run tmpfs rw,nosuid,nodev,size=1608036k,mode=755,inode64 0 0
tmpfs /run/lock tmpfs rw,nosuid,nodev,noexec,relatime,size=5120k 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime,size=804016k,uid=1000 0 0
";

        let offered: Vec<String> = MOUNTS
            .lines()
            .filter_map(parse_mount_line)
            .filter(|m| m.ram_backed && is_usable_mount(&m.dir))
            .map(|m| m.dir.display().to_string())
            .collect();

        assert_eq!(offered, vec!["/dev/shm".to_string(), "/run".to_string()]);
    }

    #[test]
    fn space_is_reported_for_a_path_that_does_not_exist_yet() {
        let dir = std::env::temp_dir();
        let missing = dir.join("ferrite-nonexistent-dir").join("ferrite.db");
        // Answered from the nearest existing ancestor, so a database that has
        // not been created yet still has a free-space figure.
        let space = space_for(&missing).expect("temp dir should report space");
        assert!(space.total_bytes > 0);
        assert!(space.available_bytes <= space.total_bytes);
    }

    #[test]
    fn writability_is_probed_not_guessed() {
        assert!(probe_writable(&std::env::temp_dir()));
        assert!(!probe_writable(Path::new("/ferrite-nonexistent-root-dir")));
    }
}
