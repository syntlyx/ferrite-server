//! Restarting in place, without dropping a query.
//!
//! When ferrite has to become a new process — a self-update, a changed
//! listen address or database, a secondary taking a primary's settings — it
//! doesn't exit and wait for the service manager. It `exec`s its own binary
//! again, keeping the DNS and panel sockets open across the exec: their file
//! descriptors are passed on (named in [`ENV`]) and the new image serves on
//! them as soon as it is up. Queries that arrive in between wait in the
//! socket's buffer and are answered then, the process id doesn't change (so
//! systemd, OpenRC and Docker see nothing happen), and capabilities granted
//! to the process stay with it.
//!
//! Only sockets bound once for the life of the process are passed on —
//! [`hold`] is for those. The rest (Tunnels, encrypted DNS, DHCP) are opened
//! again by their own supervisors, which already retry a busy port.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// `role=fd,role=fd`: the sockets a previous image handed over.
pub const ENV: &str = "FERRITE_LISTEN_FDS";

/// The binary this process was started from, read before anything could
/// replace it — after a self-update that path holds the new version.
static EXE: OnceLock<Option<PathBuf>> = OnceLock::new();
/// Sockets handed over and not yet taken, by role.
static INHERITED: Mutex<Vec<(String, i32)>> = Mutex::new(Vec::new());
/// Sockets to hand over, by role.
static HELD: Mutex<Vec<(String, i32)>> = Mutex::new(Vec::new());

/// `dns-udp=3,api=5` → its pairs; anything malformed is skipped.
pub(crate) fn parse(value: &str) -> Vec<(String, i32)> {
    value
        .split(',')
        .filter_map(|pair| {
            let (role, fd) = pair.split_once('=')?;
            let fd: i32 = fd.trim().parse().ok()?;
            (!role.trim().is_empty() && fd > 2).then(|| (role.trim().to_string(), fd))
        })
        .collect()
}

pub(crate) fn render(held: &[(String, i32)]) -> String {
    held.iter()
        .map(|(role, fd)| format!("{role}={fd}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// First thing in `main`: note the binary, and the sockets handed over.
pub fn init() {
    let _ = EXE.set(
        std::env::current_exe()
            .ok()
            .and_then(|p| p.canonicalize().ok()),
    );
    if let Ok(value) = std::env::var(ENV)
        && let Ok(mut inherited) = INHERITED.lock()
    {
        *inherited = parse(&value);
    }
}

fn take(role: &str) -> Option<i32> {
    let mut inherited = INHERITED.lock().ok()?;
    let at = inherited.iter().position(|(r, _)| r == role)?;
    Some(inherited.remove(at).1)
}

#[cfg(unix)]
fn set_cloexec(fd: i32, on: bool) {
    // SAFETY: fcntl on a descriptor this process owns; failure is harmless
    // (the socket just isn't passed on, or leaks into a child).
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            let flags = if on {
                flags | libc::FD_CLOEXEC
            } else {
                flags & !libc::FD_CLOEXEC
            };
            libc::fcntl(fd, libc::F_SETFD, flags);
        }
    }
}

/// The UDP socket handed over as `role`, if it is bound to `addr` — a socket
/// for an address no longer wanted is closed instead.
pub fn take_udp(role: &str, addr: SocketAddr) -> Option<std::net::UdpSocket> {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let fd = take(role)?;
        // SAFETY: the descriptor was handed over for exactly this role, and
        // nothing else in this process has claimed it.
        let sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
        if sock.local_addr().ok() != Some(addr) || sock.set_nonblocking(true).is_err() {
            return None;
        }
        set_cloexec(fd, true);
        tracing::info!("{role} on {addr}: kept open across the restart");
        Some(sock)
    }
    #[cfg(not(unix))]
    {
        let _ = (role, addr);
        None
    }
}

/// The TCP listener handed over as `role`, if it listens on `addr`.
pub fn take_tcp(role: &str, addr: SocketAddr) -> Option<std::net::TcpListener> {
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let fd = take(role)?;
        // SAFETY: as in `take_udp`.
        let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        if listener.local_addr().ok() != Some(addr) || listener.set_nonblocking(true).is_err() {
            return None;
        }
        set_cloexec(fd, true);
        tracing::info!("{role} on {addr}: kept open across the restart");
        Some(listener)
    }
    #[cfg(not(unix))]
    {
        let _ = (role, addr);
        None
    }
}

/// Pass this socket on at the next restart. Only for sockets open until the
/// process ends: a closed one's number could belong to something else by
/// then.
#[cfg(unix)]
pub fn hold(role: &str, socket: &impl std::os::fd::AsRawFd) {
    if let Ok(mut held) = HELD.lock() {
        held.retain(|(r, _)| r != role);
        held.push((role.to_string(), socket.as_raw_fd()));
    }
}

#[cfg(not(unix))]
pub fn hold<T>(_role: &str, _socket: &T) {}

/// Become a fresh process from the same binary, keeping the held sockets.
/// Falls back to exiting — the service manager starts ferrite again — when
/// that isn't possible.
pub fn restart() -> ! {
    #[cfg(unix)]
    {
        let err = exec();
        tracing::error!(
            "couldn't restart in place ({err}); exiting for the service manager instead"
        );
    }
    std::process::exit(0)
}

#[cfg(unix)]
fn exec() -> std::io::Error {
    use std::os::unix::process::CommandExt;
    let Some(exe) = EXE.get().cloned().flatten() else {
        return std::io::Error::other("the binary's path is unknown");
    };
    let held = HELD.lock().map(|h| h.clone()).unwrap_or_default();
    for (_, fd) in &held {
        set_cloexec(*fd, false);
    }
    #[cfg(target_os = "linux")]
    keep_capabilities();
    tracing::info!("restarting in place, handing over {}", render(&held));
    let err = std::process::Command::new(&exe)
        .args(std::env::args_os().skip(1))
        .env(ENV, render(&held))
        .exec();
    // Still here: the sockets stay ours, as they were.
    for (_, fd) in &held {
        set_cloexec(*fd, true);
    }
    err
}

/// Carry this process's capabilities over to the next image. Granted as the
/// binary's own (`setcap` on the file), they belong to that file: a
/// self-update writes a new one without them, and the image `exec`ed from it
/// would start with none — no port 443 or 853, no DHCP, no kernel WireGuard.
/// Raised into the ambient set they go with the process instead, whatever the
/// new file carries. Granted by the service manager (systemd's
/// `AmbientCapabilities`, OpenRC's `capabilities=`) they are ambient already,
/// and this changes nothing. Best effort: a refusal leaves things as they were.
#[cfg(target_os = "linux")]
fn keep_capabilities() {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: capget/capset with a version-3 header and the two data words it
    // takes; prctl with plain integers.
    unsafe {
        if libc::syscall(
            libc::SYS_capget,
            &mut header as *mut Header,
            data.as_mut_ptr(),
        ) != 0
        {
            return;
        }
        if data.iter().all(|d| d.permitted == 0) {
            return;
        }
        // A capability is raised into the ambient set only once it's
        // inheritable as well as permitted.
        for d in &mut data {
            d.inheritable |= d.permitted;
        }
        if libc::syscall(libc::SYS_capset, &mut header as *mut Header, data.as_ptr()) != 0 {
            tracing::warn!("couldn't keep capabilities across the restart: capset refused");
            return;
        }
        for cap in 0..64u32 {
            if data[(cap / 32) as usize].permitted & (1 << (cap % 32)) != 0 {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_RAISE as libc::c_ulong,
                    cap as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_list_of_sockets_reads_back() {
        let held = vec![("dns-udp".to_string(), 7), ("api".to_string(), 9)];
        assert_eq!(parse(&render(&held)), held);
        assert_eq!(parse(""), vec![]);
        // Junk, and stdin/stdout/stderr, are never taken for sockets.
        assert_eq!(
            parse("dns-udp=x,=4,api=1,dns-tcp=8"),
            vec![("dns-tcp".to_string(), 8)]
        );
    }

    /// A socket handed over is taken only for the address it was bound to.
    #[cfg(unix)]
    #[test]
    fn a_socket_is_taken_for_its_own_address_only() {
        use std::os::fd::IntoRawFd;
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = a.local_addr().unwrap();
        let fd = a.into_raw_fd();
        INHERITED.lock().unwrap().push(("t-udp".into(), fd));
        let other: SocketAddr = "127.0.0.1:1".parse().unwrap();
        assert!(take_udp("t-udp", other).is_none(), "wrong address");
        // That one was closed; hand over a fresh one for the right address.
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_b = b.local_addr().unwrap();
        INHERITED
            .lock()
            .unwrap()
            .push(("t-udp".into(), b.into_raw_fd()));
        let got = take_udp("t-udp", addr_b).unwrap();
        assert_eq!(got.local_addr().unwrap(), addr_b);
        assert!(take_udp("t-udp", addr_b).is_none(), "taken once");
        let _ = addr;
    }

    /// Whatever capabilities the process holds end up ambient, so an `exec`
    /// keeps them. Without any (an ordinary test run) it's a no-op.
    #[cfg(target_os = "linux")]
    #[test]
    fn capabilities_held_are_kept_for_the_next_image() {
        keep_capabilities();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| {
            status
                .lines()
                .find_map(|l| l.strip_prefix(name))
                .map(|v| u64::from_str_radix(v.trim(), 16).unwrap())
                .unwrap()
        };
        let (permitted, ambient) = (field("CapPrm:"), field("CapAmb:"));
        // Root holds every capability, and may not raise them all.
        if permitted != 0 && field("CapBnd:") != permitted {
            assert_eq!(ambient & permitted, permitted);
        }
    }
}
