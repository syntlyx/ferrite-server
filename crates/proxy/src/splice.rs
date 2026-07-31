//! Zero-copy relay for spliced connections (Linux).
//!
//! The generic relay reads into a userspace buffer and writes it back out, so
//! every proxied byte is copied twice (kernel → buffer → kernel) and costs two
//! syscalls per chunk. With the kernel WireGuard backend the tunnel crypto moved
//! into the kernel, which left *this* copying as the dominant per-byte CPU cost
//! of a tunneled transfer.
//!
//! When both ends are real sockets — kernel-WG, `direct`, `evasion` — the kernel
//! can move the bytes itself: `splice(2)` into a pipe, then out of the pipe into
//! the peer, passing page references instead of copying payload. That removes
//! both copies and the userspace buffers. Needs no privileges.
//!
//! The userspace WireGuard backend hands out an in-memory `DuplexStream`, not a
//! socket, so it keeps using the generic relay (as does every non-Linux build).
//!
//! Behaviour matches the generic relay: one-way EOF half-closes that direction,
//! a connection quiet in *both* directions is reaped, and per-egress byte
//! counters are updated live so the UI shows rates mid-transfer.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::Interest;
use tokio::net::TcpStream;

use super::stats::EgressStats;

/// Bytes per `splice` call, and the pipe capacity we rely on. 64 KiB is the
/// Linux default pipe size, so this asks for exactly what a pipe holds without
/// an `F_SETPIPE_SZ` bump (which would count against the per-user pipe budget).
const CHUNK: usize = 64 * 1024;

/// What a finished relay moved, plus how it ended. The byte totals are returned
/// even on error: those bytes did cross the tunnel and must still be attributed
/// to the domain.
pub(super) struct Relayed {
    pub up: u64,
    pub down: u64,
    pub result: io::Result<()>,
}

/// A kernel pipe used as the staging area for one direction. Both ends are
/// non-blocking; the fds close on drop.
struct Pipe {
    r: OwnedFd,
    w: OwnedFd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        // O_CLOEXEC so a fork/exec (the self-updater) never inherits these.
        let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: pipe2 succeeded, so both fds are fresh and owned by us.
        Ok(Self {
            r: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            w: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        })
    }
}

/// Splice both directions between two sockets until both close, an I/O error
/// occurs, or nothing moves in either direction for `idle`.
///
/// Returns `None` when the pipes can't be created (fd exhaustion) — the caller
/// falls back to the generic relay rather than dropping the connection.
pub(super) async fn relay(
    client: &TcpStream,
    egress: &TcpStream,
    idle: Duration,
    stats: Option<&EgressStats>,
) -> Option<Relayed> {
    let (to_egress, to_client) = match (Pipe::new(), Pipe::new()) {
        (Ok(a), Ok(b)) => (a, b),
        (a, b) => {
            let e = a.err().or(b.err());
            tracing::debug!("proxy: splice pipes unavailable ({e:?}) → userspace relay");
            return None;
        }
    };

    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);
    // Bumped on every byte moved in either direction; the watchdog reaps the
    // connection when a whole idle window passes without a bump.
    let activity = AtomicU64::new(0);

    let live = stats.map(|s| s.byte_counters());
    let client_to_egress = pump(
        client,
        egress,
        &to_egress,
        &up,
        live.map(|(up, _)| up),
        &activity,
    );
    let egress_to_client = pump(
        egress,
        client,
        &to_client,
        &down,
        live.map(|(_, down)| down),
        &activity,
    );
    // Both directions must finish (or the watchdog fire): a half-closed
    // connection still streams the other way, exactly like the generic relay.
    let both = async {
        let (a, b) = tokio::join!(client_to_egress, egress_to_client);
        a.and(b)
    };

    let result = tokio::select! {
        r = both => r,
        _ = idle_watchdog(&activity, idle) => Ok(()), // quiet too long → reap, not an error
    };

    Some(Relayed {
        up: up.load(Ordering::Relaxed),
        down: down.load(Ordering::Relaxed),
        result,
    })
}

/// One direction: fill the pipe from `src`, drain it into `dst`, repeat.
///
/// The pipe is only refilled once fully drained, so a full-pipe `EAGAIN` can
/// never spin against a readable source. On EOF the pipe is drained first, then
/// `dst`'s write side is shut down so the peer sees the close.
async fn pump(
    src: &TcpStream,
    dst: &TcpStream,
    pipe: &Pipe,
    moved: &AtomicU64,
    live: Option<&AtomicU64>,
    activity: &AtomicU64,
) -> io::Result<()> {
    let mut buffered = 0usize;
    let mut eof = false;

    loop {
        if buffered == 0 {
            if eof {
                break;
            }
            src.readable().await?;
            match src.try_io(Interest::READABLE, || {
                splice_once(src.as_raw_fd(), pipe.w.as_raw_fd(), CHUNK)
            }) {
                Ok(0) => eof = true,
                Ok(n) => {
                    buffered = n;
                    activity.fetch_add(1, Ordering::Relaxed);
                }
                // try_io cleared readiness — wait for the next readable event.
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        } else {
            dst.writable().await?;
            match dst.try_io(Interest::WRITABLE, || {
                splice_once(pipe.r.as_raw_fd(), dst.as_raw_fd(), buffered)
            }) {
                Ok(0) => break, // peer accepts nothing more
                Ok(n) => {
                    buffered -= n;
                    moved.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(counter) = live {
                        counter.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    activity.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    // Propagate the half-close. Errors are immaterial: the peer may already be
    // gone, and the other direction owns the connection's fate from here.
    unsafe { libc::shutdown(dst.as_raw_fd(), libc::SHUT_WR) };
    Ok(())
}

/// One non-blocking `splice` between a socket and a pipe end.
fn splice_once(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    // SAFETY: both fds are owned by the caller and live for the call; the
    // offsets must be NULL for pipes, which is what we pass.
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Resolve once a full `idle` window passes with no byte moved in either
/// direction. Sampling the counter (rather than resetting a timer per chunk)
/// keeps the hot path free of timer work, at the cost of reaping somewhere in
/// `[idle, 2 × idle)` — the point is releasing genuinely dead connections, not
/// hitting the deadline exactly.
async fn idle_watchdog(activity: &AtomicU64, idle: Duration) {
    let mut last = activity.load(Ordering::Relaxed);
    loop {
        tokio::time::sleep(idle).await;
        let now = activity.load(Ordering::Relaxed);
        if now == last {
            return;
        }
        last = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A pair of connected TCP sockets over loopback.
    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connect = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = listener.accept().await.unwrap();
        (connect.await.unwrap(), server)
    }

    /// Full duplex through the splice relay: bytes cross both ways, both totals
    /// are counted, and the relay returns cleanly once both ends EOF.
    #[tokio::test]
    async fn splices_both_directions_and_counts_bytes() {
        // client ↔ [relay] ↔ egress, with test-owned far ends.
        let (client_far, client_near) = pair().await;
        let (egress_near, egress_far) = pair().await;

        let task = tokio::spawn(async move {
            relay(&client_near, &egress_near, Duration::from_secs(5), None)
                .await
                .expect("pipes available")
        });

        let mut client_far = client_far;
        let mut egress_far = egress_far;
        client_far.write_all(b"ping from client").await.unwrap();
        let mut got = [0u8; 16];
        egress_far.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping from client");

        egress_far.write_all(b"pong").await.unwrap();
        let mut back = [0u8; 4];
        client_far.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");

        // Closing both far ends ends both directions → the relay returns.
        drop(client_far);
        drop(egress_far);
        let relayed = task.await.unwrap();
        assert!(relayed.result.is_ok(), "clean close must not be an error");
        assert_eq!(relayed.up, 16, "client→egress bytes");
        assert_eq!(relayed.down, 4, "egress→client bytes");
    }

    /// A one-way EOF must half-close, not tear down: the surviving direction
    /// keeps streaming (a client that finished its request still gets the
    /// response body).
    #[tokio::test]
    async fn half_close_keeps_the_other_direction_alive() {
        let (client_far, client_near) = pair().await;
        let (egress_near, egress_far) = pair().await;

        let task = tokio::spawn(async move {
            relay(&client_near, &egress_near, Duration::from_secs(5), None)
                .await
                .expect("pipes available")
        });

        let mut client_far = client_far;
        let mut egress_far = egress_far;
        client_far.write_all(b"req").await.unwrap();
        client_far.shutdown().await.unwrap(); // EOF client→egress only

        let mut req = [0u8; 3];
        egress_far.read_exact(&mut req).await.unwrap();
        // The egress side must observe EOF…
        assert_eq!(egress_far.read(&mut [0u8; 8]).await.unwrap(), 0);
        // …and still be able to answer.
        egress_far.write_all(b"late response").await.unwrap();
        drop(egress_far);

        let mut body = Vec::new();
        client_far.read_to_end(&mut body).await.unwrap();
        assert_eq!(&body, b"late response");

        let relayed = task.await.unwrap();
        assert!(relayed.result.is_ok());
        assert_eq!(relayed.down, 13);
    }

    /// A connection with no traffic in either direction is reaped (this is what
    /// keeps idle keep-alive sessions from pinning their egress state), and the
    /// reap is reported as a clean close. Real (short) sleeps: pausing time would
    /// need tokio's `test-util` feature.
    #[tokio::test]
    async fn reaps_a_connection_idle_in_both_directions() {
        let (client_far, client_near) = pair().await;
        let (egress_near, egress_far) = pair().await;

        let relayed = relay(&client_near, &egress_near, Duration::from_millis(50), None)
            .await
            .expect("pipes available");

        assert!(relayed.result.is_ok(), "idle reap is a clean close");
        assert_eq!((relayed.up, relayed.down), (0, 0));
        drop((client_far, egress_far));
    }
}
