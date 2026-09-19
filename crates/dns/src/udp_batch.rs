//! Moving UDP datagrams in batches instead of one per system call (Linux).
//!
//! A query costs two syscalls on the plain path — one `recvfrom`, one `sendto`
//! — and after the in-memory pipeline was cut to a few hundred nanoseconds,
//! those two are what a query actually spends its time on. `recvmmsg` and
//! `sendmmsg` take up to [`BATCH`] datagrams per call, so a busy resolver pays
//! two syscalls per batch rather than two per query. At one query at a time the
//! batch holds one datagram and nothing changes, which is the case on a quiet
//! network; the saving is all in the bursts.
//!
//! Everything here is `unsafe` FFI on the hottest path in the process, so it is
//! written to be readable rather than clever: fixed-size slots, pointers
//! rebuilt from scratch before every call (a few dozen stores, far cheaper than
//! the syscall they serve), and no assumption that the kernel filled a slot it
//! did not report.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::ptr;

use tokio::io::Interest;
use tokio::net::UdpSocket;

/// Datagrams per system call. Large enough that a burst collapses into one
/// call, small enough that the slot arrays stay a few hundred kilobytes.
pub const BATCH: usize = 32;

/// Reusable slots for one socket's batched receives and sends.
pub struct UdpBatch {
    /// One receive buffer per slot, each sized for the largest datagram.
    bufs: Vec<Vec<u8>>,
    /// Source address of each received datagram, filled by the kernel.
    recv_addrs: Vec<libc::sockaddr_storage>,
    recv_iovs: Vec<libc::iovec>,
    recv_msgs: Vec<libc::mmsghdr>,
    /// Destination address of each queued reply.
    send_addrs: Vec<libc::sockaddr_storage>,
    send_iovs: Vec<libc::iovec>,
    send_msgs: Vec<libc::mmsghdr>,
}

impl UdpBatch {
    pub fn new(datagram_bytes: usize) -> Self {
        Self {
            bufs: (0..BATCH).map(|_| vec![0u8; datagram_bytes]).collect(),
            // SAFETY: `sockaddr_storage`, `iovec` and `mmsghdr` are plain C
            // structs whose all-zero form is valid; every field that matters is
            // written before each call.
            recv_addrs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            recv_iovs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            recv_msgs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            send_addrs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            send_iovs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
            send_msgs: (0..BATCH).map(|_| unsafe { zeroed() }).collect(),
        }
    }

    /// Wait for the socket to be readable, then take up to [`BATCH`] datagrams
    /// from it in one call. Returns how many arrived; read them back with
    /// [`Self::datagram`].
    pub async fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        let fd = socket.as_raw_fd();
        socket
            .async_io(Interest::READABLE, || {
                self.point_recv_slots();
                // SAFETY: `recv_msgs` holds BATCH initialised headers, each
                // pointing at this struct's own buffers and address slots (see
                // `point_recv_slots`). MSG_DONTWAIT with a null timeout makes
                // the call return what is queued without blocking, which is
                // what `async_io` expects so it can re-arm on WouldBlock.
                let n = unsafe {
                    libc::recvmmsg(
                        fd,
                        self.recv_msgs.as_mut_ptr(),
                        BATCH as libc::c_uint,
                        // `as _`: glibc types this flag as `c_int`, musl as
                        // `c_uint`, and this crate builds against both.
                        libc::MSG_DONTWAIT as _,
                        ptr::null_mut(),
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            })
            .await
    }

    /// The `i`-th datagram of the last [`Self::recv`], and where it came from.
    /// `None` for a source address the kernel reported in a family we don't
    /// speak — the datagram is then unanswerable, so it is dropped.
    pub fn datagram(&self, i: usize) -> Option<(&[u8], SocketAddr)> {
        let msg = &self.recv_msgs[i];
        let len = (msg.msg_len as usize).min(self.bufs[i].len());
        let addr = to_socket_addr(&self.recv_addrs[i], msg.msg_hdr.msg_namelen)?;
        Some((&self.bufs[i][..len], addr))
    }

    /// Send every reply in as few calls as the kernel takes. Each reply carries
    /// its own destination, so one batch can answer many clients.
    ///
    /// A datagram the kernel refuses is dropped with a log line, exactly as a
    /// failed single send would be: a client that gets no answer retries, and
    /// one bad destination must not cost the rest of the batch.
    pub async fn send(
        &mut self,
        socket: &UdpSocket,
        replies: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<()> {
        let mut sent = 0usize;
        while sent < replies.len() {
            let chunk = &replies[sent..(sent + BATCH).min(replies.len())];
            let n = self.send_chunk(socket, chunk).await?;
            if n == 0 {
                break; // nothing moved; stop rather than spin
            }
            sent += n;
        }
        Ok(())
    }

    async fn send_chunk(
        &mut self,
        socket: &UdpSocket,
        chunk: &[(Vec<u8>, SocketAddr)],
    ) -> io::Result<usize> {
        let fd = socket.as_raw_fd();
        socket
            .async_io(Interest::WRITABLE, || {
                self.point_send_slots(chunk);
                // SAFETY: the first `chunk.len()` send headers were just
                // pointed at the caller's payloads (borrowed for this call) and
                // this struct's address slots.
                let n = unsafe {
                    libc::sendmmsg(
                        fd,
                        self.send_msgs.as_mut_ptr(),
                        chunk.len() as libc::c_uint,
                        libc::MSG_DONTWAIT as _,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(n as usize)
            })
            .await
    }

    /// Point every receive header at its own buffer and address slot, and reset
    /// the lengths the kernel overwrites.
    fn point_recv_slots(&mut self) {
        for i in 0..BATCH {
            self.recv_iovs[i] = libc::iovec {
                iov_base: self.bufs[i].as_mut_ptr().cast(),
                iov_len: self.bufs[i].len(),
            };
            let addr: *mut libc::sockaddr_storage = &raw mut self.recv_addrs[i];
            let iov: *mut libc::iovec = &raw mut self.recv_iovs[i];
            let msg = &mut self.recv_msgs[i];
            msg.msg_hdr.msg_name = addr.cast();
            msg.msg_hdr.msg_namelen = size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            msg.msg_hdr.msg_iov = iov;
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_control = ptr::null_mut();
            msg.msg_hdr.msg_controllen = 0;
            msg.msg_hdr.msg_flags = 0;
            msg.msg_len = 0;
        }
    }

    /// Point the first `chunk.len()` send headers at the caller's payloads.
    fn point_send_slots(&mut self, chunk: &[(Vec<u8>, SocketAddr)]) {
        for (i, (payload, dest)) in chunk.iter().enumerate() {
            let (addr, addr_len) = from_socket_addr(*dest);
            self.send_addrs[i] = addr;
            self.send_iovs[i] = libc::iovec {
                // The kernel only reads from this buffer, and the borrow lasts
                // exactly as long as the call below.
                iov_base: payload.as_ptr() as *mut libc::c_void,
                iov_len: payload.len(),
            };
            let addr: *mut libc::sockaddr_storage = &raw mut self.send_addrs[i];
            let iov: *mut libc::iovec = &raw mut self.send_iovs[i];
            let msg = &mut self.send_msgs[i];
            msg.msg_hdr.msg_name = addr.cast();
            msg.msg_hdr.msg_namelen = addr_len;
            msg.msg_hdr.msg_iov = iov;
            msg.msg_hdr.msg_iovlen = 1;
            msg.msg_hdr.msg_control = ptr::null_mut();
            msg.msg_hdr.msg_controllen = 0;
            msg.msg_hdr.msg_flags = 0;
            msg.msg_len = 0;
        }
    }
}

/// Read a kernel-filled address. `None` for anything that is not IPv4 or IPv6,
/// or for a truncated one.
fn to_socket_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET if len as usize >= size_of::<libc::sockaddr_in>() => {
            // SAFETY: the family says this storage holds a `sockaddr_in`, and
            // the reported length covers it.
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            Some(SocketAddr::V4(SocketAddrV4::new(
                ip,
                u16::from_be(sin.sin_port),
            )))
        }
        libc::AF_INET6 if len as usize >= size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for `sockaddr_in6`.
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                u16::from_be(sin6.sin6_port),
                u32::from_be(sin6.sin6_flowinfo),
                sin6.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Lay an address out the way the kernel wants it, with the length that names
/// which of the two it is.
fn from_socket_addr(addr: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: all-zero is a valid `sockaddr_storage`; the fields that matter
    // are written below.
    let mut storage: libc::sockaddr_storage = unsafe { zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            // SAFETY: writing the `sockaddr_in` view of a storage large enough
            // to hold one.
            let sin = unsafe { &mut *(&raw mut storage as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            (storage, size_of::<libc::sockaddr_in>() as libc::socklen_t)
        }
        SocketAddr::V6(v6) => {
            // SAFETY: as above, for `sockaddr_in6`.
            let sin6 = unsafe { &mut *(&raw mut storage as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr.s6_addr = v6.ip().octets();
            sin6.sin6_flowinfo = v6.flowinfo().to_be();
            sin6.sin6_scope_id = v6.scope_id();
            (storage, size_of::<libc::sockaddr_in6>() as libc::socklen_t)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An address has to survive the trip into the kernel's layout and back,
    /// or a reply goes to the wrong client.
    #[test]
    fn addresses_round_trip_through_the_kernel_layout() {
        for text in [
            "192.0.2.10:53000",
            "127.0.0.1:5353",
            "255.255.255.255:65535",
            "0.0.0.0:0",
            "[2001:db8::1]:53",
            "[::1]:5353",
            "[fe80::1c2b:3aff:fe4d:5e6f]:1234",
        ] {
            let addr: SocketAddr = text.parse().unwrap();
            let (storage, len) = from_socket_addr(addr);
            assert_eq!(
                to_socket_addr(&storage, len),
                Some(addr),
                "{text} did not survive the round trip"
            );
        }
    }

    #[test]
    fn unknown_or_truncated_addresses_are_refused() {
        let addr: SocketAddr = "192.0.2.10:53".parse().unwrap();
        let (storage, len) = from_socket_addr(addr);
        // A length that doesn't cover the struct means the kernel wrote less
        // than we would read.
        assert_eq!(to_socket_addr(&storage, len - 1), None);

        // SAFETY: a zeroed storage is valid; family 0 is not one we speak.
        let unknown: libc::sockaddr_storage = unsafe { zeroed() };
        assert_eq!(to_socket_addr(&unknown, 128), None);
    }

    /// Everything the batch does with real sockets: many senders, one batched
    /// receive, replies fanned back out — each to the client that asked.
    #[tokio::test]
    async fn a_batch_answers_every_sender_in_turn() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        // More senders than fit in one batch, so the loop runs twice.
        let senders: Vec<UdpSocket> = {
            let mut v = Vec::new();
            for _ in 0..BATCH + 5 {
                v.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            }
            v
        };
        for (i, sender) in senders.iter().enumerate() {
            sender
                .send_to(format!("query-{i}").as_bytes(), server_addr)
                .await
                .unwrap();
        }

        // Receive in batches until every datagram is accounted for, answering
        // each sender with the payload it sent.
        let mut batch = UdpBatch::new(512);
        let mut answered = 0usize;
        while answered < senders.len() {
            let n = batch.recv(&server).await.unwrap();
            let replies: Vec<(Vec<u8>, SocketAddr)> = (0..n)
                .filter_map(|i| batch.datagram(i))
                .map(|(payload, src)| (payload.to_vec(), src))
                .collect();
            answered += replies.len();
            batch.send(&server, &replies).await.unwrap();
        }
        assert_eq!(answered, senders.len());

        // Every sender gets back exactly its own payload — the property that
        // breaks first if an address slot is mismatched.
        for (i, sender) in senders.iter().enumerate() {
            let mut buf = [0u8; 512];
            let (len, from) = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                sender.recv_from(&mut buf),
            )
            .await
            .expect("sender never got its answer")
            .unwrap();
            assert_eq!(from, server_addr);
            assert_eq!(&buf[..len], format!("query-{i}").as_bytes());
        }
    }
}
