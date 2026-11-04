//! A connection whose first bytes were already read by someone else — the
//! Tunnels listener reads the TLS name before handing a connection over —
//! given back so the TLS handshake sees them again.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct Rewind<S> {
    peeked: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Rewind<S> {
    pub fn new(peeked: Vec<u8>, inner: S) -> Self {
        Self {
            peeked,
            at: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Rewind<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.at < self.peeked.len() {
            let n = (self.peeked.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.peeked[at..at + n]);
            self.at += n;
            if self.at == self.peeked.len() {
                self.peeked = Vec::new();
                self.at = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Rewind<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn the_peeked_bytes_come_first() {
        let rest: &[u8] = b" world";
        let mut s = Rewind::new(b"hello".to_vec(), rest);
        let mut small = [0u8; 3];
        s.read_exact(&mut small).await.unwrap();
        assert_eq!(&small, b"hel");
        let mut all = Vec::new();
        s.read_to_end(&mut all).await.unwrap();
        assert_eq!(all, b"lo world");
    }
}
