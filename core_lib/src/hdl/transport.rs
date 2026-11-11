//! Medium-agnostic byte stream used by [`InboundRequest`](super::InboundRequest)
//! and [`OutboundRequest`](super::OutboundRequest).
//!
//! Nearby Connections frames are length-prefixed protobufs regardless of the
//! medium (Wi-Fi LAN TCP, Bluetooth RFCOMM, Wi-Fi hotspot TCP, ...), so the
//! request handlers only need an ordered, reliable byte stream.
//!
//! The stream is type-erased rather than made a generic parameter so that it
//! can be swapped for a different medium in the middle of a connection, which
//! is what a bandwidth upgrade (e.g. Bluetooth -> Wi-Fi hotspot) does.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;

/// Any stream a [`Transport`] can wrap.
pub trait TransportStream: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}

impl<T> TransportStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static {}

/// A connected byte stream to a remote endpoint, tagged with its [`Medium`].
pub struct Transport {
    medium: Medium,
    stream: Box<dyn TransportStream>,
}

impl Transport {
    pub fn new(medium: Medium, stream: impl TransportStream) -> Self {
        Self {
            medium,
            stream: Box::new(stream),
        }
    }

    pub fn medium(&self) -> Medium {
        self.medium
    }
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("medium", &self.medium)
            .finish_non_exhaustive()
    }
}

impl From<TcpStream> for Transport {
    fn from(stream: TcpStream) -> Self {
        Self::new(Medium::WifiLan, stream)
    }
}

impl AsyncRead for Transport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.stream.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn round_trips_over_in_memory_stream() {
        let (a, b) = tokio::io::duplex(64);
        let mut a = Transport::new(Medium::Bluetooth, a);
        let mut b = Transport::new(Medium::Bluetooth, b);

        a.write_all(b"\x00\x00\x00\x03abc").await.unwrap();
        a.flush().await.unwrap();

        let mut buf = [0u8; 7];
        b.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"\x00\x00\x00\x03abc");
        assert_eq!(b.medium(), Medium::Bluetooth);
    }

    #[tokio::test]
    async fn tcp_stream_is_tagged_wifi_lan() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, server) = tokio::join!(TcpStream::connect(addr), listener.accept());

        assert_eq!(Transport::from(client.unwrap()).medium(), Medium::WifiLan);
        assert_eq!(Transport::from(server.unwrap().0).medium(), Medium::WifiLan);
    }
}
