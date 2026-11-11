//! Outgoing Bluetooth socket connections.
//!
//! bluer's `connect()` registers the socket with the tokio reactor *before*
//! calling `connect(2)`. The socket is writable in its initial (unconnected)
//! state, so that readiness is still cached when bluer then waits for the
//! connection to complete: the wait returns immediately, `SO_ERROR` is still
//! 0, and the not-yet-connected socket is reported as connected. The first
//! I/O then fails with ENOTCONN, tens of microseconds in.
//!
//! Like mio does for TCP, we start the non-blocking `connect(2)` first and
//! only then register the socket, so the readiness we wait for is the
//! connection's outcome. The connected fd is then handed to bluer.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};

use bluer::Address;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

const BTPROTO_L2CAP: libc::c_int = 0;
const BTPROTO_RFCOMM: libc::c_int = 3;
const BDADDR_BREDR: u8 = 0x00;

/// `struct sockaddr_l2` from `<bluetooth/l2cap.h>`.
#[repr(C)]
struct SockaddrL2 {
    l2_family: libc::sa_family_t,
    l2_psm: u16,
    l2_bdaddr: [u8; 6],
    l2_cid: u16,
    l2_bdaddr_type: u8,
}

/// `struct sockaddr_rc` from `<bluetooth/rfcomm.h>`.
#[repr(C)]
struct SockaddrRc {
    rc_family: libc::sa_family_t,
    rc_bdaddr: [u8; 6],
    rc_channel: u8,
}

/// `bdaddr_t` is little-endian; `Address` is in display order.
fn bdaddr(addr: Address) -> [u8; 6] {
    let mut b = addr.0;
    b.reverse();
    b
}

/// Connects an L2CAP SEQPACKET socket to `psm` on a BR/EDR device.
pub async fn l2cap_seq_packet(addr: Address, psm: u16) -> io::Result<bluer::l2cap::SeqPacket> {
    let sa = SockaddrL2 {
        l2_family: libc::AF_BLUETOOTH as _,
        l2_psm: psm.to_le(),
        l2_bdaddr: bdaddr(addr),
        l2_cid: 0,
        l2_bdaddr_type: BDADDR_BREDR,
    };
    let fd = connect(libc::SOCK_SEQPACKET, BTPROTO_L2CAP, &sa).await?;
    // SAFETY: `fd` is an owned, connected, non-blocking L2CAP socket.
    unsafe { bluer::l2cap::SeqPacket::from_raw_fd(fd.into_raw_fd()) }
}

/// Connects an RFCOMM stream socket to `channel` on a BR/EDR device.
///
/// No security level is requested, i.e. an insecure (unpaired) connection,
/// matching what Nearby Connections listens for.
pub async fn rfcomm_stream(addr: Address, channel: u8) -> io::Result<bluer::rfcomm::Stream> {
    let sa = SockaddrRc {
        rc_family: libc::AF_BLUETOOTH as _,
        rc_bdaddr: bdaddr(addr),
        rc_channel: channel,
    };
    let fd = connect(libc::SOCK_STREAM, BTPROTO_RFCOMM, &sa).await?;
    // SAFETY: `fd` is an owned, connected, non-blocking RFCOMM socket.
    unsafe { bluer::rfcomm::Stream::from_raw_fd(fd.into_raw_fd()) }
}

async fn connect<A>(ty: libc::c_int, proto: libc::c_int, sa: &A) -> io::Result<OwnedFd> {
    // SAFETY: plain syscall; the result is checked before use.
    let raw = unsafe {
        libc::socket(
            libc::AF_BLUETOOTH,
            ty | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            proto,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a freshly created fd we own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    // SAFETY: `sa` points to a valid sockaddr of `size_of::<A>()` bytes.
    let rc = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (sa as *const A).cast(),
            size_of::<A>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(fd);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EINPROGRESS) {
        return Err(err);
    }

    // Registered only now: the next writable/hang-up event is the outcome.
    let afd = AsyncFd::with_interest(fd, Interest::WRITABLE)?;
    let mut guard = afd.writable().await?;
    let ready = guard.ready();
    guard.clear_ready();
    drop(guard);

    if let Some(err) = take_socket_error(afd.get_ref())? {
        return Err(err);
    }
    // Torn down without an error code (seen when the connection is aborted
    // locally); never report that as connected.
    if ready.is_write_closed() {
        return Err(io::Error::from_raw_os_error(libc::ENOTCONN));
    }

    Ok(afd.into_inner())
}

fn take_socket_error(fd: &OwnedFd) -> io::Result<Option<io::Error>> {
    let mut err: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `err`/`len` describe a valid c_int buffer.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut err as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((err != 0).then(|| io::Error::from_raw_os_error(err)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_layouts_match_kernel() {
        // sizeof(struct sockaddr_l2) == 14, sizeof(struct sockaddr_rc) == 10
        assert_eq!(size_of::<SockaddrL2>(), 14);
        assert_eq!(size_of::<SockaddrRc>(), 10);
    }

    #[test]
    fn bdaddr_is_little_endian() {
        let addr: Address = "E4:0D:36:CE:AE:01".parse().unwrap();
        assert_eq!(bdaddr(addr), [0x01, 0xae, 0xce, 0x36, 0x0d, 0xe4]);
    }
}
