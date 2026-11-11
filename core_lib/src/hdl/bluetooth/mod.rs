//! Bluetooth Classic (RFCOMM) medium.
//!
//! Nearby Connections listens on an *insecure* (no pairing) RFCOMM socket
//! whose SDP service UUID is derived from the service id, and runs the exact
//! same length-prefixed frame protocol over it as over Wi-Fi LAN TCP. So a
//! connected RFCOMM stream is handed to the regular request handlers as a
//! [`Transport`] tagged [`Medium::Bluetooth`].
//!
//! - Incoming: an RFCOMM profile is registered with BlueZ, which publishes the
//!   SDP record and hands us accepted sockets.
//! - Outgoing: the remote's RFCOMM channel is resolved with our own SDP query
//!   (see [`sdp`]) and a raw RFCOMM socket is connected, so the peer does not
//!   need to be paired or known to bluetoothd.

mod sdp;
mod socket;

use std::time::Duration;

use anyhow::anyhow;
use bluer::rfcomm::{Profile, ProfileHandle, Role};
use bluer::{Address, Session};
use futures::StreamExt;
use md5::{Digest, Md5};
use uuid::Uuid;

use super::transport::{Medium, Transport};

const INNER_NAME: &str = "Bluetooth";

/// Nearby Connections service id used by Quick Share.
///
/// Its SHA-256 prefix is also the mDNS service type (`_FC9F5ED42C8A._tcp`).
pub const SERVICE_ID: &str = "NearbySharing";

const SDP_TIMEOUT: Duration = Duration::from_secs(10);
/// A profile dropped by a previous `RQS::stop` is unregistered asynchronously,
/// so an immediate restart can briefly see the UUID as still registered.
const REGISTER_ATTEMPTS: u32 = 10;
const REGISTER_RETRY_DELAY: Duration = Duration::from_millis(200);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Derives a service UUID the way Nearby Connections does (`Uuid(string)` in
/// google/nearby `internal/platform/uuid.cc`): the MD5 of the raw string with
/// the version set to 3 and the IETF variant. No namespace is involved, so
/// this is *not* RFC 4122 UUIDv3.
pub fn nearby_uuid(name: &str) -> Uuid {
    let mut bytes: [u8; 16] = Md5::digest(name.as_bytes()).into();
    bytes[6] = (bytes[6] & 0x0f) | 0x30;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

/// RFCOMM service UUID Quick Share listens on.
pub fn service_uuid() -> Uuid {
    nearby_uuid(SERVICE_ID)
}

/// Returns the Bluetooth address if `addr` is one (`AA:BB:CC:DD:EE:FF`).
pub fn parse_address(addr: &str) -> Option<Address> {
    addr.parse().ok()
}

/// Accepts incoming Quick Share RFCOMM connections.
///
/// The SDP record and the listening socket live as long as this value.
///
/// Note: BlueZ leaves the adapter non-connectable and only lets the kernel
/// page-scan for bonded devices, so an unpaired phone can only reach this
/// server while the adapter is discoverable/connectable. Making the adapter
/// reachable belongs with advertising and is not done here.
pub struct BluetoothServer {
    // Keeps the D-Bus connection the profile is registered on alive.
    _session: Session,
    profile: ProfileHandle,
}

impl BluetoothServer {
    pub async fn new() -> Result<Self, anyhow::Error> {
        let session = Session::new().await?;
        // Fail early (and let the caller carry on without Bluetooth) when
        // there is no adapter at all.
        let adapter = session.default_adapter().await?;

        let mut attempt = 1;
        let profile = loop {
            match session.register_profile(profile()).await {
                Ok(profile) => break profile,
                Err(err) if is_already_registered(&err) && attempt < REGISTER_ATTEMPTS => {
                    debug!("{INNER_NAME}: previous registration still active, retrying");
                    attempt += 1;
                    tokio::time::sleep(REGISTER_RETRY_DELAY).await;
                }
                Err(err) => return Err(err.into()),
            }
        };

        info!(
            "{INNER_NAME}: RFCOMM service {} registered on {}",
            service_uuid(),
            adapter.name()
        );

        Ok(Self {
            _session: session,
            profile,
        })
    }

    /// Waits for the next incoming connection.
    ///
    /// Only fails when the server can no longer accept anything; a single
    /// connection that cannot be set up is logged and skipped.
    pub async fn accept(&mut self) -> Result<(Transport, Address), anyhow::Error> {
        loop {
            let req = self
                .profile
                .next()
                .await
                .ok_or_else(|| anyhow!("RFCOMM profile was unregistered"))?;
            let addr = req.device();
            match req.accept() {
                Ok(stream) => {
                    debug!("{INNER_NAME}: accepted RFCOMM connection from {addr}");
                    return Ok((Transport::new(Medium::Bluetooth, stream), addr));
                }
                Err(err) => warn!("{INNER_NAME}: dropping RFCOMM connection from {addr}: {err}"),
            }
        }
    }
}

fn profile() -> Profile {
    Profile {
        uuid: service_uuid(),
        name: Some(SERVICE_ID.into()),
        role: Some(Role::Server),
        // 0 lets the kernel pick a free channel; BlueZ then publishes the
        // channel it actually got in the SDP record. Leaving it unset
        // publishes a record without starting a listener.
        channel: Some(0),
        // Insecure RFCOMM, like Android's listenUsingInsecureRfcommWithServiceRecord.
        require_authentication: Some(false),
        require_authorization: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    }
}

fn is_already_registered(err: &bluer::Error) -> bool {
    err.kind == bluer::ErrorKind::NotPermitted && err.message.contains("already registered")
}

/// Connects to a Quick Share endpoint's RFCOMM service at `addr`.
pub async fn connect(addr: Address) -> Result<Transport, anyhow::Error> {
    let channel = tokio::time::timeout(SDP_TIMEOUT, sdp::find_rfcomm_channel(addr, service_uuid()))
        .await
        .map_err(|_| anyhow!("SDP query to {addr} timed out"))??;
    debug!("{INNER_NAME}: {addr} serves Quick Share on RFCOMM channel {channel}");

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket::rfcomm_stream(addr, channel))
        .await
        .map_err(|_| anyhow!("RFCOMM connection to {addr} timed out"))??;

    Ok(Transport::new(Medium::Bluetooth, stream))
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use super::*;

    #[test]
    fn service_uuid_matches_quick_share() {
        assert_eq!(
            service_uuid(),
            uuid::uuid!("a82efa21-ae5c-3dde-9bbc-f16da7b16c5a")
        );
    }

    #[test]
    fn service_id_matches_mdns_service_type() {
        let digest = Sha256::digest(SERVICE_ID.as_bytes());
        assert_eq!(hex::encode_upper(&digest[..6]), "FC9F5ED42C8A");
    }

    #[test]
    fn distinguishes_bluetooth_from_ip_addresses() {
        assert!(parse_address("E4:0D:36:CE:AE:AE").is_some());
        assert!(parse_address("192.168.1.10:41234").is_none());
        assert!(parse_address("[fe80::1]:41234").is_none());
    }
}
