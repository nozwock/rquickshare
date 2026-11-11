//! Bandwidth upgrade: moving an established connection from a slow medium
//! (Bluetooth) to Wi-Fi, following google/nearby `bwu_manager.cc`.
//!
//! The device that accepted the connection (the receiver) proposes an
//! upgrade path and hosts it, e.g. a Wi-Fi Direct group or a hotspot. The
//! other side:
//!
//! 1. receives `UPGRADE_PATH_AVAILABLE` on the old channel;
//! 2. joins the network and opens a TCP connection to `gateway:port`;
//! 3. writes a plaintext `CLIENT_INTRODUCTION` on it and, if supported,
//!    reads a plaintext `CLIENT_INTRODUCTION_ACK` ([`connect_upgrade_path`]).
//!
//! Then both sides run the same switch-over: stop writing, send
//! `LAST_WRITE_TO_PRIOR_CHANNEL` on the old channel; answer the peer's
//! `LAST_WRITE_TO_PRIOR_CHANNEL` with `SAFE_TO_CLOSE_PRIOR_CHANNEL`; on the
//! peer's `SAFE_TO_CLOSE_PRIOR_CHANNEL`, send a plaintext disconnection on
//! the old channel, close it and resume on the new one.
//!
//! When the upgrade path `supports_disabling_encryption` (Android sets it
//! for P2P_POINT_TO_POINT), the new channel carries plain offline frames:
//! the Wi-Fi link is already protected by a one-off passphrase. Otherwise
//! the encryption context (keys and sequence numbers) carries over.

use std::time::Duration;

use anyhow::{anyhow, bail, ensure};
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::Transport;
use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;
use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::{
    ClientIntroduction, EventType, UpgradePathInfo,
};
use crate::location_nearby_connections::{
    BandwidthUpgradeNegotiationFrame, DisconnectionFrame, OfflineFrame, V1Frame, offline_frame,
    v1_frame,
};

/// Frames bigger than this are refused.
pub(crate) const MAX_FRAME_LENGTH: usize = 5 * 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const INTRODUCTION_TIMEOUT: Duration = Duration::from_secs(10);

/// A frame read from one of the connection's channels. `generation` tells
/// channels apart, so frames still in flight from a closed one can be
/// ignored.
#[derive(Debug)]
pub(crate) struct Incoming {
    pub generation: u32,
    pub frame: Result<Vec<u8>, String>,
}

/// Reads length-prefixed frames on its own task, so frames are received
/// while the owner is busy writing. Stops when dropped.
#[derive(Debug)]
pub(crate) struct FrameReader(JoinHandle<()>);

impl FrameReader {
    pub fn spawn(
        mut read: ReadHalf<Transport>,
        generation: u32,
        tx: mpsc::UnboundedSender<Incoming>,
    ) -> Self {
        Self(tokio::spawn(async move {
            loop {
                let frame = read_frame(&mut read).await.map_err(|e| e.to_string());
                let failed = frame.is_err();
                if tx.send(Incoming { generation, frame }).is_err() || failed {
                    break;
                }
            }
        }))
    }
}

impl Drop for FrameReader {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) async fn read_frame(
    read: &mut (impl AsyncRead + Unpin),
) -> Result<Vec<u8>, anyhow::Error> {
    let mut len = [0u8; 4];
    read.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    ensure!(len <= MAX_FRAME_LENGTH, "frame too long ({len} bytes)");
    let mut frame = vec![0u8; len];
    read.read_exact(&mut frame).await?;
    Ok(frame)
}

pub(crate) async fn write_frame(
    write: &mut (impl AsyncWrite + Unpin),
    frame: &[u8],
) -> Result<(), anyhow::Error> {
    let mut data = Vec::with_capacity(4 + frame.len());
    data.extend_from_slice(&u32::try_from(frame.len())?.to_be_bytes());
    data.extend_from_slice(frame);
    write.write_all(&data).await?;
    write.flush().await?;
    Ok(())
}

fn v1(frame: V1Frame) -> OfflineFrame {
    OfflineFrame {
        version: Some(offline_frame::Version::V1.into()),
        v1: Some(frame),
    }
}

pub(crate) fn negotiation(
    event: EventType,
    f: impl FnOnce(&mut BandwidthUpgradeNegotiationFrame),
) -> OfflineFrame {
    let mut bwu = BandwidthUpgradeNegotiationFrame {
        event_type: Some(event.into()),
        ..Default::default()
    };
    f(&mut bwu);
    v1(V1Frame {
        r#type: Some(v1_frame::FrameType::BandwidthUpgradeNegotiation.into()),
        bandwidth_upgrade_negotiation: Some(bwu),
        ..Default::default()
    })
}

/// Sent, unencrypted, on the old channel right before closing it.
pub(crate) fn disconnection() -> OfflineFrame {
    v1(V1Frame {
        r#type: Some(v1_frame::FrameType::Disconnection.into()),
        disconnection: Some(DisconnectionFrame {
            request_safe_to_disconnect: Some(false),
            ack_safe_to_disconnect: Some(false),
        }),
        ..Default::default()
    })
}

/// A connection over the upgraded medium, and the Wi-Fi network it needs.
#[derive(Debug)]
pub(crate) struct Upgraded {
    pub transport: Transport,
    /// Whether frames on the new channel stay encrypted.
    pub encrypted: bool,
    pub wifi: WifiConnection,
}

/// Joins the network described by `info` and introduces ourselves on it.
pub(crate) async fn connect_upgrade_path(
    info: &UpgradePathInfo,
    endpoint_id: &str,
) -> Result<Upgraded, anyhow::Error> {
    let medium = info.medium();
    let (ssid, password, gateway, port) = match medium {
        Medium::WifiDirect => {
            let c = info
                .wifi_direct_credentials
                .as_ref()
                .ok_or_else(|| anyhow!("no Wi-Fi Direct credentials"))?;
            (c.ssid(), c.password(), c.gateway(), c.port())
        }
        Medium::WifiHotspot => {
            let c = info
                .wifi_hotspot_credentials
                .as_ref()
                .ok_or_else(|| anyhow!("no Wi-Fi hotspot credentials"))?;
            (c.ssid(), c.password(), c.gateway(), c.port())
        }
        other => bail!("unsupported upgrade medium {other:?}"),
    };
    let port = u16::try_from(port)?;

    let wifi = WifiConnection::join(ssid, password).await?;
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, async {
        // The address may take a moment to come up after association.
        loop {
            match TcpStream::connect((gateway, port)).await {
                Ok(stream) => return stream,
                Err(err) => {
                    trace!("bwu: connecting to {gateway}:{port}: {err}");
                    tokio::time::sleep(Duration::from_millis(300)).await;
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow!("couldn't connect to {gateway}:{port}"))?;
    stream.set_nodelay(true)?;
    info!("bwu: connected to {gateway}:{port} over {medium:?}");

    // Android drops encryption on the new channel whenever the path allows
    // it, whatever we answer; say the same.
    let disable_encryption = info.supports_disabling_encryption();
    let introduction = negotiation(EventType::ClientIntroduction, |f| {
        f.client_introduction = Some(ClientIntroduction {
            endpoint_id: Some(endpoint_id.to_owned()),
            supports_disabling_encryption: Some(disable_encryption),
        });
    });
    write_frame(&mut stream, &introduction.encode_to_vec()).await?;

    if info.supports_client_introduction_ack() {
        let ack = tokio::time::timeout(INTRODUCTION_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| anyhow!("no introduction ack"))??;
        let ack = OfflineFrame::decode(&*ack)?;
        let event = ack
            .v1
            .and_then(|v1| v1.bandwidth_upgrade_negotiation)
            .map(|n| n.event_type());
        ensure!(
            event == Some(EventType::ClientIntroductionAck),
            "expected an introduction ack, got {event:?}"
        );
    }

    Ok(Upgraded {
        transport: Transport::new(medium, stream),
        encrypted: !disable_encryption,
        wifi,
    })
}

/// A temporary NetworkManager connection, deleted when dropped (which
/// lets NetworkManager reconnect to the previous network).
#[derive(Debug)]
pub(crate) struct WifiConnection {
    name: String,
}

impl WifiConnection {
    pub async fn join(ssid: &str, password: &str) -> Result<Self, anyhow::Error> {
        let device = wifi_device().await?;
        let name = format!("rqs-upgrade-{}", hex::encode(rand::random::<[u8; 4]>()));
        let user = std::env::var("USER").unwrap_or_default();

        let mut add = vec![
            "connection",
            "add",
            "type",
            "wifi",
            "ifname",
            &device,
            "con-name",
            &name,
            "ssid",
            ssid,
            "wifi-sec.key-mgmt",
            "wpa-psk",
            "wifi-sec.psk",
            password,
            // Probe for the SSID directly instead of waiting for a scan.
            "802-11-wireless.hidden",
            "yes",
            "ipv4.never-default",
            "yes",
            "ipv6.method",
            "ignore",
            "connection.autoconnect",
            "no",
        ];
        let permissions = format!("user:{user}");
        if !user.is_empty() {
            // Owned by us: needs no authorization.
            add.extend(["connection.permissions", &permissions]);
        }
        nmcli(&add).await?;
        let connection = Self { name };

        info!("bwu: joining {ssid:?} on {device}");
        nmcli(&["--wait", "30", "connection", "up", &connection.name]).await?;
        Ok(connection)
    }
}

impl Drop for WifiConnection {
    fn drop(&mut self) {
        info!("bwu: leaving the upgrade network");
        let _ = std::process::Command::new("nmcli")
            .args(["connection", "delete", &self.name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

async fn wifi_device() -> Result<String, anyhow::Error> {
    let out = nmcli(&["-t", "-f", "DEVICE,TYPE", "device"]).await?;
    out.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(_, ty)| *ty == "wifi")
        .map(|(dev, _)| dev.replace("\\:", ":"))
        .ok_or_else(|| anyhow!("no Wi-Fi device"))
}

async fn nmcli(args: &[&str]) -> Result<String, anyhow::Error> {
    let out = tokio::process::Command::new("nmcli")
        .args(args)
        .output()
        .await
        .map_err(|e| anyhow!("running nmcli: {e}"))?;
    if !out.status.success() {
        bail!(
            "nmcli {}: {}",
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
