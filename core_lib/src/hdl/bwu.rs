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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::Transport;
use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::Medium;
use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::upgrade_path_info::WifiHotspotCredentials;
use crate::location_nearby_connections::bandwidth_upgrade_negotiation_frame::{
    ClientIntroduction, ClientIntroductionAck, EventType, UpgradePathInfo,
};
use crate::location_nearby_connections::{
    AvailableChannels, BandwidthUpgradeNegotiationFrame, DisconnectionFrame, MediumMetadata,
    OfflineFrame, V1Frame, WifiDirectCliUsableChannels, WifiHotspotStaUsableChannels,
    offline_frame, v1_frame,
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

/// Aborts a spawned task when dropped.
#[derive(Debug)]
pub(crate) struct TaskGuard(pub JoinHandle<()>);

impl Drop for TaskGuard {
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
    let (ssid, password, gateway, port, frequency) = match medium {
        Medium::WifiDirect => {
            let c = info
                .wifi_direct_credentials
                .as_ref()
                .ok_or_else(|| anyhow!("no Wi-Fi Direct credentials"))?;
            (c.ssid(), c.password(), c.gateway(), c.port(), c.frequency())
        }
        Medium::WifiHotspot => {
            let c = info
                .wifi_hotspot_credentials
                .as_ref()
                .ok_or_else(|| anyhow!("no Wi-Fi hotspot credentials"))?;
            (c.ssid(), c.password(), c.gateway(), c.port(), c.frequency())
        }
        other => bail!("unsupported upgrade medium {other:?}"),
    };
    let port = u16::try_from(port)?;

    let wifi = WifiConnection::join(ssid, password, frequency).await?;
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
    /// Joins a network. `frequency` (MHz, -1 if unknown) narrows the probe
    /// to one channel.
    pub async fn join(ssid: &str, password: &str, frequency: i32) -> Result<Self, anyhow::Error> {
        let device = wifi_device().await?;
        let mut settings = vec![
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
        ];
        let channel = channel_settings(frequency);
        settings.extend(channel.iter().map(String::as_str));

        info!("bwu: joining {ssid:?} ({frequency} MHz) on {device}");
        Self::activate(&device, "rqs-upgrade", &settings).await
    }

    /// Hosts a WPA2 access point that hands out addresses (NetworkManager's
    /// "shared" mode).
    pub async fn host(
        device: &str,
        ssid: &str,
        password: &str,
        frequency: i32,
    ) -> Result<Self, anyhow::Error> {
        let mut settings = vec![
            "ssid",
            ssid,
            "802-11-wireless.mode",
            "ap",
            "wifi-sec.key-mgmt",
            "wpa-psk",
            "wifi-sec.psk",
            password,
            "wifi-sec.proto",
            "rsn",
            "wifi-sec.pairwise",
            "ccmp",
            "wifi-sec.group",
            "ccmp",
            "ipv4.method",
            "shared",
        ];
        let channel = channel_settings(frequency);
        settings.extend(channel.iter().map(String::as_str));

        info!("bwu: hosting {ssid:?} ({frequency} MHz) on {device}");
        Self::activate(device, "rqs-hotspot", &settings).await
    }

    async fn activate(
        device: &str,
        prefix: &str,
        settings: &[&str],
    ) -> Result<Self, anyhow::Error> {
        let name = format!("{prefix}-{}", hex::encode(rand::random::<[u8; 4]>()));
        let user = std::env::var("USER").unwrap_or_default();
        let permissions = format!("user:{user}");

        let mut add = vec![
            "connection",
            "add",
            "type",
            "wifi",
            "ifname",
            device,
            "con-name",
            &name,
            "ipv6.method",
            "ignore",
            "connection.autoconnect",
            "no",
        ];
        if !user.is_empty() {
            // Owned by us: needs no authorization.
            add.extend(["connection.permissions", &permissions]);
        }
        add.extend(settings);
        nmcli(&add).await?;
        let connection = Self { name };

        let started = std::time::Instant::now();
        nmcli(&["--wait", "30", "connection", "up", &connection.name]).await?;
        info!("bwu: {} up after {:?}", connection.name, started.elapsed());
        Ok(connection)
    }
}

/// NetworkManager settings pinning `frequency` (MHz), if it is known.
fn channel_settings(frequency: i32) -> Vec<String> {
    match channel_of(frequency) {
        Some((band, channel)) => vec![
            "802-11-wireless.band".into(),
            band.into(),
            "802-11-wireless.channel".into(),
            channel.to_string(),
        ],
        None => Vec::new(),
    }
}

/// A hotspot we host for the sender to move the connection to.
#[derive(Debug)]
pub(crate) struct Hotspot {
    pub info: UpgradePathInfo,
    listener: TcpListener,
    wifi: WifiConnection,
}

impl Hotspot {
    /// Starts a hotspot on a channel both sides can use, preferring 5 GHz.
    /// `peer` is the medium metadata from the sender's connection request.
    pub async fn start(peer: Option<&MediumMetadata>) -> Result<Self, anyhow::Error> {
        let device = wifi_device().await?;
        let ours = ap_frequencies(&iw_list().await);
        let theirs: Vec<i32> = peer
            .and_then(|m| {
                m.wifi_hotspot_sta_usable_channels
                    .as_ref()
                    .map(|c| &c.channels)
                    .or(m.available_channels.as_ref().map(|c| &c.channels))
            })
            .cloned()
            .unwrap_or_default();
        let peer_5_ghz = peer.is_some_and(|m| m.supports_5_ghz());
        let candidates = hotspot_frequencies(&ours, &theirs, peer_5_ghz);

        let ssid = format!("DIRECT-{}", random_text(8));
        let password = random_text(16);
        let mut last_err = anyhow!("no usable channel");
        let mut hosted = None;
        for frequency in candidates {
            match WifiConnection::host(&device, &ssid, &password, frequency).await {
                Ok(wifi) => {
                    hosted = Some((wifi, frequency));
                    break;
                }
                Err(err) => {
                    warn!("bwu: couldn't host on {frequency} MHz: {err}");
                    last_err = err;
                }
            }
        }
        let (wifi, frequency) = hosted.ok_or(last_err)?;

        let gateway = tokio::time::timeout(CONNECT_TIMEOUT, async {
            loop {
                if let Ok(out) = nmcli(&["-g", "IP4.ADDRESS", "device", "show", &device]).await {
                    if let Some(ip) = out.lines().next().and_then(|l| l.split('/').next()) {
                        if let Ok(ip) = ip.trim().parse::<std::net::Ipv4Addr>() {
                            return ip;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .map_err(|_| anyhow!("hotspot got no address"))?;
        let listener = TcpListener::bind((gateway, 0)).await?;
        let port = listener.local_addr()?.port();
        info!("bwu: hotspot {ssid:?} up, listening on {gateway}:{port}");

        let info = UpgradePathInfo {
            medium: Some(Medium::WifiHotspot.into()),
            wifi_hotspot_credentials: Some(WifiHotspotCredentials {
                ssid: Some(ssid),
                password: Some(password),
                port: Some(port.into()),
                gateway: Some(gateway.to_string()),
                frequency: Some(frequency),
            }),
            supports_disabling_encryption: Some(true),
            supports_client_introduction_ack: Some(true),
            ..Default::default()
        };
        Ok(Self {
            info,
            listener,
            wifi,
        })
    }

    /// Waits for the sender to connect and introduce itself.
    pub async fn accept(self) -> Result<Upgraded, anyhow::Error> {
        let (mut stream, peer) =
            tokio::time::timeout(Duration::from_secs(45), self.listener.accept())
                .await
                .map_err(|_| anyhow!("sender didn't join the hotspot"))??;
        stream.set_nodelay(true)?;
        info!("bwu: {peer} connected over the hotspot");

        let frame = tokio::time::timeout(INTRODUCTION_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| anyhow!("no client introduction"))??;
        let negotiation_frame = OfflineFrame::decode(&*frame)?
            .v1
            .and_then(|v1| v1.bandwidth_upgrade_negotiation)
            .ok_or_else(|| anyhow!("expected a client introduction"))?;
        ensure!(
            negotiation_frame.event_type() == EventType::ClientIntroduction,
            "expected a client introduction, got {:?}",
            negotiation_frame.event_type()
        );
        let introduction = negotiation_frame.client_introduction.unwrap_or_default();
        debug!("bwu: client introduction {introduction:?}");

        let ack = negotiation(EventType::ClientIntroductionAck, |f| {
            f.client_introduction_ack = Some(ClientIntroductionAck {});
        });
        write_frame(&mut stream, &ack.encode_to_vec()).await?;

        Ok(Upgraded {
            transport: Transport::new(Medium::WifiHotspot, stream),
            encrypted: !introduction.supports_disabling_encryption(),
            wifi: self.wifi,
        })
    }
}

/// Channels to try hosting on, best first: 5 GHz ones both sides can use,
/// then 2.4 GHz, then whatever NetworkManager picks (-1).
fn hotspot_frequencies(ours: &[i32], theirs: &[i32], peer_5_ghz: bool) -> Vec<i32> {
    let shared = |f: &i32| theirs.is_empty() || theirs.contains(f);
    let mut candidates: Vec<i32> = Vec::new();
    if peer_5_ghz {
        candidates.extend(ours.iter().filter(|f| **f >= 5000 && shared(f)).take(1));
    }
    candidates.extend(
        ours.iter()
            .filter(|f| **f < 5000 && shared(f))
            .min_by_key(|f| (**f - 2437).abs())
            .copied(),
    );
    candidates.push(-1);
    candidates
}

fn random_text(len: usize) -> String {
    use rand::Rng;
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

async fn iw_list() -> String {
    match tokio::process::Command::new("iw")
        .arg("list")
        .output()
        .await
    {
        Ok(out) => String::from_utf8_lossy(&out.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

/// Frequencies (MHz) we may start transmitting on, i.e. host an AP.
fn ap_frequencies(iw_list: &str) -> Vec<i32> {
    let mut frequencies: Vec<i32> = iw_list
        .lines()
        .filter_map(|l| l.trim().strip_prefix("* "))
        .filter(|l| {
            l.contains(" MHz")
                && !l.contains("disabled")
                && !l.contains("no IR")
                && !l.contains("radar")
        })
        .filter_map(|l| l.split(" MHz").next()?.split('.').next()?.parse().ok())
        .collect();
    frequencies.sort_unstable();
    frequencies.dedup();
    frequencies
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

/// NetworkManager band and channel number for a frequency in MHz.
fn channel_of(frequency: i32) -> Option<(&'static str, i32)> {
    match frequency {
        2484 => Some(("bg", 14)),
        2412..=2472 => Some(("bg", (frequency - 2407) / 5)),
        5160..=5885 => Some(("a", (frequency - 5000) / 5)),
        _ => None,
    }
}

/// What the receiver needs to pick an upgrade network we can join: like
/// Android, the bands we support, the access point we are on (so it can
/// share its channel) and the frequencies we can use. `None` without Wi-Fi.
pub(crate) async fn local_medium_metadata() -> Option<MediumMetadata> {
    let device = wifi_device().await.ok()?;

    let frequencies = usable_frequencies(&iw_list().await);
    let props = nmcli(&[
        "-t",
        "-f",
        "WIFI-PROPERTIES.5GHZ",
        "device",
        "show",
        &device,
    ])
    .await
    .unwrap_or_default();
    let supports_5_ghz =
        props.contains(":yes") || frequencies.iter().any(|f| (5000..5925).contains(f));
    let supports_6_ghz = frequencies.iter().any(|f| *f >= 5925);

    let mut metadata = MediumMetadata {
        supports_5_ghz: Some(supports_5_ghz),
        supports_6_ghz: Some(supports_6_ghz),
        mobile_radio: Some(false),
        ..Default::default()
    };
    let aps = nmcli(&[
        "-t",
        "-f",
        "ACTIVE,BSSID,FREQ",
        "device",
        "wifi",
        "list",
        "ifname",
        &device,
        "--rescan",
        "no",
    ])
    .await
    .unwrap_or_default();
    if let Some((bssid, freq)) = aps.lines().find_map(parse_active_ap) {
        metadata.bssid = Some(bssid);
        metadata.ap_frequency = Some(freq);
    }
    if !frequencies.is_empty() {
        metadata.available_channels = Some(AvailableChannels {
            channels: frequencies.clone(),
        });
        metadata.wifi_direct_cli_usable_channels = Some(WifiDirectCliUsableChannels {
            channels: frequencies.clone(),
        });
        metadata.wifi_hotspot_sta_usable_channels = Some(WifiHotspotStaUsableChannels {
            channels: frequencies,
        });
    }
    Some(metadata)
}

/// Enabled frequencies (MHz) from `iw list`.
fn usable_frequencies(iw_list: &str) -> Vec<i32> {
    let mut frequencies: Vec<i32> = iw_list
        .lines()
        .filter_map(|l| l.trim().strip_prefix("* "))
        .filter(|l| l.contains(" MHz") && !l.contains("disabled"))
        .filter_map(|l| l.split(" MHz").next()?.split('.').next()?.parse().ok())
        .collect();
    frequencies.sort_unstable();
    frequencies.dedup();
    frequencies
}

/// `yes:AA\:BB\:..:5240 MHz` -> (`AA:BB:..`, 5240).
fn parse_active_ap(line: &str) -> Option<(String, i32)> {
    let rest = line.strip_prefix("yes:")?;
    let (bssid, freq) = rest.rsplit_once(':')?;
    let freq = freq.trim_end_matches(" MHz").parse().ok()?;
    Some((bssid.replace("\\:", ":"), freq))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channels() {
        assert_eq!(channel_of(2432), Some(("bg", 5)));
        assert_eq!(channel_of(5240), Some(("a", 48)));
        assert_eq!(channel_of(-1), None);
    }

    #[test]
    fn parses_iw_list() {
        let iw = "\t\t\t* 2412 MHz [1] (22.0 dBm)\n\t\t\t* 2467 MHz [12] (disabled)\n\
                  \t\t\t* 5180.0 MHz [36] (22.0 dBm)\n\t\t\t* MCS: ff\n";
        assert_eq!(usable_frequencies(iw), vec![2412, 5180]);
    }

    #[test]
    fn picks_hotspot_channels() {
        let ours = [2412, 2437, 2462, 5180, 5240, 5745];
        assert_eq!(
            hotspot_frequencies(&ours, &[2437, 5240, 5745], true),
            vec![5240, 2437, -1]
        );
        assert_eq!(hotspot_frequencies(&ours, &[], false), vec![2437, -1]);
        assert_eq!(hotspot_frequencies(&[], &[], true), vec![-1]);
    }

    #[test]
    fn ap_frequencies_skip_no_ir() {
        let iw = "* 2412 MHz [1] (22.0 dBm)\n* 5260 MHz [52] (22.0 dBm) (no IR, radar detection)\n";
        assert_eq!(ap_frequencies(iw), vec![2412]);
    }

    #[test]
    fn parses_active_ap() {
        assert_eq!(
            parse_active_ap("yes:30\\:01\\:AF\\:9E\\:3D\\:2C:5240 MHz"),
            Some(("30:01:AF:9E:3D:2C".into(), 5240))
        );
        assert_eq!(parse_active_ap("no:30\\:01:2412 MHz"), None);
    }
}
