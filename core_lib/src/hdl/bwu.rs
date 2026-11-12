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

use super::{Transport, nm};
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
    /// Takes the connection down when dropped.
    _activation: nm::Activation,
    /// Whether we host the network (an access point).
    #[cfg_attr(
        not(all(feature = "experimental", target_os = "linux")),
        allow(dead_code)
    )]
    host: bool,
}

impl WifiConnection {
    /// Joins a network. `frequency` (MHz, -1 if unknown) narrows the probe
    /// to one channel.
    pub async fn join(ssid: &str, password: &str, frequency: i32) -> Result<Self, anyhow::Error> {
        let device = nm::wifi_device().await?;
        info!(
            "bwu: joining {ssid:?} ({frequency} MHz) on {}",
            device.interface
        );
        Self::activate(
            &device,
            nm::UPGRADE_PREFIX,
            ssid,
            password,
            false,
            frequency,
        )
        .await
    }

    /// Hosts a WPA2 access point that hands out addresses (NetworkManager's
    /// "shared" mode).
    pub async fn host(
        device: &nm::WifiDevice,
        ssid: &str,
        password: &str,
        frequency: i32,
    ) -> Result<Self, anyhow::Error> {
        info!(
            "bwu: hosting {ssid:?} ({frequency} MHz) on {}",
            device.interface
        );
        Self::activate(device, nm::HOTSPOT_PREFIX, ssid, password, true, frequency).await
    }

    async fn activate(
        device: &nm::WifiDevice,
        prefix: &str,
        ssid: &str,
        password: &str,
        host: bool,
        frequency: i32,
    ) -> Result<Self, anyhow::Error> {
        let name = format!("{prefix}{}", hex::encode(rand::random::<[u8; 4]>()));
        let profile = nm::WifiProfile {
            name: name.clone(),
            ssid: ssid.to_owned(),
            password: password.to_owned(),
            host,
            channel: channel_of(frequency),
        };
        let started = std::time::Instant::now();
        let activation = nm::activate(device, profile).await?;
        info!("bwu: {name} up after {:?}", started.elapsed());
        Ok(Self {
            _activation: activation,
            host,
        })
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
        let device = nm::wifi_device().await?;
        ensure!(
            device.capabilities & nm::CAP_AP != 0,
            "{} can't host an access point",
            device.interface
        );
        let mut ours = ap_frequencies(&iw_list().await);
        if ours.is_empty() {
            ours = fallback_frequencies(device.capabilities);
        }
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
                if let Some(ip) = nm::ipv4_address(&device).await {
                    return ip;
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
        // Dropping the activation afterwards takes the network down.
        info!("bwu: leaving the upgrade network");
        #[cfg(all(feature = "experimental", target_os = "linux"))]
        if self.host {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async {
                    // Let NetworkManager take the access point down first.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    if let Err(err) = super::bluetooth::revive_scanning().await {
                        warn!("bwu: checking Bluetooth scanning: {err}");
                    }
                });
            }
        }
    }
}

/// NetworkManager band and channel number for a frequency in MHz.
fn channel_of(frequency: i32) -> Option<(&'static str, u32)> {
    let channel = |base: i32| u32::try_from((frequency - base) / 5).ok();
    match frequency {
        2484 => Some(("bg", 14)),
        2412..=2472 => Some(("bg", channel(2407)?)),
        5160..=5885 => Some(("a", channel(5000)?)),
        _ => None,
    }
}

/// Frequencies (MHz) to assume when `iw` can't tell us (it's missing, or
/// we're in a sandbox): 2.4 GHz channels 1-11 and, if supported, the 5 GHz
/// channels most countries allow without radar detection (36-48, 149-165).
fn fallback_frequencies(capabilities: u32) -> Vec<i32> {
    let mut frequencies: Vec<i32> = (2412..=2462).step_by(5).collect();
    if capabilities & nm::CAP_FREQ_5GHZ != 0 {
        frequencies.extend([5180, 5200, 5220, 5240, 5745, 5765, 5785, 5805, 5825]);
    }
    frequencies
}

/// What the receiver needs to pick an upgrade network we can join: like
/// Android, the bands we support, the access point we are on (so it can
/// share its channel) and the frequencies we can use. `None` without Wi-Fi.
pub(crate) async fn local_medium_metadata() -> Option<MediumMetadata> {
    let device = nm::wifi_device().await.ok()?;

    let mut frequencies = usable_frequencies(&iw_list().await);
    if frequencies.is_empty() {
        frequencies = fallback_frequencies(device.capabilities);
    }
    let supports_5_ghz = device.capabilities & nm::CAP_FREQ_5GHZ != 0
        || frequencies.iter().any(|f| (5000..5925).contains(f));
    let supports_6_ghz = frequencies.iter().any(|f| *f >= 5925);

    let mut metadata = MediumMetadata {
        supports_5_ghz: Some(supports_5_ghz),
        supports_6_ghz: Some(supports_6_ghz),
        mobile_radio: Some(false),
        ..Default::default()
    };
    if let Some((bssid, frequency)) = nm::active_access_point(&device).await {
        metadata.bssid = Some(bssid);
        metadata.ap_frequency = Some(frequency);
    }
    metadata.available_channels = Some(AvailableChannels {
        channels: frequencies.clone(),
    });
    metadata.wifi_direct_cli_usable_channels = Some(WifiDirectCliUsableChannels {
        channels: frequencies.clone(),
    });
    metadata.wifi_hotspot_sta_usable_channels = Some(WifiHotspotStaUsableChannels {
        channels: frequencies,
    });
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
    fn fallback_frequencies_follow_capabilities() {
        assert_eq!(fallback_frequencies(0).len(), 11);
        assert!(fallback_frequencies(nm::CAP_FREQ_5GHZ).contains(&5180));
    }
}

#[cfg(test)]
mod nm_smoke {
    /// Talks to the real NetworkManager; run with `--ignored`.
    #[test]
    #[ignore]
    fn reads_wifi_device_and_hosts() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let device = super::nm::wifi_device().await.unwrap();
            println!("device {device:?}");
            println!("metadata {:?}", super::local_medium_metadata().await);
            let wifi =
                super::WifiConnection::host(&device, "DIRECT-rqs-smoke", "smoketest1234", 5180)
                    .await
                    .unwrap();
            println!(
                "hosting {wifi:?}, gateway {:?}",
                super::nm::ipv4_address(&device).await
            );
            let hold = std::env::var("RQS_SMOKE_HOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            tokio::time::sleep(std::time::Duration::from_secs(hold)).await;
            drop(wifi);
            // Give the Bluetooth scan check a chance to run.
            tokio::time::sleep(std::time::Duration::from_secs(12)).await;
            println!("done");
        });
    }
}
