use std::sync::Arc;

use bluer::UuidExt;
use bluer::adv::Advertisement;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const SERVICE_DATA: Bytes = Bytes::from_static(&[
    252, 18, 142, 1, 66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 191, 45, 91, 160, 225, 216, 117, 36, 202, 0,
]);

const INNER_NAME: &str = "BleAdvertiser";

#[derive(Debug, Clone)]
pub struct BleAdvertiser {
    adapter: Arc<bluer::Adapter>,
}

impl BleAdvertiser {
    pub async fn new() -> Result<Self, anyhow::Error> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;

        Ok(Self {
            adapter: Arc::new(adapter),
        })
    }

    pub async fn run(&self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!(
            "{INNER_NAME}: advertising on Bluetooth adapter {} with address {}",
            self.adapter.name(),
            self.adapter.address().await?
        );

        let service_uuid = Uuid::from_u16(0xFE2C);
        let handle = self
            .adapter
            .advertise(self.get_advertisement(service_uuid, SERVICE_DATA))
            .await?;
        ctk.cancelled().await;
        info!("{INNER_NAME}: tracker cancelled, returning");
        drop(handle);

        Ok(())
    }

    fn get_advertisement(&self, service_uuid: Uuid, adv_data: Bytes) -> Advertisement {
        Advertisement {
            advertisement_type: bluer::adv::Type::Broadcast,
            service_data: [(service_uuid, adv_data.into())].into(),
            ..Default::default()
        }
    }
}

// ----------------------------------------------------------------------------
// QuickShare *receiver* discovery over BLE (service UUID 0xFEF3).
//
// Unlike `BleAdvertiser` (which emits the 0xFE2C "I want to send" FastInit
// beacon during the discovery/send phase), this advertises the device as a
// discoverable Nearby Connections *endpoint* so a phone that has dropped off
// Wi-Fi during its browse phase (the Pixel "AirDrop update" behaviour) can
// still list us as a target. Once the user selects us, the phone reconnects to
// Wi-Fi and the transfer completes over the normal Wi-Fi-LAN (mDNS + TCP) path,
// which is why the advertised endpoint_id MUST match the one used by MDnsServer.
//
// The byte layout was reverse-engineered from a live capture of a Pixel 9 Pro
// advertising in "Everyone" mode. The identity/MAC/trailing-presence segments
// are reused verbatim from that capture (they are not validated for discovery);
// only the endpoint_id, device name and the length fields vary.
const RX_INNER_NAME: &str = "ReceiverAdvertiser";
const QS_SERVICE_UUID: u16 = 0xFEF3;
// 3-byte hash of the "NearbySharing" service id (matches the mDNS _FC9F5ED42C8A type).
const QS_SVC_HASH: [u8; 3] = [0xfc, 0x9f, 0x5e];
// endpoint_info identity bytes (2-byte salt + 14-byte metadata-key hash).
const QS_EINFO_IDENTITY: [u8; 16] = [
    0x4a, 0x22, 0x71, 0x16, 0x9c, 0x15, 0x99, 0xa2, 0x44, 0xaf, 0x44, 0xb0, 0x17, 0x9c, 0x0f, 0x23,
];
// Connections advertisement trailer after endpoint_info: bluetooth MAC(6) + extra(2).
// The MAC is left all-zero ("not set"): a set MAC makes the phone also register us
// as a Bluetooth Classic endpoint and, since Nearby tries BLUETOOTH before BLE,
// page that address first. We have no Classic socket (and the MAC copied from the
// Pixel capture isn't ours), so that cost a 5-10 s page timeout on every send.
const QS_CONN_MAC_EXTRA: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
// Mediums advertisement trailer: device_token(2) only. The Pixel capture also had
// an extra-fields mask (0x03) advertising an L2CAP PSM (0x0082) and 63 bytes of
// rx instant-connection data; we implement neither (only the GATT weave socket),
// so advertising them could make a phone try a transport we can't serve.
const QS_MEDIUMS_TRAILING: [u8; 2] = [0x62, 0xf1];

/// Build the 0xFEF3 service data advertising this device as a QuickShare
/// receiver endpoint. `endpoint_id` must be the same 4 bytes used by MDnsServer.
pub fn receiver_service_data(endpoint_id: [u8; 4], device_type: u8, device_name: &str) -> Vec<u8> {
    // Inner Nearby Share application advertisement (== the mDNS "n" TXT record):
    //   1B header: version(3b)=1 | visibility(1b)=0(visible) | device_type(3b) | reserved
    //   16B identity (2B salt + 14B metadata-key hash)
    //   1B name length + UTF-8 name (plaintext, since we're visible to "Everyone")
    let mut einfo: Vec<u8> = Vec::new();
    einfo.push((1 << 5) | ((device_type & 0x7) << 1));
    einfo.extend_from_slice(&QS_EINFO_IDENTITY);
    let mut name = device_name.as_bytes().to_vec();
    name.truncate(255);
    einfo.push(name.len() as u8);
    einfo.extend_from_slice(&name);

    // Nearby Connections offline BLE advertisement carrying the endpoint id + info.
    let mut data: Vec<u8> = Vec::new();
    data.push(0x23); // version(3b)=1 | pcp(5b)
    data.extend_from_slice(&QS_SVC_HASH);
    data.extend_from_slice(&endpoint_id);
    data.push(einfo.len() as u8);
    data.extend_from_slice(&einfo);
    data.extend_from_slice(&QS_CONN_MAC_EXTRA);

    // Mediums BLE advertisement wrapper (+ appended presence data elements).
    let mut sd: Vec<u8> = Vec::new();
    sd.push(0x48); // version(3b)=2 | socket_version(3b)=2 | fast(1b)=0 | reserved
    sd.extend_from_slice(&QS_SVC_HASH);
    sd.extend_from_slice(&(data.len() as u32).to_be_bytes());
    sd.extend_from_slice(&data);
    sd.extend_from_slice(&QS_MEDIUMS_TRAILING);
    sd
}

#[derive(Debug, Clone)]
pub struct ReceiverAdvertiser {
    adapter: Arc<bluer::Adapter>,
    service_data: Vec<u8>,
}

impl ReceiverAdvertiser {
    pub async fn new(
        endpoint_id: [u8; 4],
        device_type: u8,
        device_name: &str,
    ) -> Result<Self, anyhow::Error> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;

        Ok(Self {
            adapter: Arc::new(adapter),
            service_data: receiver_service_data(endpoint_id, device_type, device_name),
        })
    }

    pub async fn run(&self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!(
            "{RX_INNER_NAME}: advertising QuickShare receiver (0x{QS_SERVICE_UUID:04X}, {} bytes) on adapter {} ({})",
            self.service_data.len(),
            self.adapter.name(),
            self.adapter.address().await?
        );

        let uuid = Uuid::from_u16(QS_SERVICE_UUID);
        // A connectable advertising set is consumed when a phone connects, so
        // re-register periodically to stay discoverable for further transfers.
        loop {
            let adv = Advertisement {
                // Connectable, matching how the phone advertises as a receiver.
                advertisement_type: bluer::adv::Type::Peripheral,
                service_data: [(uuid, self.service_data.clone())].into(),
                discoverable: Some(true),
                // Advertise fast so the phone discovers and connects quickly
                // (BlueZ defaults to a slow ~1-2s interval).
                min_interval: Some(std::time::Duration::from_millis(100)),
                max_interval: Some(std::time::Duration::from_millis(150)),
                // The service data (~45 bytes + device name) only fits an extended (non-legacy)
                // advertising PDU; without a secondary channel the kernel uses a
                // legacy PDU (31-byte limit) and rejects the set with
                // "Invalid Parameters" (seen on an Intel controller, BlueZ 5.72).
                secondary_channel: Some(bluer::adv::SecondaryChannel::OneM),
                ..Default::default()
            };
            match self.adapter.advertise(adv).await {
                Ok(handle) => {
                    debug!("{RX_INNER_NAME}: advertisement registered");
                    tokio::select! {
                        _ = ctk.cancelled() => {
                            drop(handle);
                            info!("{RX_INNER_NAME}: tracker cancelled, returning");
                            return Ok(());
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(30)) => {
                            drop(handle);
                        }
                    }
                }
                Err(e) => {
                    warn!("{RX_INNER_NAME}: advertise failed ({e}); retrying");
                    tokio::select! {
                        _ = ctk.cancelled() => return Ok(()),
                        _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {}
                    }
                }
            }
        }
    }
}
