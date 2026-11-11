//! Discovers Quick Share receivers over BLE, without a shared Wi-Fi LAN.
//!
//! Receivers only advertise after hearing a sender's 0xFE2C "someone is
//! sharing" beacon (sent by [`BleAdvertiser`](super::BleAdvertiser) during
//! discovery). A receiver that is visible to everyone then publishes a
//! Nearby Connections header under 0xFEF3, and the full advertisement, which
//! includes its Bluetooth Classic address, as a GATT characteristic. That
//! address is what [`bluetooth::connect`](super::bluetooth::connect) needs.
//!
//! Fast advertisements (hidden / contacts-only receivers) carry no address
//! and are ignored.

pub(crate) mod adv;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use bluer::{Adapter, AdapterEvent, Address, DiscoveryFilter, DiscoveryTransport, Session, Uuid};
use futures::StreamExt;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use self::adv::{NearbyAdvertisement, ServiceData};
use super::EndpointInfo;
use super::bluetooth::SERVICE_ID;
use crate::utils::parse_endpoint_info;

const INNER_NAME: &str = "BleDiscovery";

/// 16-bit service UUID Nearby Connections advertises under.
const NEARBY_SERVICE_UUID: Uuid = Uuid::from_u128(0x0000fef3_0000_1000_8000_00805f9b34fb);
/// GATT characteristic holding advertisement slot 0
/// (`GenerateAdvertisementUuid(0)` in google/nearby).
const ADVERTISEMENT_SLOT_0: Uuid = Uuid::from_u128(0x00000000_0000_3000_8000_000000000000);

const GATT_TIMEOUT: Duration = Duration::from_secs(20);
/// Don't hammer a device whose advertisement could not be read.
const GATT_RETRY_AFTER: Duration = Duration::from_secs(15);
/// Visible receivers re-advertise every few seconds; forget silent ones.
const STALE_AFTER: Duration = Duration::from_secs(30);
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

struct Known {
    info: EndpointInfo,
    last_seen: Instant,
}

pub struct BleDiscovery {
    // Keeps the D-Bus connection alive.
    _session: Session,
    adapter: Adapter,
    sender: broadcast::Sender<EndpointInfo>,
}

impl BleDiscovery {
    pub async fn new(sender: broadcast::Sender<EndpointInfo>) -> Result<Self, anyhow::Error> {
        let session = Session::new().await?;
        let adapter = session.default_adapter().await?;

        Ok(Self {
            _session: session,
            adapter,
            sender,
        })
    }

    pub async fn run(self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");

        self.adapter
            .set_discovery_filter(DiscoveryFilter {
                transport: DiscoveryTransport::Le,
                // Repeated advertisements keep `last_seen` fresh.
                duplicate_data: true,
                ..Default::default()
            })
            .await?;
        let mut events = self.adapter.discover_devices_with_changes().await?;

        // Advertisement hash -> Bluetooth address it resolved to.
        let mut resolved: HashMap<[u8; 4], String> = HashMap::new();
        let mut failed: HashMap<[u8; 4], Instant> = HashMap::new();
        let mut endpoints: HashMap<String, Known> = HashMap::new();
        // Last 0xFEF3 payload per advertiser, to trace only changes.
        let mut last_payload: HashMap<Address, Vec<u8>> = HashMap::new();
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);

        loop {
            let addr = tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                _ = sweep.tick() => {
                    self.forget_stale(&mut endpoints);
                    continue;
                }
                ev = events.next() => match ev {
                    Some(AdapterEvent::DeviceAdded(addr)) => addr,
                    Some(_) => continue,
                    None => bail!("discovery stream ended"),
                },
            };

            let Some(data) = self.nearby_service_data(addr).await else {
                continue;
            };
            let parsed = adv::parse_service_data(&data, SERVICE_ID);
            if last_payload.get(&addr) != Some(&data) {
                trace!(
                    "{INNER_NAME}: {addr} 0xFEF3 {}: {parsed:?}",
                    hex::encode(&data)
                );
                last_payload.insert(addr, data.clone());
            }

            let (adv, adv_hash) = match parsed {
                Ok(ServiceData::Regular(adv)) => (adv, None),
                Ok(ServiceData::Header { adv_hash }) => {
                    if let Some(known) = resolved.get(&adv_hash).and_then(|a| endpoints.get_mut(a))
                    {
                        known.last_seen = Instant::now();
                        continue;
                    }
                    if failed
                        .get(&adv_hash)
                        .is_some_and(|t| t.elapsed() < GATT_RETRY_AFTER)
                    {
                        continue;
                    }

                    debug!("{INNER_NAME}: {addr} publishes a Nearby header, reading it over GATT");
                    let read = tokio::select! {
                        _ = ctk.cancelled() => break,
                        r = self.read_advertisement(addr) => r,
                    };
                    match read {
                        Ok(adv) => (adv, Some(adv_hash)),
                        Err(err) => {
                            debug!("{INNER_NAME}: reading advertisement from {addr}: {err}");
                            failed.insert(adv_hash, Instant::now());
                            continue;
                        }
                    }
                }
                // No Bluetooth address to connect to.
                Ok(ServiceData::Fast(_)) | Err(_) => continue,
            };

            if let Some(bt_addr) = self.update(&mut endpoints, adv) {
                if let Some(hash) = adv_hash {
                    resolved.insert(hash, bt_addr);
                }
            }
        }

        Ok(())
    }

    async fn nearby_service_data(&self, addr: Address) -> Option<Vec<u8>> {
        let device = self.adapter.device(addr).ok()?;
        device
            .service_data()
            .await
            .ok()??
            .remove(&NEARBY_SERVICE_UUID)
    }

    /// Reads the full advertisement from the device's GATT server.
    async fn read_advertisement(
        &self,
        addr: Address,
    ) -> Result<NearbyAdvertisement, anyhow::Error> {
        let device = self.adapter.device(addr)?;

        let started = Instant::now();
        let result = tokio::time::timeout(GATT_TIMEOUT, async {
            if !device.is_connected().await? {
                device.connect().await?;
            }
            trace!(
                "{INNER_NAME}: {addr} connected after {:?}",
                started.elapsed()
            );
            while !device.is_services_resolved().await? {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            trace!(
                "{INNER_NAME}: {addr} services resolved after {:?}",
                started.elapsed()
            );

            for service in device.services().await? {
                if service.uuid().await? != NEARBY_SERVICE_UUID {
                    continue;
                }
                for characteristic in service.characteristics().await? {
                    if characteristic.uuid().await? == ADVERTISEMENT_SLOT_0 {
                        let value = characteristic.read().await?;
                        trace!(
                            "{INNER_NAME}: {addr} advertisement read after {:?}",
                            started.elapsed()
                        );
                        return adv::parse_regular(&value, SERVICE_ID);
                    }
                }
            }
            bail!("no Nearby advertisement characteristic")
        })
        .await;

        // Disconnecting takes seconds; don't hold up discovery for it.
        tokio::spawn(async move {
            let _ = device.disconnect().await;
        });
        result.map_err(|_| anyhow!("GATT read timed out"))?
    }

    /// Records a reachable endpoint and announces it if it is new or changed.
    /// Returns its Bluetooth address.
    fn update(
        &self,
        endpoints: &mut HashMap<String, Known>,
        adv: NearbyAdvertisement,
    ) -> Option<String> {
        let bt_addr = Address::new(adv.bluetooth_address?).to_string();
        let (device_type, name) = parse_endpoint_info(&adv.endpoint_info).ok()?;

        let info = EndpointInfo {
            fullname: adv.endpoint_id,
            id: bt_addr.clone(),
            name,
            ip: None,
            port: None,
            rtype: Some(device_type),
            present: Some(true),
            bluetooth_address: Some(bt_addr.clone()),
        };

        let changed = endpoints
            .get(&bt_addr)
            .is_none_or(|k| k.info.name != info.name || k.info.rtype != info.rtype);
        if changed {
            info!("{INNER_NAME}: found {:?} ({bt_addr})", info.name);
            let _ = self.sender.send(info.clone());
        }
        endpoints.insert(
            bt_addr.clone(),
            Known {
                info,
                last_seen: Instant::now(),
            },
        );

        Some(bt_addr)
    }

    fn forget_stale(&self, endpoints: &mut HashMap<String, Known>) {
        endpoints.retain(|id, known| {
            if known.last_seen.elapsed() < STALE_AFTER {
                return true;
            }
            info!("{INNER_NAME}: lost {:?} ({id})", known.info.name);
            let _ = self.sender.send(EndpointInfo {
                id: id.clone(),
                ..Default::default()
            });
            false
        });
    }
}
