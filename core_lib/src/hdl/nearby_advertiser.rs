//! Makes this device discoverable and reachable over Bluetooth by Quick Share
//! senders that are not on the same LAN.
//!
//! While visible, it:
//! - serves a Nearby Connections *regular* advertisement, carrying our
//!   endpoint id, endpoint info (with the device name) and our Bluetooth
//!   Classic address, from a GATT server. It is too long for a legacy
//!   advertisement, and BlueZ/the kernel cap advertising data at 31 bytes
//!   even on BLE 5 adapters, so like Android without extended advertising
//!   we advertise a 17-byte header under 0xFEF3 that tells scanners to read
//!   the rest over GATT;
//! - keeps the adapter discoverable. BlueZ otherwise only page-scans for
//!   bonded devices, so an unpaired phone could not open the RFCOMM
//!   connection to [`BluetoothServer`](super::bluetooth::BluetoothServer).
//!   The previous discoverable settings are restored when hidden again.

use std::sync::RwLock;
use std::time::Duration;

use bluer::adv::{Advertisement, AdvertisementHandle, Type};
use bluer::gatt::local::{
    Application, ApplicationHandle, Characteristic, CharacteristicRead, Service,
};
use bluer::{Adapter, Session};
use futures::FutureExt;
use rand::Rng;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::Visibility;
use super::ble_discovery::adv;
use super::bluetooth::SERVICE_ID;
use crate::DeviceType;
use crate::utils::gen_endpoint_info;

const INNER_NAME: &str = "NearbyAdvertiser";

const NEARBY_SERVICE_UUID: bluer::Uuid =
    bluer::Uuid::from_u128(0x0000fef3_0000_1000_8000_00805f9b34fb);
/// GATT characteristic of advertisement slot 0 (`GenerateAdvertisementUuid(0)`).
const ADVERTISEMENT_SLOT_0: bluer::Uuid =
    bluer::Uuid::from_u128(0x00000000_0000_3000_8000_000000000000);

/// Adapter settings to put back when we stop being visible.
struct SavedDiscoverable {
    discoverable: bool,
    timeout: u32,
}

/// Something that is active only while we are visible.
struct Active {
    // Dropping these unregisters them.
    advertisement: AdvertisementHandle,
    gatt: ApplicationHandle,
    saved: Option<SavedDiscoverable>,
}

pub struct NearbyAdvertiser {
    _session: Session,
    adapter: Adapter,
    endpoint_id: [u8; 4],
    device_name: &'static RwLock<String>,
    visibility: watch::Receiver<Visibility>,
}

impl NearbyAdvertiser {
    pub(crate) async fn new(
        endpoint_id: [u8; 4],
        device_name: &'static RwLock<String>,
        visibility: watch::Receiver<Visibility>,
    ) -> Result<Self, anyhow::Error> {
        let session = Session::new().await?;
        let adapter = session.default_adapter().await?;

        Ok(Self {
            _session: session,
            adapter,
            endpoint_id,
            device_name,
            visibility,
        })
    }

    pub async fn run(mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");
        let mut active: Option<Active> = None;

        loop {
            let visible = *self.visibility.borrow_and_update() != Visibility::Invisible;
            match (visible, active.is_some()) {
                (true, false) => match self.start().await {
                    Ok(a) => active = Some(a),
                    Err(err) => warn!("{INNER_NAME}: couldn't advertise: {err}"),
                },
                (false, true) => self.stop(active.take()).await,
                _ => {}
            }

            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                r = self.visibility.changed() => {
                    if r.is_err() {
                        break;
                    }
                }
            }
        }

        self.stop(active.take()).await;
        Ok(())
    }

    async fn start(&self) -> Result<Active, anyhow::Error> {
        let name = self.device_name.read().unwrap().clone();
        let info = gen_endpoint_info(DeviceType::Laptop as u8, &name);
        let address = self.adapter.address().await?;
        let data = adv::build_regular(
            SERVICE_ID,
            self.endpoint_id,
            &info,
            address.0,
            rand::rng().random(),
        )?;

        // Must come first: turning discoverability on while an LE
        // advertisement is registered leaves the change pending forever
        // (BlueZ 5.64 / Linux 6.1), and every later one fails with Busy.
        let saved = match self.make_connectable().await {
            Ok(saved) => saved,
            Err(err) => {
                warn!("{INNER_NAME}: couldn't make the adapter discoverable: {err}");
                None
            }
        };

        let served = async {
            let gatt = self
                .adapter
                .serve_gatt_application(advertisement_server(data.clone()))
                .await?;
            let advertisement = self
                .adapter
                .advertise(Advertisement {
                    // Connectable, so scanners can read the GATT characteristic.
                    advertisement_type: Type::Peripheral,
                    service_data: [(
                        NEARBY_SERVICE_UUID,
                        adv::build_header(SERVICE_ID, &data).into_bytes(),
                    )]
                    .into(),
                    ..Default::default()
                })
                .await?;
            Ok::<_, bluer::Error>((gatt, advertisement))
        };
        let (gatt, advertisement) = match served.await {
            Ok(v) => v,
            Err(err) => {
                if let Some(saved) = saved {
                    let _ = self.restore(saved).await;
                }
                return Err(err.into());
            }
        };

        info!("{INNER_NAME}: advertising {name:?} on {address}");
        Ok(Active {
            advertisement,
            gatt,
            saved,
        })
    }

    /// Turns on discoverability (and with it page scan) indefinitely.
    /// Returns the settings to restore, or `None` if it was already on.
    async fn make_connectable(&self) -> Result<Option<SavedDiscoverable>, anyhow::Error> {
        if self.adapter.is_discoverable().await? {
            return Ok(None);
        }
        let saved = SavedDiscoverable {
            discoverable: false,
            timeout: self.adapter.discoverable_timeout().await?,
        };
        self.adapter.set_discoverable_timeout(0).await?;
        self.adapter.set_discoverable(true).await?;
        Ok(Some(saved))
    }

    async fn restore(&self, saved: SavedDiscoverable) -> Result<(), anyhow::Error> {
        self.adapter.set_discoverable(saved.discoverable).await?;
        self.adapter.set_discoverable_timeout(saved.timeout).await?;
        Ok(())
    }

    async fn stop(&self, active: Option<Active>) {
        let Some(active) = active else { return };
        let before = self.adapter.active_advertising_instances().await;
        drop(active.advertisement);
        drop(active.gatt);

        if let Some(saved) = active.saved {
            // Same BlueZ issue as in `start`: wait for the advertisement to
            // be gone before touching discoverability.
            if let Ok(before) = before {
                for _ in 0..20 {
                    match self.adapter.active_advertising_instances().await {
                        Ok(n) if n < before => break,
                        _ => tokio::time::sleep(Duration::from_millis(100)).await,
                    }
                }
            }
            if let Err(err) = self.restore(saved).await {
                warn!("{INNER_NAME}: couldn't restore discoverability: {err}");
            }
        }
        info!("{INNER_NAME}: stopped advertising");
    }
}

/// GATT service 0xFEF3 with the full advertisement in slot 0.
fn advertisement_server(advertisement: Vec<u8>) -> Application {
    let read = move |req: bluer::gatt::local::CharacteristicReadRequest| {
        let value = advertisement
            .get(usize::from(req.offset)..)
            .unwrap_or_default()
            .to_vec();
        trace!(
            "{INNER_NAME}: {} read the advertisement",
            req.device_address
        );
        async move { Ok(value) }.boxed()
    };
    Application {
        services: vec![Service {
            uuid: NEARBY_SERVICE_UUID,
            primary: true,
            characteristics: vec![Characteristic {
                uuid: ADVERTISEMENT_SLOT_0,
                read: Some(CharacteristicRead {
                    read: true,
                    fun: Box::new(read),
                    ..Default::default()
                }),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    }
}
