#[macro_use]
extern crate log;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use anyhow::anyhow;
use channel::ChannelMessage;
#[cfg(all(feature = "experimental", target_os = "linux"))]
use hdl::BleAdvertiser;
use hdl::MDnsDiscovery;
use once_cell::sync::Lazy;
use rand::Rng;
use rand::distr::Alphanumeric;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

#[cfg(feature = "experimental")]
use crate::hdl::BleListener;
use crate::hdl::MDnsServer;
use crate::manager::TcpServer;

pub mod channel;
pub mod errors;
pub mod hdl;
pub mod manager;
pub mod utils;

pub use hdl::{EndpointInfo, OutboundPayload, TextPayloadType, TransferState, Visibility};
pub use manager::SendInfo;
pub use utils::DeviceType;

pub mod sharing_nearby {
    include!(concat!(env!("OUT_DIR"), "/sharing.nearby.rs"));
}

pub mod securemessage {
    include!(concat!(env!("OUT_DIR"), "/securemessage.rs"));
}

pub mod securegcm {
    include!(concat!(env!("OUT_DIR"), "/securegcm.rs"));
}

pub mod location_nearby_connections {
    include!(concat!(env!("OUT_DIR"), "/location.nearby.connections.rs"));
}

static CUSTOM_DOWNLOAD: Lazy<RwLock<Option<PathBuf>>> = Lazy::new(|| RwLock::new(None));
static DEVICE_NAME: Lazy<RwLock<String>> =
    Lazy::new(|| RwLock::new(sys_metrics::host::get_hostname().unwrap_or("Unknown device".into())));

#[derive(Debug)]
pub struct RQS {
    tracker: Option<TaskTracker>,
    ctoken: Option<CancellationToken>,
    // Discovery token is different than ctoken because he is on his own
    // - can be cancelled while the ctoken is still active
    discovery_ctk: Option<CancellationToken>,

    // Used to trigger a change in the mDNS visibility (and later on, BLE)
    pub visibility_sender: Arc<Mutex<watch::Sender<Visibility>>>,
    visibility_receiver: watch::Receiver<Visibility>,

    // Only used to send the info "a nearby device is sharing"
    ble_sender: broadcast::Sender<()>,

    pub port_number: Option<u32>,

    pub message_sender: broadcast::Sender<ChannelMessage>,
}

impl Default for RQS {
    fn default() -> Self {
        Self::new(
            Visibility::Visible,
            None,
            None,
            Some(sys_metrics::host::get_hostname().unwrap_or("Unknown device".into())),
        )
    }
}

impl RQS {
    pub fn new(
        visibility: Visibility,
        port_number: Option<u32>,
        download_path: Option<PathBuf>,
        device_name: Option<String>,
    ) -> Self {
        {
            let mut guard = CUSTOM_DOWNLOAD.write().unwrap();
            *guard = download_path;
        }
        {
            let mut guard = DEVICE_NAME.write().unwrap();
            if let Some(device_name) = device_name {
                *guard = device_name.clone();
            }
        }

        let (message_sender, _) = broadcast::channel(50);
        let (ble_sender, _) = broadcast::channel(5);

        // Define default visibility as per the args inside the new()
        let (visibility_sender, visibility_receiver) = watch::channel(Visibility::Invisible);
        let _ = visibility_sender.send(visibility);

        Self {
            tracker: None,
            ctoken: None,
            discovery_ctk: None,
            visibility_sender: Arc::new(Mutex::new(visibility_sender)),
            visibility_receiver,
            ble_sender,
            port_number,
            message_sender,
        }
    }

    pub async fn run(
        &mut self,
    ) -> Result<(mpsc::Sender<SendInfo>, broadcast::Receiver<()>), anyhow::Error> {
        let tracker = TaskTracker::new();
        let ctoken = CancellationToken::new();
        self.tracker = Some(tracker.clone());
        self.ctoken = Some(ctoken.clone());

        let endpoint_id: Vec<u8> = rand::rng()
            .sample_iter(Alphanumeric)
            .take(4)
            .map(u8::from)
            .collect();
        let tcp_listener =
            TcpListener::bind(format!("0.0.0.0:{}", self.port_number.unwrap_or(0))).await?;
        let binded_addr = tcp_listener.local_addr()?;
        info!("TcpListener on: {}", binded_addr);

        // So the random port can be accessed from the user if needed.
        // This does have a difference in behaviour however when port_number is Some.
        // .stop() and .run() will reuse the port number instead of generating a new one.
        self.port_number = Some(binded_addr.port() as u32);

        // MPSC for the TcpServer
        let send_channel = mpsc::channel(10);
        // Start TcpServer in own "task"
        let mut server = TcpServer::new(
            endpoint_id[..4].try_into()?,
            tcp_listener,
            self.message_sender.clone(),
            send_channel.1,
        )?;
        let ctk = ctoken.clone();
        tracker.spawn(async move { server.run(ctk).await });

        #[cfg(feature = "experimental")]
        {
            if let Ok(ble) = BleListener::new(self.ble_sender.clone())
                .await
                .inspect_err(|err| warn!("BleListener: {}", err))
            {
                let ctk = ctoken.clone();
                tracker.spawn(async move { ble.run(ctk).await });
            }
        }

        // Start MDnsServer in own "task"
        let mut mdns = MDnsServer::new(
            endpoint_id[..4].try_into()?,
            binded_addr.port(),
            self.ble_sender.subscribe(),
            self.visibility_sender.clone(),
            self.visibility_receiver.clone(),
        )?;
        let ctk = ctoken.clone();
        tracker.spawn(async move { mdns.run(ctk).await });

        // Advertise as a discoverable QuickShare receiver over BLE (0xFEF3) so a
        // phone that drops off Wi-Fi during its browse phase (the Pixel "AirDrop
        // update" behaviour) can still list us as a target. Uses the SAME
        // endpoint_id as mDNS, so once selected the phone reconnects to Wi-Fi and
        // completes the transfer over the normal Wi-Fi-LAN (mDNS + TCP) path.
        // The advertisement follows the visibility setting (hidden => not
        // discoverable over BLE either); the GATT server stays registered.
        #[cfg(all(feature = "experimental", target_os = "linux"))]
        {
            let rx_endpoint_id: [u8; 4] = endpoint_id[..4].try_into()?;
            let rx_device_name = DEVICE_NAME.read().unwrap().clone();
            // Same advertisement bytes are used for the BLE advert and served
            // over GATT slot 0, so the phone reads a consistent endpoint.
            let advert = crate::hdl::receiver_service_data(
                rx_endpoint_id,
                crate::utils::DeviceType::Laptop as u8,
                &rx_device_name,
            );

            // GATT server: when the phone selects us it opens a GATT connection,
            // reads slot 0 for our advertisement, then drives the weave data
            // socket which we bridge to the inbound handshake.
            let gatt_advert = advert.clone();
            let gatt_sender = self.message_sender.clone();
            let gatt_tcp_port = binded_addr.port();
            let gctk = ctoken.clone();
            tracker.spawn(async move {
                match crate::hdl::ReceiverGattServer::new(gatt_advert, gatt_sender, gatt_tcp_port).await {
                    Ok(srv) => {
                        if let Err(e) = srv.run(gctk).await {
                            error!("ReceiverGattServer: {}", e);
                        }
                    }
                    Err(e) => error!("Couldn't init ReceiverGattServer: {}", e),
                }
            });

            // BLE receiver advertisement (0xFEF3), only while visible.
            let ctk = ctoken.clone();
            let mut visibility = self.visibility_receiver.clone();
            tracker.spawn(async move {
                let adv = match crate::hdl::ReceiverAdvertiser::new(
                    rx_endpoint_id,
                    crate::utils::DeviceType::Laptop as u8,
                    &rx_device_name,
                )
                .await
                {
                    Ok(adv) => adv,
                    Err(e) => {
                        error!("Couldn't init ReceiverAdvertiser: {}", e);
                        return;
                    }
                };

                loop {
                    tokio::select! {
                        _ = ctk.cancelled() => return,
                        r = visibility.wait_for(|v| *v != Visibility::Invisible) => {
                            if r.is_err() {
                                return;
                            }
                        }
                    }

                    // Dropping run() drops its advertisement handle, which
                    // unregisters the advertisement.
                    tokio::select! {
                        res = adv.run(ctk.clone()) => {
                            if let Err(e) = res {
                                error!("ReceiverAdvertiser: {}", e);
                            }
                            return;
                        }
                        r = visibility.wait_for(|v| *v == Visibility::Invisible) => {
                            if r.is_err() {
                                return;
                            }
                            info!("ReceiverAdvertiser: hidden, stopped advertising");
                        }
                    }
                }
            });
        }

        tracker.close();

        Ok((send_channel.0, self.ble_sender.subscribe()))
    }

    pub fn discovery(
        &mut self,
        sender: broadcast::Sender<EndpointInfo>,
    ) -> Result<(), anyhow::Error> {
        let tracker = self
            .tracker
            .as_ref()
            .ok_or_else(|| anyhow!("The service wasn't first started"))?;

        let ctk = CancellationToken::new();
        self.discovery_ctk = Some(ctk.clone());

        #[cfg(all(feature = "experimental", target_os = "linux"))]
        {
            let ctk_blea = ctk.clone();
            tracker.spawn(async move {
                let blea = match BleAdvertiser::new().await {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Couldn't init BleAdvertiser: {}", e);
                        return;
                    }
                };

                if let Err(e) = blea.run(ctk_blea).await {
                    error!("Couldn't start BleAdvertiser: {}", e);
                }
            });
        }

        let discovery = MDnsDiscovery::new(sender)?;
        tracker.spawn(async move { discovery.run(ctk.clone()).await });

        Ok(())
    }

    pub fn stop_discovery(&mut self) {
        if let Some(discovert_ctk) = &self.discovery_ctk {
            discovert_ctk.cancel();
            self.discovery_ctk = None;
        }
    }

    pub fn change_visibility(&mut self, nv: Visibility) {
        self.visibility_sender
            .lock()
            .unwrap()
            .send_modify(|state| *state = nv);
    }

    pub async fn stop(&mut self) {
        self.stop_discovery();

        if let Some(ctoken) = &self.ctoken {
            ctoken.cancel();
        }

        if let Some(tracker) = &self.tracker {
            // Inorder for TaskTracker::wait to return, close() must be called
            // and the count of tasks being watched should be 0 (i.e. they've all closed).
            //
            // If not, the TaskTracker may forever wait if task count is 0 when wait() was called
            tracker.close();
            tracker.wait().await;
        }

        self.ctoken = None;
        self.tracker = None;
    }

    // Setting None here will resume the default settings
    pub fn set_download_path(&self, p: Option<PathBuf>) {
        debug!("Setting the download path to {:?}", p);
        let mut guard = CUSTOM_DOWNLOAD.write().unwrap();
        *guard = p;
    }

    /// For this to properly take effect,
    /// `MdnsServer` would need to be reset which is done by `RQS::stop` followed by `RQS::run`.
    ///
    /// So only do this when no data transfer is going on.
    pub fn set_device_name(&self, name: String) {
        debug!("Setting the device name {:?}", name);
        let mut guard = DEVICE_NAME.write().unwrap();
        *guard = name;
    }

    pub fn get_device_name(&self) -> String {
        DEVICE_NAME.read().unwrap().clone()
    }
}
