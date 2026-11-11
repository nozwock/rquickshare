use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;

use crate::channel::{self, ChannelMessage, MessageClient, TransferKind};
use crate::errors::AppError;
#[cfg(all(feature = "experimental", target_os = "linux"))]
use crate::hdl::bluetooth::{self, BluetoothServer};
use crate::hdl::{InboundRequest, OutboundPayload, OutboundRequest, TransferState, Transport};
use crate::utils::RemoteDeviceInfo;

const INNER_NAME: &str = "TcpServer";

/// Without Bluetooth support the server slot can never be filled.
#[cfg(not(all(feature = "experimental", target_os = "linux")))]
type BluetoothServer = std::convert::Infallible;

#[derive(Debug, Clone)]
pub struct SendInfo {
    pub id: String,
    pub name: String,
    /// Where to reach the endpoint: `ip:port` for Wi-Fi LAN, or a Bluetooth
    /// address (`AA:BB:CC:DD:EE:FF`) for Bluetooth RFCOMM.
    pub addr: String,
    pub ob: OutboundPayload,
}

pub struct TcpServer {
    endpoint_id: [u8; 4],
    tcp_listener: TcpListener,
    sender: Sender<ChannelMessage>,
    connect_receiver: Receiver<SendInfo>,
    bluetooth: Option<BluetoothServer>,
}

impl TcpServer {
    pub fn new(
        endpoint_id: [u8; 4],
        tcp_listener: TcpListener,
        sender: Sender<ChannelMessage>,
        connect_receiver: Receiver<SendInfo>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            endpoint_id,
            tcp_listener,
            sender,
            connect_receiver,
            bluetooth: None,
        })
    }

    /// Also accept incoming connections over Bluetooth RFCOMM.
    #[cfg(all(feature = "experimental", target_os = "linux"))]
    pub fn set_bluetooth(&mut self, server: BluetoothServer) {
        self.bluetooth = Some(server);
    }

    pub async fn run(&mut self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        info!("{INNER_NAME}: service starting");

        loop {
            let cctk = ctk.clone();

            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                }
                Some(i) = self.connect_receiver.recv() => {
                    info!("{INNER_NAME}: connect_receiver: got {:?}", i);
                    if let Err(e) = self.connect(cctk, i).await {
                        error!("{INNER_NAME}: error sending: {}", e.to_string());
                    }
                }
                r = self.tcp_listener.accept() => {
                    match r {
                        Ok((socket, remote_addr)) => {
                            trace!("{INNER_NAME}: new client: {remote_addr}");
                            self.spawn_inbound(socket.into(), remote_addr.to_string());
                        },
                        Err(err) => {
                            error!("{INNER_NAME}: error accepting: {}", err);
                            break;
                        }
                    }
                }
                r = accept_bluetooth(&mut self.bluetooth) => {
                    match r {
                        Ok((transport, remote_addr)) => {
                            trace!("{INNER_NAME}: new Bluetooth client: {remote_addr}");
                            self.spawn_inbound(transport, remote_addr);
                        },
                        Err(err) => {
                            // Keep serving Wi-Fi LAN clients.
                            error!("{INNER_NAME}: error accepting over Bluetooth, disabling it: {err}");
                            self.bluetooth = None;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn spawn_inbound(&self, transport: Transport, id: String) {
        let esender = self.sender.clone();
        let csender = self.sender.clone();

        tokio::spawn(async move {
            let mut ir = InboundRequest::new(transport, id.clone(), csender);

            loop {
                match ir.handle().await {
                    Ok(_) => {}
                    Err(e) => match e.downcast_ref() {
                        Some(AppError::NotAnError) => break,
                        None => {
                            if ir.state.state == TransferState::Initial {
                                break;
                            }

                            if ir.state.state != TransferState::Finished {
                                let _ = esender.send(ChannelMessage {
                                    id: id.clone(),
                                    msg: channel::Message::Client(MessageClient {
                                        kind: TransferKind::Inbound,
                                        state: Some(TransferState::Disconnected),
                                        metadata: Default::default(),
                                    }),
                                });
                            }
                            error!(
                                "{INNER_NAME}: error while handling client: {e} ({:?})",
                                ir.state.state
                            );
                            break;
                        }
                    },
                }
            }
        });
    }

    /// To be called inside a separate task if we want to handle concurrency
    pub async fn connect(&self, ctk: CancellationToken, si: SendInfo) -> Result<(), anyhow::Error> {
        debug!("{INNER_NAME}: Connecting to: {}", si.addr);
        let socket = dial(&si.addr).await?;

        let mut or = OutboundRequest::new(
            self.endpoint_id,
            socket,
            si.id,
            self.sender.clone(),
            si.ob,
            RemoteDeviceInfo {
                device_type: crate::DeviceType::Unknown,
                name: si.name,
            },
        );

        // Send connection request
        or.send_connection_request().await?;
        // Send UKEY init
        or.send_ukey2_client_init().await?;

        loop {
            tokio::select! {
                _ = ctk.cancelled() => {
                    info!("{INNER_NAME}: tracker cancelled, breaking");
                    break;
                },
                r = or.handle() => {
                    if let Err(e) = r {
                        match e.downcast_ref() {
                            Some(AppError::NotAnError) => break,
                            None => {
                                if or.state.state == TransferState::Initial {
                                    break;
                                }

                                if or.state.state != TransferState::Finished && or.state.state != TransferState::Cancelled {
                                    let _ = self.sender.clone().send(ChannelMessage {
                                        id: si.addr,
                                        msg: channel::Message::Client(MessageClient {
                                            kind: TransferKind::Outbound,
                                            state: Some(TransferState::Disconnected),
                                            metadata: Default::default()
                                        }),
                                    });
                                }
                                error!("{INNER_NAME}: error while handling client: {e} ({:?})", or.state.state);
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Opens a transport to `addr` (see [`SendInfo::addr`]).
async fn dial(addr: &str) -> Result<Transport, anyhow::Error> {
    #[cfg(all(feature = "experimental", target_os = "linux"))]
    if let Some(bt_addr) = bluetooth::parse_address(addr) {
        return bluetooth::connect(bt_addr).await;
    }

    Ok(TcpStream::connect(addr).await?.into())
}

/// Next incoming Bluetooth connection, or never if Bluetooth is not serving.
async fn accept_bluetooth(
    server: &mut Option<BluetoothServer>,
) -> Result<(Transport, String), anyhow::Error> {
    #[cfg(all(feature = "experimental", target_os = "linux"))]
    if let Some(server) = server {
        let (transport, addr) = server.accept().await?;
        return Ok((transport, addr.to_string()));
    }
    #[cfg(not(all(feature = "experimental", target_os = "linux")))]
    let _ = server;

    std::future::pending().await
}
