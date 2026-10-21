use std::sync::Arc;

use bluer::gatt::local::{
    Application, Characteristic, CharacteristicNotify, CharacteristicNotifyMethod,
    CharacteristicNotifier, CharacteristicRead, CharacteristicWrite, CharacteristicWriteMethod,
    Service,
};
use bluer::{Adapter, Uuid, UuidExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::broadcast::Sender;
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio_util::sync::CancellationToken;

use crate::channel::ChannelMessage;
use crate::errors::AppError;
use crate::hdl::InboundRequest;

const INNER_NAME: &str = "ReceiverGattServer";

// Nearby Connections copresence GATT service + advertisement slot-0 characteristic.
const QS_GATT_SERVICE: u16 = 0xFEF3;
const QS_ADV_SLOT0_UUID: &str = "00000000-0000-3000-8000-000000000000";
// BLE-"weave" GATT socket characteristics (Apple GNS* client code):
// ToPeripheral = phone -> us (write), FromPeripheral = us -> phone (notify).
const QS_WEAVE_TO_PERIPHERAL: &str = "00000100-0004-1000-8000-001a11000101";
const QS_WEAVE_FROM_PERIPHERAL: &str = "00000100-0004-1000-8000-001a11000102";

// Weave packet header bits (internal/weave/packet.cc).
const WEAVE_CONTROL: u8 = 0b1000_0000;
const WEAVE_CMD_MASK: u8 = 0b0000_1111;
const WEAVE_FIRST_BIT: u8 = 0b0000_1000;
const WEAVE_LAST_BIT: u8 = 0b0000_0100;
const WEAVE_COUNTER_MASK: u8 = 0b0111_0000;
const WEAVE_CMD_CONN_REQUEST: u8 = 0;
const WEAVE_CMD_CONN_CONFIRM: u8 = 1;
const WEAVE_CMD_ERROR: u8 = 2;
const WEAVE_PROTOCOL_VERSION: u16 = 1;

// BLE-socket demux (internal/platform .../ble_packet): [service_id_hash(3)][data];
// service_id_hash 00 00 00 marks a control packet (SocketControlFrame).
const QS_SVC_HASH: [u8; 3] = [0xfc, 0x9f, 0x5e];
const SOCKET_CTRL_INTRODUCTION: u8 = 1;
const SOCKET_CTRL_DISCONNECTION: u8 = 2;

pub struct ReceiverGattServer {
    adapter: Arc<Adapter>,
    advertisement: Vec<u8>,
    sender: Sender<ChannelMessage>,
    tcp_port: u16,
}

impl ReceiverGattServer {
    pub async fn new(
        advertisement: Vec<u8>,
        sender: Sender<ChannelMessage>,
        tcp_port: u16,
    ) -> Result<Self, anyhow::Error> {
        let session = bluer::Session::new().await?;
        let adapter = session.default_adapter().await?;
        adapter.set_powered(true).await?;

        Ok(Self {
            adapter: Arc::new(adapter),
            advertisement,
            sender,
            tcp_port,
        })
    }

    pub async fn run(&self, ctk: CancellationToken) -> Result<(), anyhow::Error> {
        let service_uuid = Uuid::from_u16(QS_GATT_SERVICE);
        let slot0: Uuid = QS_ADV_SLOT0_UUID.parse()?;
        let weave_write: Uuid = QS_WEAVE_TO_PERIPHERAL.parse()?;
        let weave_notify: Uuid = QS_WEAVE_FROM_PERIPHERAL.parse()?;
        let advert = self.advertisement.clone();

        // Weave packets written by the phone to 0101 are forwarded to the notify
        // task (which owns the notifier needed to reply on 0102).
        let (pkt_tx, pkt_rx) = unbounded_channel::<Vec<u8>>();
        let pkt_rx: Arc<Mutex<Option<UnboundedReceiver<Vec<u8>>>>> =
            Arc::new(Mutex::new(Some(pkt_rx)));
        let sender = self.sender.clone();
        let tcp_port = self.tcp_port;

        let app = Application {
            services: vec![Service {
                uuid: service_uuid,
                primary: true,
                characteristics: vec![
                    Characteristic {
                        uuid: slot0,
                        read: Some(CharacteristicRead {
                            read: true,
                            fun: Box::new(move |_req| {
                                let advert = advert.clone();
                                Box::pin(async move {
                                    debug!("{INNER_NAME}: slot0 advertisement read ({} bytes)", advert.len());
                                    Ok(advert)
                                })
                            }),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: weave_write,
                        write: Some(CharacteristicWrite {
                            write: true,
                            // Write-with-response only: forces the phone to send weave
                            // packets serially so BlueZ delivers them to us in order.
                            write_without_response: false,
                            method: CharacteristicWriteMethod::Fun(Box::new(move |value, _req| {
                                let pkt_tx = pkt_tx.clone();
                                Box::pin(async move {
                                    let _ = pkt_tx.send(value);
                                    Ok(())
                                })
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    Characteristic {
                        uuid: weave_notify,
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            indicate: true,
                            method: CharacteristicNotifyMethod::Fun(Box::new(move |notifier| {
                                let pkt_rx = pkt_rx.clone();
                                let sender = sender.clone();
                                Box::pin(async move {
                                    weave_session(notifier, pkt_rx, sender, tcp_port).await;
                                })
                            })),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        info!(
            "{INNER_NAME}: registering GATT service 0x{QS_GATT_SERVICE:04X} (slot0 {} bytes + weave socket)",
            self.advertisement.len()
        );
        let handle = self.adapter.serve_gatt_application(app).await?;
        ctk.cancelled().await;
        info!("{INNER_NAME}: tracker cancelled, returning");
        drop(handle);

        Ok(())
    }
}

/// Bridges the weave BLE socket to the (transport-generic) inbound handshake:
/// answers the Connection Request, then shuttles the `[hash][len][OfflineFrame]`
/// stream between the phone and an `InboundRequest` running over an in-memory duplex.
async fn weave_session(
    mut notifier: CharacteristicNotifier,
    pkt_rx: Arc<Mutex<Option<UnboundedReceiver<Vec<u8>>>>>,
    sender: Sender<ChannelMessage>,
    tcp_port: u16,
) {
    let mut guard = pkt_rx.lock().await;
    let Some(rx) = guard.as_mut() else {
        warn!("{INNER_NAME}: weave: no packet receiver (second session?)");
        return;
    };
    info!("{INNER_NAME}: weave: notify session open");

    // 1. Weave connection handshake.
    let selected = loop {
        match rx.recv().await {
            Some(pkt)
                if !pkt.is_empty()
                    && pkt[0] & WEAVE_CONTROL != 0
                    && pkt[0] & WEAVE_CMD_MASK == WEAVE_CMD_CONN_REQUEST =>
            {
                let max = if pkt.len() >= 7 {
                    u16::from_be_bytes([pkt[5], pkt[6]])
                } else {
                    100
                };
                break max.min(509).max(20);
            }
            Some(_) => continue,
            None => return,
        }
    };
    let confirm = vec![
        WEAVE_CONTROL | WEAVE_CMD_CONN_CONFIRM,
        (WEAVE_PROTOCOL_VERSION >> 8) as u8,
        (WEAVE_PROTOCOL_VERSION & 0xff) as u8,
        (selected >> 8) as u8,
        (selected & 0xff) as u8,
    ];
    if let Err(e) = notifier.notify(confirm).await {
        error!("{INNER_NAME}: weave: conn-confirm failed: {e}");
        return;
    }
    let max_payload = (selected as usize).saturating_sub(1).max(19);
    info!("{INNER_NAME}: weave: connected (selected={selected})");

    // 2. Run the inbound handshake over an in-memory duplex; we bridge the bytes.
    let (inbound_side, weave_side) = tokio::io::duplex(64 * 1024);
    let (mut weave_rd, mut weave_wr) = tokio::io::split(weave_side);
    let isender = sender.clone();
    tokio::spawn(async move {
        // A unique id per session, so overlapping transfers don't collide in
        // the UI (which keys transfers by this id).
        let mut ir = InboundRequest::new(
            crate::hdl::MigratableStream::Ble(inbound_side),
            format!("ble-weave-{:08x}", rand::random::<u32>()),
            isender,
        );
        ir.set_bwu_tcp_port(tcp_port);
        loop {
            if let Err(e) = ir.handle().await {
                if !matches!(e.downcast_ref(), Some(AppError::NotAnError)) {
                    debug!("{INNER_NAME}: weave inbound ended: {e}");
                }
                break;
            }
            // Once the encrypted connection is up, upgrade the payload to Wi-Fi.
            if ir.take_bwu_pending() {
                if let Err(e) = ir.do_bwu().await {
                    warn!("{INNER_NAME}: BWU failed, staying on BLE: {e}");
                }
            }
        }
    });

    // 3. Shuttle loop.
    let mut reasm: Vec<u8> = Vec::new(); // reassembles fragmented weave messages
    let mut out_buf: Vec<u8> = Vec::new(); // accumulates inbound's [len][frame] writes
    let mut send_counter: u8 = 1; // conn-confirm was counter 0
    let mut rbuf = [0u8; 2048];

    loop {
        tokio::select! {
            maybe_pkt = rx.recv() => {
                let Some(pkt) = maybe_pkt else { break; };
                if pkt.is_empty() { continue; }
                let hdr = pkt[0];
                debug!("{INNER_NAME}: rx pkt hdr={hdr:#04x} plen={}", pkt.len());
                if hdr & WEAVE_CONTROL != 0 {
                    if hdr & WEAVE_CMD_MASK == WEAVE_CMD_ERROR {
                        debug!("{INNER_NAME}: weave: peer sent ERROR, closing");
                        break;
                    }
                    continue;
                }
                // Data weave packet: reassemble first..last into a message.
                reasm.extend_from_slice(&pkt[1..]);
                if hdr & WEAVE_LAST_BIT == 0 {
                    continue;
                }
                let msg = std::mem::take(&mut reasm);
                if msg.len() < 3 {
                    continue;
                }
                debug!("{INNER_NAME}: rx msg {} bytes: {}", msg.len(), hex::encode(&msg[..msg.len().min(24)]));
                if msg[0..3] == [0, 0, 0] {
                    // BLE control packet (SocketControlFrame): 00 00 00 08 <type> ...
                    let ctrl_type = if msg.len() >= 5 && msg[3] == 0x08 { msg[4] } else { 0 };
                    match ctrl_type {
                        SOCKET_CTRL_INTRODUCTION => debug!("{INNER_NAME}: weave: INTRODUCTION"),
                        SOCKET_CTRL_DISCONNECTION => {
                            debug!("{INNER_NAME}: weave: DISCONNECTION");
                            break;
                        }
                        _ => debug!("{INNER_NAME}: weave: control {}", hex::encode(&msg)),
                    }
                    continue;
                }
                // Data packet: strip 3-byte hash, forward [len][frame] to inbound.
                let inner = &msg[3..];
                let len_field = if inner.len() >= 4 {
                    u32::from_be_bytes([inner[0], inner[1], inner[2], inner[3]])
                } else {
                    0
                };
                debug!(
                    "{INNER_NAME}: -> inbound {} bytes, len_field={len_field} hash={}",
                    inner.len(),
                    hex::encode(&msg[..3])
                );
                if weave_wr.write_all(inner).await.is_err() {
                    break;
                }
            }
            r = weave_rd.read(&mut rbuf) => {
                match r {
                    Ok(0) => break, // inbound closed
                    Ok(n) => {
                        out_buf.extend_from_slice(&rbuf[..n]);
                        // Emit each complete [len(4)][frame] as a BLE data message.
                        loop {
                            if out_buf.len() < 4 { break; }
                            let len = u32::from_be_bytes([out_buf[0], out_buf[1], out_buf[2], out_buf[3]]) as usize;
                            if out_buf.len() < 4 + len { break; }
                            let entry: Vec<u8> = out_buf.drain(0..4 + len).collect();
                            let mut message = Vec::with_capacity(3 + entry.len());
                            message.extend_from_slice(&QS_SVC_HASH);
                            message.extend_from_slice(&entry);
                            // Fragment into weave data packets.
                            let total = message.len();
                            let mut off = 0;
                            while off < total {
                                let end = (off + max_payload).min(total);
                                let first = off == 0;
                                let last = end == total;
                                let mut wp = Vec::with_capacity(1 + (end - off));
                                let mut h = (send_counter & 0x07) << 4;
                                if first { h |= WEAVE_FIRST_BIT; }
                                if last { h |= WEAVE_LAST_BIT; }
                                let _ = WEAVE_COUNTER_MASK; // documents counter field
                                wp.push(h);
                                wp.extend_from_slice(&message[off..end]);
                                send_counter = send_counter.wrapping_add(1);
                                if let Err(e) = notifier.notify(wp).await {
                                    error!("{INNER_NAME}: weave: notify failed: {e}");
                                    return;
                                }
                                off = end;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    info!("{INNER_NAME}: weave: session ended");
}
