//! End-to-end transfers between an `OutboundRequest` and an `InboundRequest`
//! over an in-memory stream instead of a TCP socket.
//!
//! This stands in for a non-IP medium (e.g. Bluetooth RFCOMM) and checks that
//! the whole protocol stack (connection request, UKEY2, paired key exchange,
//! introduction, consent, encrypted payload transfer) is medium-agnostic.

use std::path::PathBuf;
use std::time::Duration;

use rqs_lib::channel::{ChannelMessage, Message, TransferAction};
use rqs_lib::hdl::info::TransferPayload;
use rqs_lib::hdl::transport::Medium;
use rqs_lib::hdl::{InboundRequest, OutboundPayload, OutboundRequest, Transport};
use rqs_lib::utils::RemoteDeviceInfo;
use rqs_lib::{DeviceType, RQS, TextPayloadType, TransferState, Visibility};
use tokio::sync::broadcast;

const INBOUND_ID: &str = "inbound";
const OUTBOUND_ID: &str = "outbound";

/// Runs one transfer to completion and returns the payload the receiver saw.
async fn transfer(payload: OutboundPayload) -> TransferPayload {
    let (a, b) = tokio::io::duplex(64 * 1024);
    let (sender, _) = broadcast::channel(256);
    let mut events = sender.subscribe();

    let mut inbound = InboundRequest::new(
        Transport::new(Medium::Bluetooth, b),
        INBOUND_ID.into(),
        sender.clone(),
    );
    let mut outbound = OutboundRequest::new(
        *b"TEST",
        Transport::new(Medium::Bluetooth, a),
        OUTBOUND_ID.into(),
        sender.clone(),
        payload,
        RemoteDeviceInfo {
            name: "receiver".into(),
            device_type: DeviceType::Laptop,
        },
    );

    let inbound_task = tokio::spawn(async move { while inbound.handle().await.is_ok() {} });
    let outbound_task = tokio::spawn(async move {
        outbound.send_connection_request().await.unwrap();
        outbound.send_ukey2_client_init().await.unwrap();
        while outbound.handle().await.is_ok() {}
    });

    let received = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let msg = events.recv().await.unwrap();
            if msg.id != INBOUND_ID {
                continue;
            }
            let Some(client) = msg.msg.as_client() else {
                continue;
            };
            match client.state {
                Some(TransferState::WaitingForUserConsent) => {
                    sender
                        .send(ChannelMessage {
                            id: INBOUND_ID.into(),
                            msg: Message::Lib {
                                action: TransferAction::ConsentAccept,
                            },
                        })
                        .unwrap();
                }
                Some(TransferState::Finished) => {
                    break client.metadata.clone().unwrap().payload.unwrap();
                }
                Some(
                    ref s @ (TransferState::Disconnected
                    | TransferState::Rejected
                    | TransferState::Cancelled),
                ) => panic!("transfer ended early: {s:?}"),
                _ => {}
            }
        }
    })
    .await
    .expect("transfer timed out");

    tokio::time::timeout(Duration::from_secs(5), async {
        inbound_task.await.unwrap();
        outbound_task.await.unwrap();
    })
    .await
    .expect("request handlers did not exit");

    received
}

#[tokio::test(flavor = "multi_thread")]
async fn text_over_non_tcp_transport() {
    let text = "hello over a non-TCP medium";
    let payload = transfer(OutboundPayload::Text {
        text: text.into(),
        text_type: TextPayloadType::Text,
    })
    .await;

    assert!(matches!(payload, TransferPayload::Text(t) if t == text));
}

#[tokio::test(flavor = "multi_thread")]
async fn file_over_non_tcp_transport() {
    let root = std::env::temp_dir().join(format!("rqs-loopback-{}", std::process::id()));
    let src_dir = root.join("src");
    let dst_dir = root.join("dst");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::create_dir_all(&dst_dir).unwrap();

    // Large enough to span several payload chunks.
    let content: Vec<u8> = (0..3 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let src: PathBuf = src_dir.join("blob.bin");
    std::fs::write(&src, &content).unwrap();

    // Only used to set the process-wide download directory.
    let _rqs = RQS::new(Visibility::Invisible, None, Some(dst_dir.clone()), None);

    let payload = transfer(OutboundPayload::Files(vec![
        src.to_string_lossy().into_owned(),
    ]))
    .await;

    assert!(matches!(payload, TransferPayload::Files(_)), "{payload:?}");
    assert_eq!(std::fs::read(dst_dir.join("blob.bin")).unwrap(), content);

    let _ = std::fs::remove_dir_all(&root);
}
