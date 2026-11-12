//! Receive from a Quick Share sender over Bluetooth, without a shared LAN.
//!
//!     cargo run --example bt_receive -- [DOWNLOAD_DIR] [DEVICE_NAME]
//!
//! Stays visible to everyone (which also makes the Bluetooth adapter
//! discoverable while it runs) and accepts every incoming transfer.
//! Stop with Ctrl-C.

use std::path::PathBuf;

use rqs_lib::channel::{ChannelMessage, Message, TransferAction, TransferKind};
use rqs_lib::{RQS, TransferState, Visibility};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("rqs_lib=debug,bt_receive=debug")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let download = args.next().map(PathBuf::from);
    let name = args.next().unwrap_or_else(|| "RQS Bluetooth test".into());

    let mut rqs = RQS::new(Visibility::Visible, None, download, Some(name.clone()));
    rqs.run().await?;
    let sender = rqs.message_sender.clone();
    let mut events = sender.subscribe();
    println!("visible as {name:?}; send something from the phone (Ctrl-C to stop)");

    loop {
        let msg = tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            m = events.recv() => m?,
        };
        let Message::Client(client) = &msg.msg else {
            continue;
        };
        if client.kind != TransferKind::Inbound {
            continue;
        }
        let Some(state) = &client.state else { continue };
        println!("[{}] state: {state:?}", msg.id);

        match state {
            TransferState::WaitingForUserConsent => {
                if let Some(meta) = &client.metadata {
                    println!(
                        "  from {:?}, PIN {:?}, {:?}",
                        meta.source.as_ref().map(|s| &s.name),
                        meta.pin_code,
                        meta.payload_preview
                            .as_ref()
                            .unwrap_or(&format!("{} bytes", meta.total_bytes))
                    );
                }
                let _ = sender.send(ChannelMessage {
                    id: msg.id.clone(),
                    msg: Message::Lib {
                        action: TransferAction::ConsentAccept,
                    },
                });
            }
            TransferState::Finished => {
                if let Some(payload) = client.metadata.as_ref().and_then(|m| m.payload.as_ref()) {
                    println!("  received: {payload:?}");
                }
            }
            _ => {}
        }
    }

    rqs.stop().await;
    Ok(())
}
