// End-to-end receive test: runs the full RQS service (mDNS + TCP + the new
// 0xFEF3 BLE receiver advert), auto-accepts any incoming transfer, and logs the
// state machine. Point a phone at "Packet Linux RX" and send a file.
#[macro_use]
extern crate log;

use rqs_lib::channel::{ChannelMessage, Message, TransferAction};
use rqs_lib::{RQS, TransferState, Visibility};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(if std::env::var("RUST_LOG").is_ok() {
            EnvFilter::builder().from_env_lossy()
        } else {
            EnvFilter::builder().parse_lossy(
                "info,rqs_lib=debug,mdns_sd=error,polling=error,neli=error,bluez_async=error,btleplug=error",
            )
        })
        .init();

    let download_dir = std::env::temp_dir().join("rqs-received");
    std::fs::create_dir_all(&download_dir).ok();

    let mut rqs = RQS::new(
        Visibility::Visible,
        None,
        Some(download_dir.clone()),
        Some("Packet Linux RX".to_string()),
    );
    rqs.run().await?;
    println!(
        "RQS receive service running: mDNS + TCP + BLE 0xFEF3 receiver advert. Downloads -> {}",
        download_dir.display()
    );
    println!("On the phone, open Quick Share -> Send and look for 'Packet Linux RX'. Ctrl-C to stop.");

    // Auto-accept any inbound transfer so a file actually lands.
    let sender = rqs.message_sender.clone();
    let mut rx = rqs.message_sender.subscribe();
    tokio::spawn(async move {
        while let Ok(cm) = rx.recv().await {
            if let Message::Client(mc) = &cm.msg {
                info!("EVENT id={} kind={:?} state={:?}", cm.id, mc.kind, mc.state);
                if mc.state == Some(TransferState::WaitingForUserConsent) {
                    info!(">>> auto-accepting transfer {}", cm.id);
                    let _ = sender.send(ChannelMessage {
                        id: cm.id.clone(),
                        msg: Message::Lib {
                            action: TransferAction::ConsentAccept,
                        },
                    });
                }
            }
        }
    });

    let _ = tokio::signal::ctrl_c().await;
    info!("Stopping service.");
    rqs.stop().await;
    Ok(())
}
