//! Send text to a Quick Share device over Bluetooth RFCOMM.
//!
//!     cargo run --example bt_send -- AA:BB:CC:DD:EE:FF "hello"
//!
//! The receiver must be in Quick Share's receiving mode (visible). Its
//! Bluetooth address is under Settings > About phone on Android.

use std::time::Duration;

use rqs_lib::channel::Message;
use rqs_lib::{OutboundPayload, RQS, SendInfo, TextPayloadType, TransferState, Visibility};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("rqs_lib=debug,bt_send=debug")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let (Some(addr), Some(text)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: bt_send <BLUETOOTH_ADDRESS> <TEXT>");
    };
    anyhow::ensure!(
        rqs_lib::hdl::bluetooth::parse_address(&addr).is_some(),
        "{addr} is not a Bluetooth address"
    );

    let mut rqs = RQS::new(Visibility::Invisible, None, None, None);
    let (send, _) = rqs.run().await?;
    let mut events = rqs.message_sender.subscribe();

    send.send(SendInfo {
        id: addr.clone(),
        name: addr.clone(),
        addr: addr.clone(),
        ob: OutboundPayload::Text {
            text,
            text_type: TextPayloadType::Text,
        },
    })
    .await?;

    // SDP + RFCOMM connect take at most ~25 s; afterwards the receiver
    // needs time to accept on the phone.
    let outcome = tokio::time::timeout(Duration::from_secs(150), async {
        let mut connected = false;
        loop {
            let wait = Duration::from_secs(if connected { 120 } else { 30 });
            let Ok(msg) = tokio::time::timeout(wait, events.recv()).await else {
                anyhow::bail!("no response (connection errors are in the log above)");
            };
            let msg = msg?;
            connected = true;
            let Message::Client(client) = msg.msg else {
                continue;
            };
            let Some(state) = client.state else { continue };
            if let Some(pin) = client.metadata.as_ref().and_then(|m| m.pin_code.clone()) {
                println!("state: {state:?} (PIN {pin})");
            } else {
                println!("state: {state:?}");
            }
            if matches!(
                state,
                TransferState::Finished
                    | TransferState::Rejected
                    | TransferState::Cancelled
                    | TransferState::Disconnected
            ) {
                return Ok::<_, anyhow::Error>(state);
            }
        }
    })
    .await;

    rqs.stop().await;
    match outcome {
        Ok(Ok(state)) => println!("result: {state:?}"),
        Ok(Err(err)) => println!("result: {err}"),
        Err(_) => println!("result: timed out"),
    }
    Ok(())
}
