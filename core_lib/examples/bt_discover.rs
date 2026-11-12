//! Look for Quick Share receivers like Packet's send dialog does, and print
//! when each one shows up.
//!
//!     cargo run --example bt_discover -- [SECONDS] [visible|invisible]
//!
//! The receiver must be in Quick Share's receiving mode and visible to
//! everyone.

use std::time::{Duration, Instant};

use rqs_lib::{RQS, Visibility};
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("rqs_lib=info,bt_discover=debug")),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let seconds: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(60);
    let visibility = match args.next().as_deref() {
        Some("invisible") => Visibility::Invisible,
        _ => Visibility::Visible,
    };

    let mut rqs = RQS::new(visibility, None, None, None);
    rqs.run().await?;

    let (tx, mut found) = broadcast::channel(16);
    let started = Instant::now();
    rqs.discovery(tx)?;
    println!("discovering for {seconds} s ({visibility:?})...");
    let _ = tokio::time::timeout(Duration::from_secs(seconds), async {
        while let Ok(e) = found.recv().await {
            println!(
                "{:>5.1} s: {:?} bt={:?} ip={:?} present={:?}",
                started.elapsed().as_secs_f32(),
                e.name,
                e.bluetooth_address,
                e.ip,
                e.present
            );
        }
    })
    .await;
    rqs.stop_discovery();
    rqs.stop().await;
    Ok(())
}
