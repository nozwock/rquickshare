//! Checks against a real bluetoothd. Needs a Bluetooth adapter, so ignored by
//! default: `cargo test --test bluetooth_bluez -- --ignored --test-threads=1`
#![cfg(all(feature = "experimental", target_os = "linux"))]

use std::time::Duration;

use rqs_lib::hdl::bluetooth::{BluetoothServer, service_uuid};

async fn adapter_has_service() -> bool {
    let session = bluer::Session::new().await.unwrap();
    let adapter = session.default_adapter().await.unwrap();
    adapter
        .uuids()
        .await
        .unwrap()
        .unwrap_or_default()
        .contains(&service_uuid())
}

/// Number of RFCOMM sockets the kernel knows about (listening ones included).
fn rfcomm_sockets() -> usize {
    std::fs::read_to_string("/proc/net/rfcomm")
        .map(|s| s.lines().skip(1).count())
        .unwrap_or(0)
}

async fn eventually(mut cond: impl AsyncFnMut() -> bool) -> bool {
    for _ in 0..50 {
        if cond().await {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
#[ignore = "needs bluetoothd and an adapter"]
async fn registers_listens_and_survives_restart() {
    assert!(!adapter_has_service().await, "service already registered");
    let sockets_before = rfcomm_sockets();

    let server = BluetoothServer::new().await.unwrap();
    assert!(eventually(adapter_has_service).await, "UUID not published");
    assert_eq!(rfcomm_sockets(), sockets_before + 1, "no RFCOMM listener");

    // What RQS::stop + RQS::run does: drop and immediately register again.
    drop(server);
    let server = BluetoothServer::new().await.unwrap();
    assert!(eventually(adapter_has_service).await);
    assert!(eventually(async || rfcomm_sockets() == sockets_before + 1).await);

    drop(server);
    assert!(
        eventually(async || !adapter_has_service().await).await,
        "UUID not removed after drop"
    );
    assert!(eventually(async || rfcomm_sockets() == sockets_before).await);
}
