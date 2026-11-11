//! Merges an endpoint discovered on several mediums into a single entry.
//!
//! A receiver on the same Wi-Fi LAN is found both over mDNS (id `ip:port`)
//! and over BLE (id = Bluetooth address). Both carry the same Nearby
//! endpoint id, which is used to recognise them as one device. The merged
//! entry keeps the id it was first reported with, so consumers that key on
//! [`EndpointInfo::id`] see one device that gains or loses addresses.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio_util::sync::CancellationToken;

use super::EndpointInfo;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    Mdns,
    Ble,
}

#[derive(Default)]
struct Entry {
    /// Id the entry was first reported with.
    id: String,
    mdns: Option<EndpointInfo>,
    ble: Option<EndpointInfo>,
}

impl Entry {
    fn slot(&mut self, source: Source) -> &mut Option<EndpointInfo> {
        match source {
            Source::Mdns => &mut self.mdns,
            Source::Ble => &mut self.ble,
        }
    }

    fn merged(&self) -> EndpointInfo {
        let (mdns, ble) = (self.mdns.as_ref(), self.ble.as_ref());
        let primary = mdns.or(ble).expect("entry has at least one source");

        EndpointInfo {
            id: self.id.clone(),
            fullname: primary.fullname.clone(),
            name: mdns
                .and_then(|e| e.name.clone())
                .or_else(|| ble.and_then(|e| e.name.clone())),
            rtype: mdns
                .and_then(|e| e.rtype.clone())
                .or_else(|| ble.and_then(|e| e.rtype.clone())),
            ip: mdns.and_then(|e| e.ip.clone()),
            port: mdns.and_then(|e| e.port.clone()),
            bluetooth_address: ble.and_then(|e| e.bluetooth_address.clone()),
            present: Some(true),
        }
    }
}

#[derive(Default)]
pub(crate) struct EndpointMerger {
    /// Merge key -> entry.
    entries: HashMap<String, Entry>,
    /// (source, id reported by that source) -> merge key.
    keys: HashMap<(Source, String), String>,
}

impl EndpointMerger {
    /// Applies one report from `source` and returns what to announce.
    ///
    /// Reports with `present: None` are removals (as sent by the discovery
    /// services). A removal only becomes a removal of the merged entry once
    /// no source reports the endpoint any more.
    pub fn update(&mut self, source: Source, info: EndpointInfo) -> Option<EndpointInfo> {
        if info.present.is_none() {
            let key = self.keys.remove(&(source, info.id))?;
            let entry = self.entries.get_mut(&key)?;
            *entry.slot(source) = None;
            if entry.mdns.is_none() && entry.ble.is_none() {
                let id = self.entries.remove(&key)?.id;
                return Some(EndpointInfo {
                    id,
                    ..Default::default()
                });
            }
            return Some(entry.merged());
        }

        let key = merge_key(source, &info);
        // A source may re-report the endpoint under a new id (e.g. a new port).
        self.keys.retain(|(s, _), k| !(*s == source && *k == key));
        self.keys.insert((source, info.id.clone()), key.clone());

        let entry = self.entries.entry(key).or_insert_with(|| Entry {
            id: info.id.clone(),
            ..Default::default()
        });
        *entry.slot(source) = Some(info);
        Some(entry.merged())
    }
}

/// Forwards the reports of each medium's discovery to `out`, merged.
pub(crate) async fn forward(
    mut mdns: Receiver<EndpointInfo>,
    mut ble: Receiver<EndpointInfo>,
    out: Sender<EndpointInfo>,
    ctk: CancellationToken,
) {
    let mut merger = EndpointMerger::default();
    let (mut mdns_open, mut ble_open) = (true, true);

    while mdns_open || ble_open {
        let (source, report) = tokio::select! {
            _ = ctk.cancelled() => break,
            r = mdns.recv(), if mdns_open => (Source::Mdns, r),
            r = ble.recv(), if ble_open => (Source::Ble, r),
        };
        match report {
            Ok(info) => {
                if let Some(merged) = merger.update(source, info) {
                    let _ = out.send(merged);
                }
            }
            Err(RecvError::Lagged(n)) => warn!("EndpointMerger: missed {n} {source:?} reports"),
            Err(RecvError::Closed) => match source {
                Source::Mdns => mdns_open = false,
                Source::Ble => ble_open = false,
            },
        }
    }
}

fn merge_key(source: Source, info: &EndpointInfo) -> String {
    match nearby_endpoint_id(source, info) {
        Some(endpoint_id) => format!("endpoint:{endpoint_id}"),
        None => format!("{source:?}:{}", info.id),
    }
}

/// The Nearby endpoint id: BLE discovery reports it as `fullname`; mDNS
/// encodes it in the service instance name, which is base64url of
/// `[PCP][endpoint id (4)][service id hash (3)][reserved (2)]`.
fn nearby_endpoint_id(source: Source, info: &EndpointInfo) -> Option<String> {
    match source {
        Source::Ble => Some(info.fullname.clone()).filter(|id| !id.is_empty()),
        Source::Mdns => {
            let instance = info.fullname.split('.').next()?;
            let bytes = URL_SAFE_NO_PAD.decode(instance).ok()?;
            (bytes.len() >= 5).then(|| String::from_utf8(bytes[1..5].to_vec()).ok())?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceType;

    fn mdns(port: &str) -> EndpointInfo {
        EndpointInfo {
            // base64url of 23 "LJC3" fc9f5e 0000
            fullname: "I0xKQzP8n14AAA._FC9F5ED42C8A._tcp.local.".into(),
            id: format!("192.168.1.20:{port}"),
            name: Some("Phone".into()),
            ip: Some("192.168.1.20".into()),
            port: Some(port.into()),
            rtype: Some(DeviceType::Phone),
            present: Some(true),
            bluetooth_address: None,
        }
    }

    fn ble() -> EndpointInfo {
        EndpointInfo {
            fullname: "LJC3".into(),
            id: "02:00:00:00:00:01".into(),
            name: Some("Phone".into()),
            rtype: Some(DeviceType::Phone),
            present: Some(true),
            bluetooth_address: Some("02:00:00:00:00:01".into()),
            ..Default::default()
        }
    }

    fn removal(id: &str) -> EndpointInfo {
        EndpointInfo {
            id: id.into(),
            ..Default::default()
        }
    }

    #[test]
    fn extracts_endpoint_id_from_mdns_name() {
        assert_eq!(
            nearby_endpoint_id(Source::Mdns, &mdns("1")).as_deref(),
            Some("LJC3")
        );
    }

    #[test]
    fn merges_mdns_and_ble_under_first_id() {
        let mut m = EndpointMerger::default();
        let first = m.update(Source::Mdns, mdns("4000")).unwrap();
        assert_eq!(first.id, "192.168.1.20:4000");
        assert_eq!(first.send_address().as_deref(), Some("192.168.1.20:4000"));

        let merged = m.update(Source::Ble, ble()).unwrap();
        assert_eq!(merged.id, "192.168.1.20:4000");
        assert_eq!(
            merged.bluetooth_address.as_deref(),
            Some("02:00:00:00:00:01")
        );
        // Wi-Fi LAN is preferred while both are known.
        assert_eq!(merged.send_address().as_deref(), Some("192.168.1.20:4000"));

        // Leaves the LAN: still reachable over Bluetooth, same id.
        let ble_only = m
            .update(Source::Mdns, removal("192.168.1.20:4000"))
            .unwrap();
        assert_eq!(ble_only.id, "192.168.1.20:4000");
        assert_eq!(ble_only.present, Some(true));
        assert_eq!(
            ble_only.send_address().as_deref(),
            Some("02:00:00:00:00:01")
        );

        // Gone everywhere.
        let gone = m.update(Source::Ble, removal("02:00:00:00:00:01")).unwrap();
        assert_eq!(
            (gone.id.as_str(), gone.present),
            ("192.168.1.20:4000", None)
        );
    }

    #[test]
    fn ble_first_keeps_bluetooth_id() {
        let mut m = EndpointMerger::default();
        assert_eq!(
            m.update(Source::Ble, ble()).unwrap().id,
            "02:00:00:00:00:01"
        );
        let merged = m.update(Source::Mdns, mdns("4000")).unwrap();
        assert_eq!(merged.id, "02:00:00:00:00:01");
        assert_eq!(merged.ip.as_deref(), Some("192.168.1.20"));
    }

    #[test]
    fn re_reported_mdns_id_replaces_old_one() {
        let mut m = EndpointMerger::default();
        m.update(Source::Mdns, mdns("4000"));
        m.update(Source::Mdns, mdns("5000"));
        // The stale id no longer maps to the entry...
        assert!(
            m.update(Source::Mdns, removal("192.168.1.20:4000"))
                .is_none()
        );
        // ...the new one does.
        let gone = m
            .update(Source::Mdns, removal("192.168.1.20:5000"))
            .unwrap();
        assert_eq!(gone.present, None);
    }

    #[test]
    fn unknown_names_are_not_merged() {
        let mut m = EndpointMerger::default();
        let mut other = mdns("4000");
        other.fullname = "not-base64!.local.".into();
        assert_eq!(
            m.update(Source::Mdns, other).unwrap().id,
            "192.168.1.20:4000"
        );
        assert_eq!(
            m.update(Source::Ble, ble()).unwrap().id,
            "02:00:00:00:00:01"
        );
        assert!(m.update(Source::Mdns, removal("unknown")).is_none());
    }
}
