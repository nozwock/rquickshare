//! Parsing of Nearby Connections BLE advertisements (service data under
//! 16-bit UUID 0xFEF3), following google/nearby
//! `connections/implementation/mediums/ble/ble_advertisement{,_header}.cc`
//! and `connections/implementation/ble_advertisement.cc`.
//!
//! A Quick Share receiver that is visible to everyone publishes three things:
//!
//! - a 17-byte *header* (base64 text in legacy advertising) announcing that
//!   the full advertisement is available over GATT (and possibly via BLE 5
//!   extended advertising);
//! - the full *regular* advertisement, which wraps the connections-level
//!   advertisement carrying the endpoint id, endpoint info and the
//!   Bluetooth Classic MAC address;
//! - while hidden / contacts-only, a *fast* advertisement instead: endpoint id
//!   and a name-less endpoint info, but no MAC address.

use anyhow::{anyhow, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

/// BLE medium advertisement flags (byte 0).
const MEDIUM_VERSION_V2: u8 = 2;
const MEDIUM_SOCKET_VERSION_V2: u8 = 2;
const MEDIUM_FAST_FLAG: u8 = 0x02;
/// Connections-level advertisement byte 0: version (3 bits) | PCP (5 bits).
const CONNECTIONS_VERSION_V1: u8 = 1;
const PCP_P2P_POINT_TO_POINT: u8 = 3;

const SERVICE_ID_HASH_LEN: usize = 3;
const ENDPOINT_ID_LEN: usize = 4;
const HEADER_LEN: usize = 17;
const HEADER_ADV_HASH: std::ops::Range<usize> = 11..15;

pub fn service_id_hash(service_id: &str) -> [u8; SERVICE_ID_HASH_LEN] {
    let digest = Sha256::digest(service_id.as_bytes());
    [digest[0], digest[1], digest[2]]
}

/// What a 0xFEF3 service data blob turned out to be.
#[derive(Debug, PartialEq)]
pub enum ServiceData {
    /// Full advertisement is published over GATT; `adv_hash` changes whenever
    /// its contents do, so it can be used as a cache key.
    Header { adv_hash: [u8; 4] },
    /// Full regular advertisement (e.g. received via extended advertising).
    Regular(NearbyAdvertisement),
    /// Fast advertisement: has no Bluetooth address, so it cannot be reached
    /// over RFCOMM.
    Fast(NearbyAdvertisement),
}

#[derive(Debug, Clone, PartialEq)]
pub struct NearbyAdvertisement {
    pub endpoint_id: String,
    pub endpoint_info: Vec<u8>,
    /// Bluetooth Classic address in display order (`AA:BB:..` -> `[0xAA, 0xBB, ..]`).
    pub bluetooth_address: Option<[u8; 6]>,
}

/// Classifies and parses one 0xFEF3 service data blob for `service_id`.
pub fn parse_service_data(data: &[u8], service_id: &str) -> Result<ServiceData, anyhow::Error> {
    if let Some(header) = decode_header(data) {
        return Ok(ServiceData::Header {
            adv_hash: header[HEADER_ADV_HASH].try_into()?,
        });
    }

    let flags = *data.first().ok_or_else(|| anyhow!("empty service data"))?;
    ensure!(
        flags >> 5 == MEDIUM_VERSION_V2,
        "unsupported BLE advertisement version"
    );
    if flags & MEDIUM_FAST_FLAG != 0 {
        let len = *data
            .get(1)
            .ok_or_else(|| anyhow!("truncated fast advertisement"))? as usize;
        let body = data
            .get(2..2 + len)
            .ok_or_else(|| anyhow!("truncated fast advertisement"))?;
        Ok(ServiceData::Fast(parse_connections(body, None)?))
    } else {
        Ok(ServiceData::Regular(parse_regular(data, service_id)?))
    }
}

/// Parses a full regular advertisement, as read from the GATT characteristic.
pub fn parse_regular(data: &[u8], service_id: &str) -> Result<NearbyAdvertisement, anyhow::Error> {
    let hash = service_id_hash(service_id);
    ensure!(data.len() >= 8, "regular advertisement too short");
    ensure!(
        data[0] >> 5 == MEDIUM_VERSION_V2,
        "unsupported BLE advertisement version"
    );
    ensure!(
        data[0] & MEDIUM_FAST_FLAG == 0,
        "not a regular advertisement"
    );
    ensure!(data[1..4] == hash, "advertisement is for another service");

    let len = u32::from_be_bytes(data[4..8].try_into()?) as usize;
    let body = data
        .get(8..8 + len)
        .ok_or_else(|| anyhow!("truncated regular advertisement"))?;
    parse_connections(body, Some(&hash))
}

/// Builds a regular advertisement (the inverse of [`parse_regular`]) for an
/// endpoint reachable over Bluetooth Classic at `bluetooth_address`.
pub fn build_regular(
    service_id: &str,
    endpoint_id: [u8; ENDPOINT_ID_LEN],
    endpoint_info: &[u8],
    bluetooth_address: [u8; 6],
    device_token: [u8; 2],
) -> Result<Vec<u8>, anyhow::Error> {
    let hash = service_id_hash(service_id);

    let mut connections = Vec::with_capacity(17 + endpoint_info.len());
    connections.push((CONNECTIONS_VERSION_V1 << 5) | PCP_P2P_POINT_TO_POINT);
    connections.extend_from_slice(&hash);
    connections.extend_from_slice(&endpoint_id);
    connections.push(u8::try_from(endpoint_info.len())?);
    connections.extend_from_slice(endpoint_info);
    connections.extend_from_slice(&bluetooth_address);
    connections.push(0); // no UWB address
    connections.push(0); // extra field: not WebRTC connectable

    let mut medium = Vec::with_capacity(10 + connections.len());
    medium.push((MEDIUM_VERSION_V2 << 5) | (MEDIUM_SOCKET_VERSION_V2 << 2));
    medium.extend_from_slice(&hash);
    medium.extend_from_slice(&u32::try_from(connections.len())?.to_be_bytes());
    medium.extend_from_slice(&connections);
    medium.extend_from_slice(&device_token);
    Ok(medium)
}

/// Length of the random service id mixed into a header to anonymise it.
const DUMMY_SERVICE_ID_LEN: usize = 128;
const BLOOM_FILTER_LEN: usize = 10;
const BLOOM_FILTER_HASHES: i32 = 5;

/// Builds the header advertised in place of a full advertisement that is too
/// long for legacy advertising (`Ble::CreateAdvertisementHeader`): one GATT
/// slot holding `gatt_advertisement`, no extended advertisement, no L2CAP
/// PSM. Returned as base64url text, the way Android publishes it.
pub fn build_header(service_id: &str, gatt_advertisement: &[u8]) -> String {
    let mut dummy = [0u8; DUMMY_SERVICE_ID_LEN];
    rand::Rng::fill(&mut rand::rng(), &mut dummy[..]);
    URL_SAFE_NO_PAD.encode(header_bytes(service_id, &dummy, gatt_advertisement))
}

fn header_bytes(service_id: &str, dummy_service_id: &[u8], gatt_advertisement: &[u8]) -> Vec<u8> {
    let mut bloom = [0u8; BLOOM_FILTER_LEN];
    bloom_add(&mut bloom, dummy_service_id);
    bloom_add(&mut bloom, service_id.as_bytes());

    let seed = Sha256::digest(dummy_service_id);
    let adv_hash = Sha256::new()
        .chain_update(&seed[..4])
        .chain_update(gatt_advertisement)
        .finalize();

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.push((MEDIUM_VERSION_V2 << 5) | 1); // not extended, 1 slot
    header.extend_from_slice(&bloom);
    header.extend_from_slice(&adv_hash[..4]);
    header.extend_from_slice(&[0, 0]); // PSM
    header
}

/// Bit positions of `s` in the header's service id bloom filter
/// (`mediums::BloomFilter`).
fn bloom_positions(s: &[u8]) -> impl Iterator<Item = usize> {
    let (h, _) = murmur3_x64_128(s, 0);
    let (hash1, hash2) = (h as i32, (h >> 32) as i32);
    (1..=BLOOM_FILTER_HASHES).map(move |i| {
        let combined = hash1.wrapping_add(i.wrapping_mul(hash2));
        let combined = if combined < 0 { !combined } else { combined };
        combined as usize % (BLOOM_FILTER_LEN * 8)
    })
}

fn bloom_add(filter: &mut [u8; BLOOM_FILTER_LEN], s: &[u8]) {
    for p in bloom_positions(s) {
        filter[p / 8] |= 1 << (p % 8);
    }
}

#[cfg(test)]
fn bloom_contains(filter: &[u8], s: &[u8]) -> bool {
    bloom_positions(s).all(|p| filter[p / 8] & (1 << (p % 8)) != 0)
}

/// MurmurHash3_x64_128; returns (h1, h2), i.e. (low, high) 64 bits.
fn murmur3_x64_128(data: &[u8], seed: u64) -> (u64, u64) {
    const C1: u64 = 0x87c3_7b91_1142_53d5;
    const C2: u64 = 0x4cf5_ad43_2745_937f;
    fn fmix(mut k: u64) -> u64 {
        k ^= k >> 33;
        k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
        k ^= k >> 33;
        k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        k ^ (k >> 33)
    }
    let mix_k1 = |k: u64| k.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
    let mix_k2 = |k: u64| k.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);

    let (mut h1, mut h2) = (seed, seed);
    let mut blocks = data.chunks_exact(16);
    for block in &mut blocks {
        let k1 = u64::from_le_bytes(block[..8].try_into().unwrap());
        let k2 = u64::from_le_bytes(block[8..].try_into().unwrap());
        h1 ^= mix_k1(k1);
        h1 = h1
            .rotate_left(27)
            .wrapping_add(h2)
            .wrapping_mul(5)
            .wrapping_add(0x52dc_e729);
        h2 ^= mix_k2(k2);
        h2 = h2
            .rotate_left(31)
            .wrapping_add(h1)
            .wrapping_mul(5)
            .wrapping_add(0x3849_5ab5);
    }

    let tail = blocks.remainder();
    let mut padded = [0u8; 16];
    padded[..tail.len()].copy_from_slice(tail);
    if tail.len() > 8 {
        h2 ^= mix_k2(u64::from_le_bytes(padded[8..].try_into().unwrap()));
    }
    if !tail.is_empty() {
        h1 ^= mix_k1(u64::from_le_bytes(padded[..8].try_into().unwrap()));
    }

    h1 ^= data.len() as u64;
    h2 ^= data.len() as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix(h1);
    h2 = fmix(h2);
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    (h1, h2)
}

/// Parses a connections-level advertisement. `service_hash` is `None` for
/// the fast variant, which carries neither a service hash nor an address.
fn parse_connections(
    data: &[u8],
    service_hash: Option<&[u8; SERVICE_ID_HASH_LEN]>,
) -> Result<NearbyAdvertisement, anyhow::Error> {
    let mut r = Reader(data);
    let head = r.byte()?;
    ensure!(
        head >> 5 == CONNECTIONS_VERSION_V1,
        "unsupported connections advertisement"
    );
    ensure!(
        head & 0x1f == PCP_P2P_POINT_TO_POINT,
        "not a P2P_POINT_TO_POINT advertisement"
    );

    if let Some(expected) = service_hash {
        ensure!(
            r.take(SERVICE_ID_HASH_LEN)? == expected,
            "advertisement is for another service"
        );
    }
    let endpoint_id = String::from_utf8(r.take(ENDPOINT_ID_LEN)?.to_vec())?;
    let info_len = r.byte()? as usize;
    let endpoint_info = r.take(info_len)?.to_vec();

    let bluetooth_address = match service_hash {
        Some(_) => {
            let mac: [u8; 6] = r.take(6)?.try_into()?;
            (mac != [0; 6]).then_some(mac)
        }
        None => None,
    };

    Ok(NearbyAdvertisement {
        endpoint_id,
        endpoint_info,
        bluetooth_address,
    })
}

/// The header is published as base64 text; decode it if `data` is one.
fn decode_header(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?.trim_end_matches('=');
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| STANDARD_NO_PAD.decode(text))
        .ok()?;
    (bytes.len() == HEADER_LEN && bytes[0] >> 5 == MEDIUM_VERSION_V2).then_some(bytes)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], anyhow::Error> {
        if self.0.len() < n {
            bail!("advertisement truncated");
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn byte(&mut self) -> Result<u8, anyhow::Error> {
        Ok(self.take(1)?[0])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceType;
    use crate::utils::parse_endpoint_info;

    const SERVICE_ID: &str = "NearbySharing";

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.replace(' ', "")).unwrap()
    }

    /// Layout of a GATT slot-0 value read from a Galaxy phone visible to
    /// everyone, with the name, address, salt and key hash replaced.
    fn regular() -> Vec<u8> {
        unhex(concat!(
            "48 fc9f5e 0000002f",                   // flags, service hash, length 47
            "23 fc9f5e 4c4a4333 1e",                // v1|PCP3, service hash, "LJC3", info len 30
            "22 0102 0303030303030303030303030303", // info: type byte, salt, key hash
            "09 5465737450686f6e65 020101",         // info: name "TestPhone", trailing fields
            "020000000001 00 00",                   // MAC, no UWB, extra field
            "d997 02 03 aabbcc",                    // device token, extra fields
        ))
    }

    #[test]
    fn service_hash_is_sha256_prefix() {
        assert_eq!(service_id_hash(SERVICE_ID), [0xfc, 0x9f, 0x5e]);
    }

    #[test]
    fn parses_regular_advertisement_with_mac() {
        let adv = parse_regular(&regular(), SERVICE_ID).unwrap();
        assert_eq!(adv.endpoint_id, "LJC3");
        assert_eq!(adv.endpoint_info.len(), 30);
        assert_eq!(adv.bluetooth_address, Some([0x02, 0, 0, 0, 0, 0x01]));

        let (device_type, name) = parse_endpoint_info(&adv.endpoint_info).unwrap();
        assert_eq!(device_type, DeviceType::Phone);
        assert_eq!(name.as_deref(), Some("TestPhone"));

        // The same bytes can also arrive directly as service data.
        assert_eq!(
            parse_service_data(&regular(), SERVICE_ID).unwrap(),
            ServiceData::Regular(adv)
        );
    }

    #[test]
    fn parses_base64_header() {
        // Captured header (legacy advertising, base64 text).
        let data = b"VSAACFACACADAQFQDlSFAAA";
        assert_eq!(
            parse_service_data(data, SERVICE_ID).unwrap(),
            ServiceData::Header {
                adv_hash: [0x50, 0x0e, 0x54, 0x85]
            }
        );
    }

    #[test]
    fn parses_fast_advertisement_without_mac() {
        // Captured fast advertisement of a contacts-only device.
        let data = unhex("4a17 2333565a4311 16e30e9baa895839c888768dee7a0a627f 20ad");
        let ServiceData::Fast(adv) = parse_service_data(&data, SERVICE_ID).unwrap() else {
            panic!("not fast");
        };
        assert_eq!(adv.endpoint_id, "3VZC");
        assert_eq!(adv.bluetooth_address, None);
        let (device_type, name) = parse_endpoint_info(&adv.endpoint_info).unwrap();
        assert_eq!((device_type, name), (DeviceType::Laptop, None));
    }

    #[test]
    fn rejects_other_services_and_garbage() {
        let mut other = regular();
        other[1] ^= 0xff;
        assert!(parse_regular(&other, SERVICE_ID).is_err());
        assert!(parse_service_data(&unhex("110171c43816"), SERVICE_ID).is_err());
        assert!(parse_service_data(&[], SERVICE_ID).is_err());
        assert!(parse_regular(&regular()[..20], SERVICE_ID).is_err());
    }

    #[test]
    fn built_advertisement_parses_back() {
        let info = crate::utils::gen_endpoint_info(DeviceType::Laptop as u8, "my-laptop");
        let mac = [0xe4, 0x0d, 0x36, 0x00, 0x00, 0x01];
        let built = build_regular(SERVICE_ID, *b"AB12", &info, mac, [0x12, 0x34]).unwrap();

        // Same framing as the captured phone advertisement.
        assert_eq!(&built[..4], &[0x48, 0xfc, 0x9f, 0x5e]);
        assert_eq!(&built[built.len() - 2..], &[0x12, 0x34]);

        let adv = parse_regular(&built, SERVICE_ID).unwrap();
        assert_eq!(adv.endpoint_id, "AB12");
        assert_eq!(adv.endpoint_info, info);
        assert_eq!(adv.bluetooth_address, Some(mac));
        let (device_type, name) = parse_endpoint_info(&adv.endpoint_info).unwrap();
        assert_eq!(
            (device_type, name.as_deref()),
            (DeviceType::Laptop, Some("my-laptop"))
        );
    }

    #[test]
    fn zero_mac_means_absent() {
        let mut data = regular();
        let mac_at = 8 + 1 + 3 + 4 + 1 + 30;
        data[mac_at..mac_at + 6].fill(0);
        assert_eq!(
            parse_regular(&data, SERVICE_ID).unwrap().bluetooth_address,
            None
        );
    }

    #[test]
    fn murmur3_matches_reference() {
        assert_eq!(murmur3_x64_128(b"", 0), (0, 0));
        // smhasher reference: "The quick brown fox jumps over the lazy dog".
        assert_eq!(
            murmur3_x64_128(b"The quick brown fox jumps over the lazy dog", 0),
            (0xe34bbc7bbc071b6c, 0x7a433ca9c49a9347)
        );
    }

    #[test]
    fn captured_header_bloom_contains_service_id() {
        let header = decode_header(b"VSAACFACACADAQFQDlSFAAA").unwrap();
        let bloom = &header[1..1 + BLOOM_FILTER_LEN];
        assert!(bloom_contains(bloom, SERVICE_ID.as_bytes()));
        assert!(!bloom_contains(bloom, b"SomeOtherService"));
    }

    #[test]
    fn built_header_parses_back() {
        let gatt = b"advertisement";
        let dummy = [7u8; DUMMY_SERVICE_ID_LEN];
        let bytes = header_bytes(SERVICE_ID, &dummy, gatt);
        assert_eq!(bytes.len(), HEADER_LEN);
        assert!(bloom_contains(&bytes[1..11], SERVICE_ID.as_bytes()));

        let text = build_header(SERVICE_ID, gatt);
        assert!(text.len() <= 27, "must fit in legacy advertising");
        assert!(matches!(
            parse_service_data(text.as_bytes(), SERVICE_ID).unwrap(),
            ServiceData::Header { .. }
        ));
    }
}
