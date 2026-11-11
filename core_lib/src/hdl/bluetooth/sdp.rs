//! Minimal SDP client: resolves the RFCOMM channel a remote device publishes
//! for a service UUID.
//!
//! BlueZ only exposes SDP lookups through `Device1.ConnectProfile`, which
//! requires bluetoothd to already know the device (paired or discovered).
//! Quick Share peers are usually neither: their classic MAC address arrives
//! out of band (inside a BLE advertisement), and phones are not discoverable
//! over BR/EDR. So, like Android's `createInsecureRfcommSocketToServiceRecord`,
//! we query the remote SDP server ourselves over L2CAP PSM 1.
//!
//! Reference: Bluetooth Core Specification, Vol 3, Part B (Service Discovery
//! Protocol), sections 3 (data elements) and 4.7 (ServiceSearchAttribute).

use anyhow::{anyhow, bail, ensure};
use bluer::Address;
use uuid::Uuid;

const SDP_PSM: u16 = 0x0001;

const PDU_ERROR_RESPONSE: u8 = 0x01;
const PDU_SERVICE_SEARCH_ATTR_REQUEST: u8 = 0x06;
const PDU_SERVICE_SEARCH_ATTR_RESPONSE: u8 = 0x07;

const ATTR_PROTOCOL_DESCRIPTOR_LIST: u16 = 0x0004;
const RFCOMM_PROTOCOL_UUID16: u16 = 0x0003;

/// Upper bound for attribute bytes per response; keeps each response within
/// the default SDP L2CAP MTU (672) so a single `recv` gets the whole PDU.
const MAX_ATTRIBUTE_BYTES: u16 = 512;
/// The continuation state is at most 16 bytes; guard against a server that
/// never stops sending continuations.
const MAX_CONTINUATIONS: usize = 64;

/// Queries `addr`'s SDP server for `service` and returns its RFCOMM channel.
pub async fn find_rfcomm_channel(addr: Address, service: Uuid) -> Result<u8, anyhow::Error> {
    let socket = super::socket::l2cap_seq_packet(addr, SDP_PSM).await?;
    let mut buf = vec![0u8; socket.recv_mtu()?.max(1024)];

    let mut attribute_lists = Vec::new();
    let mut continuation = Vec::new();
    for tid in 0..MAX_CONTINUATIONS as u16 {
        socket
            .send(&build_request(tid, service, &continuation))
            .await?;
        let n = socket.recv(&mut buf).await?;
        let (bytes, next) = parse_response(&buf[..n], tid)?;
        attribute_lists.extend_from_slice(bytes);

        if next.is_empty() {
            return rfcomm_channel(&attribute_lists)?
                .ok_or_else(|| anyhow!("{addr} has no RFCOMM channel for {service}"));
        }
        continuation = next.to_vec();
    }

    bail!("SDP response from {addr} did not terminate")
}

/// Builds a ServiceSearchAttributeRequest for the ProtocolDescriptorList of
/// records containing `service`.
fn build_request(tid: u16, service: Uuid, continuation: &[u8]) -> Vec<u8> {
    let mut params = Vec::with_capacity(32);
    // ServiceSearchPattern: DES { UUID128 }
    params.extend_from_slice(&[0x35, 17, 0x1c]);
    params.extend_from_slice(service.as_bytes());
    params.extend_from_slice(&MAX_ATTRIBUTE_BYTES.to_be_bytes());
    // AttributeIDList: DES { uint16 }
    params.extend_from_slice(&[0x35, 3, 0x09]);
    params.extend_from_slice(&ATTR_PROTOCOL_DESCRIPTOR_LIST.to_be_bytes());
    params.push(continuation.len() as u8);
    params.extend_from_slice(continuation);

    let mut pdu = Vec::with_capacity(5 + params.len());
    pdu.push(PDU_SERVICE_SEARCH_ATTR_REQUEST);
    pdu.extend_from_slice(&tid.to_be_bytes());
    pdu.extend_from_slice(&(params.len() as u16).to_be_bytes());
    pdu.extend_from_slice(&params);
    pdu
}

/// Splits a ServiceSearchAttributeResponse into its (partial) attribute list
/// bytes and the continuation state (empty when this was the last response).
fn parse_response(pdu: &[u8], expected_tid: u16) -> Result<(&[u8], &[u8]), anyhow::Error> {
    ensure!(pdu.len() >= 5, "SDP PDU too short");
    let tid = u16::from_be_bytes([pdu[1], pdu[2]]);
    let param_len = u16::from_be_bytes([pdu[3], pdu[4]]) as usize;
    let params = pdu
        .get(5..5 + param_len)
        .ok_or_else(|| anyhow!("SDP PDU truncated"))?;
    ensure!(tid == expected_tid, "SDP transaction id mismatch");

    match pdu[0] {
        PDU_SERVICE_SEARCH_ATTR_RESPONSE => {}
        PDU_ERROR_RESPONSE => {
            let code = params.get(..2).map(|c| u16::from_be_bytes([c[0], c[1]]));
            bail!("SDP error response: {code:?}");
        }
        other => bail!("unexpected SDP PDU 0x{other:02x}"),
    }

    ensure!(params.len() >= 2, "SDP response too short");
    let count = u16::from_be_bytes([params[0], params[1]]) as usize;
    let lists = params
        .get(2..2 + count)
        .ok_or_else(|| anyhow!("SDP attribute lists truncated"))?;
    let rest = &params[2 + count..];
    let cont_len = *rest
        .first()
        .ok_or_else(|| anyhow!("missing continuation"))? as usize;
    ensure!(cont_len <= 16, "invalid SDP continuation length");
    let cont = rest
        .get(1..1 + cont_len)
        .ok_or_else(|| anyhow!("SDP continuation truncated"))?;

    Ok((lists, cont))
}

/// Finds the RFCOMM channel in the AttributeLists of a complete response.
fn rfcomm_channel(attribute_lists: &[u8]) -> Result<Option<u8>, anyhow::Error> {
    let (lists, _) = DataElement::parse(attribute_lists)?;

    for record in lists.items() {
        let attrs = record.items();
        for pair in attrs.chunks_exact(2) {
            if !matches!(pair[0], DataElement::Uint(id) if id == ATTR_PROTOCOL_DESCRIPTOR_LIST as u128)
            {
                continue;
            }
            // A plain list of protocol descriptors, or an alternative of such lists.
            let stacks: Vec<&DataElement> = match &pair[1] {
                DataElement::Alt(alts) => alts.iter().collect(),
                other => vec![other],
            };
            for stack in stacks {
                for proto in stack.items() {
                    if let [DataElement::Uuid(uuid), DataElement::Uint(channel), ..] = proto.items()
                    {
                        if *uuid == uuid16(RFCOMM_PROTOCOL_UUID16) {
                            return Ok(Some(u8::try_from(*channel)?));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
}

fn uuid16(short: u16) -> Uuid {
    uuid32(short as u32)
}

fn uuid32(short: u32) -> Uuid {
    // Bluetooth Base UUID: 00000000-0000-1000-8000-00805F9B34FB
    Uuid::from_u128(((short as u128) << 96) | 0x0000_0000_0000_1000_8000_0080_5f9b_34fb)
}

#[derive(Debug, PartialEq)]
enum DataElement {
    Nil,
    Uint(u128),
    Int(i128),
    Uuid(Uuid),
    Bool(bool),
    Bytes(Vec<u8>),
    Seq(Vec<DataElement>),
    Alt(Vec<DataElement>),
}

impl DataElement {
    fn items(&self) -> &[DataElement] {
        match self {
            DataElement::Seq(items) | DataElement::Alt(items) => items,
            _ => &[],
        }
    }

    /// Parses one data element; returns it and the number of bytes consumed.
    fn parse(buf: &[u8]) -> Result<(Self, usize), anyhow::Error> {
        let header = *buf.first().ok_or_else(|| anyhow!("empty data element"))?;
        let kind = header >> 3;
        let size_index = header & 0x07;

        let (len, offset) = match size_index {
            0..=4 if kind == 0 => (0, 1),
            0..=4 => (1usize << size_index, 1),
            5 => (
                *buf.get(1).ok_or_else(|| anyhow!("truncated length"))? as usize,
                2,
            ),
            6 => {
                let b = buf.get(1..3).ok_or_else(|| anyhow!("truncated length"))?;
                (u16::from_be_bytes([b[0], b[1]]) as usize, 3)
            }
            _ => {
                let b = buf.get(1..5).ok_or_else(|| anyhow!("truncated length"))?;
                (u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize, 5)
            }
        };
        let body = buf
            .get(offset..offset + len)
            .ok_or_else(|| anyhow!("truncated data element"))?;

        let fixed = |n: usize| -> Result<[u8; 16], anyhow::Error> {
            ensure!(
                size_index <= 4 && body.len() == n,
                "invalid fixed-size element"
            );
            let mut out = [0u8; 16];
            out[16 - n..].copy_from_slice(body);
            Ok(out)
        };

        let element = match kind {
            0 => DataElement::Nil,
            1 => DataElement::Uint(u128::from_be_bytes(fixed(len)?)),
            2 => {
                let shift = 128 - 8 * len as u32;
                DataElement::Int((i128::from_be_bytes(fixed(len)?) << shift) >> shift)
            }
            3 => DataElement::Uuid(match len {
                2 => uuid16(u16::from_be_bytes([body[0], body[1]])),
                4 => uuid32(u32::from_be_bytes([body[0], body[1], body[2], body[3]])),
                16 => Uuid::from_slice(body)?,
                _ => bail!("invalid UUID size {len}"),
            }),
            4 | 8 => DataElement::Bytes(body.to_vec()),
            5 => DataElement::Bool(body.first().is_some_and(|b| *b != 0)),
            6 | 7 => {
                let mut items = Vec::new();
                let mut pos = 0;
                while pos < body.len() {
                    let (item, used) = Self::parse(&body[pos..])?;
                    items.push(item);
                    pos += used;
                }
                if kind == 6 {
                    DataElement::Seq(items)
                } else {
                    DataElement::Alt(items)
                }
            }
            _ => bail!("unknown data element type {kind}"),
        };

        Ok((element, offset + len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE: Uuid = Uuid::from_u128(0xa82efa21_ae5c_3dde_9bbc_f16da7b16c5a);

    /// AttributeLists for one record whose ProtocolDescriptorList is
    /// { { L2CAP }, { RFCOMM, channel } }, as Android and BlueZ publish it.
    fn attribute_lists(channel: u8) -> Vec<u8> {
        let protocols = [
            &[0x35, 0x03, 0x19, 0x01, 0x00][..], // DES { UUID16 L2CAP }
            &[0x35, 0x05, 0x19, 0x00, 0x03, 0x08, channel], // DES { UUID16 RFCOMM, uint8 }
        ]
        .concat();
        let mut attr = vec![0x09, 0x00, 0x04, 0x35, protocols.len() as u8];
        attr.extend(protocols);
        let mut record = vec![0x35, attr.len() as u8];
        record.extend(attr);
        let mut lists = vec![0x35, record.len() as u8];
        lists.extend(record);
        lists
    }

    fn response(tid: u16, lists: &[u8], continuation: &[u8]) -> Vec<u8> {
        let mut params = (lists.len() as u16).to_be_bytes().to_vec();
        params.extend_from_slice(lists);
        params.push(continuation.len() as u8);
        params.extend_from_slice(continuation);
        let mut pdu = vec![PDU_SERVICE_SEARCH_ATTR_RESPONSE];
        pdu.extend_from_slice(&tid.to_be_bytes());
        pdu.extend_from_slice(&(params.len() as u16).to_be_bytes());
        pdu.extend(params);
        pdu
    }

    #[test]
    fn request_layout() {
        let req = build_request(0x0102, SERVICE, &[0xaa, 0xbb]);
        let mut expected = vec![0x06, 0x01, 0x02, 0x00, 29, 0x35, 0x11, 0x1c];
        expected.extend_from_slice(SERVICE.as_bytes());
        expected.extend_from_slice(&[0x02, 0x00, 0x35, 0x03, 0x09, 0x00, 0x04, 0x02, 0xaa, 0xbb]);
        assert_eq!(req, expected);
    }

    #[test]
    fn finds_rfcomm_channel() {
        assert_eq!(rfcomm_channel(&attribute_lists(17)).unwrap(), Some(17));
    }

    #[test]
    fn reassembles_continued_responses() {
        let full = attribute_lists(5);
        let (a, b) = full.split_at(4);

        let first = response(0, a, &[0x01, 0x02]);
        let (bytes, cont) = parse_response(&first, 0).unwrap();
        assert_eq!((bytes, cont), (a, &[0x01, 0x02][..]));

        let second = response(1, b, &[]);
        let (bytes2, cont2) = parse_response(&second, 1).unwrap();
        assert!(cont2.is_empty());

        assert_eq!(rfcomm_channel(&[bytes, bytes2].concat()).unwrap(), Some(5));
    }

    #[test]
    fn no_record_means_no_channel() {
        // Empty AttributeLists: DES {}
        assert_eq!(rfcomm_channel(&[0x35, 0x00]).unwrap(), None);
    }

    #[test]
    fn record_without_rfcomm_means_no_channel() {
        // ProtocolDescriptorList with only L2CAP (e.g. an L2CAP-only service)
        let lists = [
            0x35, 0x0a, 0x35, 0x08, 0x09, 0x00, 0x04, 0x35, 0x03, 0x19, 0x01, 0x00,
        ];
        assert_eq!(rfcomm_channel(&lists).unwrap(), None);
    }

    #[test]
    fn rejects_error_and_mismatched_responses() {
        let err = [PDU_ERROR_RESPONSE, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02];
        assert!(parse_response(&err, 0).is_err());
        assert!(parse_response(&response(1, &[0x35, 0x00], &[]), 0).is_err());
        assert!(parse_response(&[0x07, 0x00], 0).is_err());
    }

    #[test]
    fn parses_mixed_elements() {
        // DES { uint32 0x01020304, int8 -2, UUID32 0x0000110a, bool, text "hi", alt { nil } }
        let bytes = [
            0x35, 0x15, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x10, 0xfe, 0x1a, 0x00, 0x00, 0x11, 0x0a,
            0x28, 0x01, 0x25, 0x02, b'h', b'i', 0x3d, 0x01, 0x00,
        ];
        let (el, used) = DataElement::parse(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(
            el,
            DataElement::Seq(vec![
                DataElement::Uint(0x01020304),
                DataElement::Int(-2),
                DataElement::Uuid(uuid16(0x110a)),
                DataElement::Bool(true),
                DataElement::Bytes(b"hi".to_vec()),
                DataElement::Alt(vec![DataElement::Nil]),
            ])
        );
    }
}
