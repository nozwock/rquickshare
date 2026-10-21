use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bytes::Bytes;
use hmac::{Hmac, Mac};
use libaes::{AES_256_KEY_LEN, Cipher};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{EncodedPoint, PublicKey};
use prost::Message;
use rand::Rng;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast::{Receiver, Sender};

use super::{InnerState, TransferState};
use crate::channel::{self, ChannelMessage, MessageClient, TransferAction, TransferKind};
use crate::hdl::TextPayloadInfo;
use crate::hdl::info::{InternalFileInfo, TransferMetadata, TransferPayload, TransferPayloadKind};
use crate::location_nearby_connections::payload_transfer_frame::{
    PacketType, PayloadChunk, PayloadHeader, payload_header,
};
use crate::location_nearby_connections::{KeepAliveFrame, OfflineFrame, PayloadTransferFrame};
use crate::securegcm::ukey2_alert::AlertType;
use crate::securegcm::{
    DeviceToDeviceMessage, GcmMetadata, Type, Ukey2Alert, Ukey2ClientFinished, Ukey2ClientInit,
    Ukey2HandshakeCipher, Ukey2Message, Ukey2ServerInit, ukey2_message,
};
use crate::securemessage::{
    EcP256PublicKey, EncScheme, GenericPublicKey, Header, HeaderAndBody, PublicKeyType,
    SecureMessage, SigScheme,
};
use crate::sharing_nearby::wifi_credentials_metadata::SecurityType;
use crate::sharing_nearby::{paired_key_result_frame, text_metadata};
use crate::utils::{
    DeviceType, RemoteDeviceInfo, encode_point, gen_ecdsa_keypair, gen_random, get_download_dir,
    hkdf_extract_expand, stream_read_exact, to_four_digit_string,
};
use crate::{location_nearby_connections, sharing_nearby};

type HmacSha256 = Hmac<Sha256>;

const SANE_FRAME_LENGTH: i32 = 5 * 1024 * 1024;
const SANITY_DURATION: Duration = Duration::from_micros(10);

#[cfg(test)]
mod dest_name_tests {
    use super::dest_file_name;

    #[test]
    fn fixes_generic_extension_from_mime() {
        // The observed case: a PDF sent as a .tmp cache file.
        assert_eq!(dest_file_name("cache123.tmp", "application/pdf"), "cache123.pdf");
        // No extension + a known MIME type → gains the right one.
        assert!(dest_file_name("noext", "application/pdf").ends_with(".pdf"));
        // A good, specific extension is left alone.
        assert_eq!(dest_file_name("photo.jpg", "image/jpeg"), "photo.jpg");
        assert_eq!(dest_file_name("real.pdf", "application/pdf"), "real.pdf");
        // Unknown/default MIME type → keep the sender's name untouched.
        assert_eq!(dest_file_name("data.tmp", "application/octet-stream"), "data.tmp");
    }
}

/// Pick the on-disk name for a received file: keep the sender's name, but if its
/// extension is missing or generic (e.g. a `.tmp` cache file), fix it from the
/// declared MIME type so e.g. a PDF sent as `cache123.tmp` lands as `cache123.pdf`.
fn dest_file_name(name: &str, mime_type: &str) -> String {
    let path = std::path::Path::new(name);
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());
    let generic = matches!(ext.as_deref(), None | Some("tmp") | Some("bin") | Some("dat"));
    if !generic || mime_type.is_empty() || mime_type == "application/octet-stream" {
        return name.to_string();
    }
    match mime_guess::get_mime_extensions_str(mime_type).and_then(|exts| exts.first()) {
        Some(good) => path.with_extension(good).to_string_lossy().into_owned(),
        None => name.to_string(),
    }
}

/// If `buf` begins with a complete `[len][OfflineFrame]` that is a bandwidth-upgrade
/// CLIENT_INTRODUCTION, returns the peer's endpoint_id. Used by the TCP server to
/// route an upgraded connection to its in-flight BLE session instead of treating it
/// as a fresh transfer. Returns None if not (yet) a client introduction.
pub fn peek_client_introduction(buf: &[u8]) -> Option<String> {
    use location_nearby_connections::bandwidth_upgrade_negotiation_frame::EventType;
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 || buf.len() < 4 + len {
        return None;
    }
    let frame = OfflineFrame::decode(&buf[4..4 + len]).ok()?;
    let v1 = frame.v1?;
    if v1.r#type() != location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeNegotiation {
        return None;
    }
    let bwu = v1.bandwidth_upgrade_negotiation?;
    if bwu.event_type() != EventType::ClientIntroduction {
        return None;
    }
    Some(bwu.client_introduction?.endpoint_id().to_string())
}

/// Read one length-prefixed `[4-byte len][frame]` message from a stream (plaintext).
#[cfg(all(feature = "experimental", target_os = "linux"))]
async fn read_frame_from<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>, anyhow::Error> {
    let mut len_buf = [0u8; 4];
    stream_read_exact(stream, &mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > SANE_FRAME_LENGTH as usize {
        return Err(anyhow!("bad frame length {len}"));
    }
    let mut data = vec![0u8; len];
    stream_read_exact(stream, &mut data).await?;
    Ok(data)
}

/// Write a length-prefixed `[4-byte len][frame]` message to a stream (plaintext).
#[cfg(all(feature = "experimental", target_os = "linux"))]
async fn send_frame_on<W: AsyncWrite + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> Result<(), anyhow::Error> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

#[derive(Debug)]
pub struct InboundRequest<S = TcpStream> {
    socket: S,
    pub state: InnerState,
    sender: Sender<ChannelMessage>,
    receiver: Receiver<ChannelMessage>,
    /// Set (BLE sessions) to enable offering a Wi-Fi bandwidth upgrade once the
    /// encrypted connection is established.
    bwu_tcp_port: Option<u16>,
    /// Set by the state machine when it's time to run the bandwidth-upgrade
    /// handoff; consumed by the BLE session loop (which owns a MigratableStream).
    bwu_pending: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> InboundRequest<S> {
    pub fn new(socket: S, id: String, sender: Sender<ChannelMessage>) -> Self {
        let receiver = sender.subscribe();

        Self {
            socket,
            state: InnerState {
                id,
                server_seq: 0,
                client_seq: 0,
                state: TransferState::Initial,
                encryption_done: true,
                ..Default::default()
            },
            sender,
            receiver,
            bwu_tcp_port: None,
            bwu_pending: false,
        }
    }

    /// Enable Wi-Fi bandwidth upgrade for this (BLE) session.
    pub fn set_bwu_tcp_port(&mut self, port: u16) {
        self.bwu_tcp_port = Some(port);
    }

    /// Consume the "run the bandwidth upgrade now" flag.
    pub fn take_bwu_pending(&mut self) -> bool {
        std::mem::take(&mut self.bwu_pending)
    }

    /// Build a BANDWIDTH_UPGRADE_NEGOTIATION OfflineFrame for the given event.
    fn bwu_frame(
        event_type: location_nearby_connections::bandwidth_upgrade_negotiation_frame::EventType,
        upgrade_path_info: Option<
            location_nearby_connections::bandwidth_upgrade_negotiation_frame::UpgradePathInfo,
        >,
        client_introduction: Option<
            location_nearby_connections::bandwidth_upgrade_negotiation_frame::ClientIntroduction,
        >,
    ) -> OfflineFrame {
        use location_nearby_connections::BandwidthUpgradeNegotiationFrame;
        OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeNegotiation
                        .into(),
                ),
                bandwidth_upgrade_negotiation: Some(BandwidthUpgradeNegotiationFrame {
                    event_type: Some(event_type.into()),
                    upgrade_path_info,
                    client_introduction,
                    client_introduction_ack: None,
                }),
                ..Default::default()
            }),
        }
    }

    /// Offer a Wi-Fi-LAN bandwidth upgrade: send an encrypted UPGRADE_PATH_AVAILABLE
    /// over the current (BLE) channel advertising our TCP ip:port.
    async fn send_upgrade_path_available(&mut self, port: u16) -> Result<(), anyhow::Error> {
        use location_nearby_connections::bandwidth_upgrade_negotiation_frame::{
            EventType, UpgradePathInfo,
            upgrade_path_info::{Medium, WifiLanSocket},
        };

        let ip = crate::utils::local_ipv4()
            .ok_or_else(|| anyhow!("no local IPv4 address for bandwidth upgrade"))?;
        info!(
            "BWU: offering WIFI_LAN upgrade at {}.{}.{}.{}:{port}",
            ip[0], ip[1], ip[2], ip[3]
        );

        let frame = Self::bwu_frame(
            EventType::UpgradePathAvailable,
            Some(UpgradePathInfo {
                medium: Some(Medium::WifiLan.into()),
                wifi_lan_socket: Some(WifiLanSocket {
                    ip_address: Some(ip.to_vec()),
                    wifi_port: Some(port as i32),
                }),
                supports_client_introduction_ack: Some(true),
                ..Default::default()
            }),
            None,
        );
        self.encrypt_and_send(&frame).await
    }

    /// Build a plaintext CLIENT_INTRODUCTION_ACK (sent over the new TCP channel).
    fn bwu_ack_frame() -> OfflineFrame {
        use location_nearby_connections::BandwidthUpgradeNegotiationFrame;
        use location_nearby_connections::bandwidth_upgrade_negotiation_frame::{
            ClientIntroductionAck, EventType,
        };
        OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeNegotiation
                        .into(),
                ),
                bandwidth_upgrade_negotiation: Some(BandwidthUpgradeNegotiationFrame {
                    event_type: Some(EventType::ClientIntroductionAck.into()),
                    client_introduction_ack: Some(ClientIntroductionAck {}),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        }
    }

    /// Read one encrypted frame from the current channel and return the decrypted
    /// OfflineFrame (advancing client_seq). Used to drain the BLE channel during a
    /// bandwidth upgrade without dispatching to the payload state machine.
    async fn read_encrypted_offline_frame(&mut self) -> Result<OfflineFrame, anyhow::Error> {
        let mut len_buf = [0u8; 4];
        stream_read_exact(&mut self.socket, &mut len_buf).await?;
        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > SANE_FRAME_LENGTH as usize {
            return Err(anyhow!("bad frame length {msg_len}"));
        }
        let mut data = vec![0u8; msg_len];
        stream_read_exact(&mut self.socket, &mut data).await?;

        let smsg = SecureMessage::decode(&*data)?;
        let mut hmac = HmacSha256::new_from_slice(self.state.recv_hmac_key.as_ref().unwrap())?;
        hmac.update(&smsg.header_and_body);
        if !hmac
            .finalize()
            .into_bytes()
            .as_slice()
            .eq(smsg.signature.as_slice())
        {
            return Err(anyhow!("hmac!=signature"));
        }
        let header_and_body = HeaderAndBody::decode(&*smsg.header_and_body)?;
        let key = self.state.decrypt_key.as_ref().unwrap();
        let mut cipher = Cipher::new_256(key[..AES_256_KEY_LEN].try_into()?);
        cipher.set_auto_padding(true);
        let decrypted = cipher.cbc_decrypt(header_and_body.header.iv(), &header_and_body.body);
        let d2d_msg = DeviceToDeviceMessage::decode(&*decrypted)?;

        let seq = self.get_client_seq_inc().await;
        if d2d_msg.sequence_number() != seq {
            return Err(anyhow!(
                "seq invalid ({} vs {})",
                d2d_msg.sequence_number(),
                seq
            ));
        }
        Ok(OfflineFrame::decode(d2d_msg.message())?)
    }

    pub async fn handle(&mut self) -> Result<(), anyhow::Error> {
        // Buffer for the 4-byte length
        let mut length_buf = [0u8; 4];

        tokio::select! {
            i = self.receiver.recv() => {
                match i {
                    Ok(channel_msg) => {
                        if channel_msg.id != self.state.id {
                            return Ok(());
                        }

                        if let channel::Message::Lib { action } = &channel_msg.msg {
                            debug!("inbound: got: {:?}", channel_msg);
                            match action {
                                TransferAction::ConsentAccept => {
                                    self.accept_transfer().await?;
                                },
                                TransferAction::ConsentDecline => {
                                    self.update_state(
                                        |e| {
                                            e.state = TransferState::Rejected;
                                        },
                                        true,
                                    ).await;

                                    self.reject_transfer(Some(
                                        sharing_nearby::connection_response_frame::Status::Reject
                                    )).await?;
                                    return Err(anyhow!(crate::errors::AppError::NotAnError));
                                },
                                TransferAction::TransferCancel => {
                                    self.update_state(
                                        |e| {
                                            e.state = TransferState::Cancelled;
                                        },
                                        true,
                                    ).await;
                                    self.disconnection().await?;
                                    return Err(anyhow!(crate::errors::AppError::NotAnError));
                                },
                            }
                        }

                    }
                    Err(e) => {
                        error!("inbound: channel error: {}", e);
                    }
                }
            },
            h = stream_read_exact(&mut self.socket, &mut length_buf) => {
                h?;

                self._handle(length_buf).await?
            }
        }

        Ok(())
    }

    pub async fn _handle(&mut self, length_buf: [u8; 4]) -> Result<(), anyhow::Error> {
        let msg_length = u32::from_be_bytes(length_buf) as usize;
        // Ensure the message length is not unreasonably big to avoid allocation attacks
        if msg_length > SANE_FRAME_LENGTH as usize {
            error!("Message length too big");
            return Err(anyhow!("value"));
        }

        // Allocate buffer for the actual message and read it
        let mut frame_data = vec![0u8; msg_length];
        stream_read_exact(&mut self.socket, &mut frame_data).await?;

        let current_state = &self.state;
        // Now determine what will be the request type based on current state
        match current_state.state {
            TransferState::Initial => {
                debug!("Handling State::Initial frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                let rdi = self.process_connection_request(&frame)?;
                info!("RemoteDeviceInfo: {:?}", &rdi);

                // Advance current state
                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::ReceivedConnectionRequest;
                        e.remote_device_info = Some(rdi);
                    },
                    false,
                )
                .await;
            }
            TransferState::ReceivedConnectionRequest => {
                debug!("Handling State::ReceivedConnectionRequest frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_init(&msg).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::SentUkeyServerInit;
                        e.client_init_msg_data = Some(frame_data);
                    },
                    false,
                )
                .await;
            }
            TransferState::SentUkeyServerInit => {
                debug!("Handling State::SentUkeyServerInit frame");
                let msg = Ukey2Message::decode(&*frame_data)?;
                self.process_ukey2_client_finish(&msg, &frame_data).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::ReceivedUkeyClientFinish;
                    },
                    false,
                )
                .await;
            }
            TransferState::ReceivedUkeyClientFinish => {
                debug!("Handling State::ReceivedUkeyClientFinish frame");
                let frame = location_nearby_connections::OfflineFrame::decode(&*frame_data)?;
                self.process_connection_response(&frame).await?;

                self.update_state(
                    |e: &mut InnerState| {
                        e.state = TransferState::SentConnectionResponse;
                    },
                    false,
                )
                .await;

                // The encrypted connection is up: flag a Wi-Fi bandwidth upgrade
                // (BLE sessions only). The BLE session loop runs the handoff.
                if self.bwu_tcp_port.is_some() {
                    self.bwu_pending = true;
                }
            }
            _ => {
                debug!("Handling SecureMessage frame");
                let smsg = SecureMessage::decode(&*frame_data)?;
                self.decrypt_and_process_secure_message(&smsg).await?;
            }
        }

        Ok(())
    }

    fn process_connection_request(
        &self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<RemoteDeviceInfo, anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionRequest
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let connection_request = v1_frame
            .connection_request
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let endpoint_info = connection_request
            .endpoint_info
            .as_ref()
            .ok_or_else(|| anyhow!("Missing endpoint info"))?;

        // Check if endpoint info length is greater than 17
        if endpoint_info.len() <= 17 {
            return Err(anyhow!("Endpoint info too short"));
        }

        let device_name_length = endpoint_info[17] as usize;
        // Validate length including device name
        if endpoint_info.len() < device_name_length + 18 {
            return Err(anyhow!(
                "Endpoint info too short to contain the device name"
            ));
        }

        // Extract and validate device name based on length
        let device_name = std::str::from_utf8(&endpoint_info[18..(18 + device_name_length)])
            .map_err(|_| anyhow!("Device name is not valid UTF-8"))?;

        // Parsing the device type
        let raw_device_type = (endpoint_info[0] & 7) >> 1_usize;

        Ok(RemoteDeviceInfo {
            name: device_name.to_string(),
            device_type: DeviceType::from_raw_value(raw_device_type),
        })
    }

    async fn process_ukey2_client_init(&mut self, msg: &Ukey2Message) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientInit {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientInit",
                msg.message_type
            ));
        }

        let client_init = match Ukey2ClientInit::decode(msg.message_data()) {
            Ok(uk2ci) => uk2ci,
            Err(e) => {
                self.send_ukey2_alert(AlertType::BadMessageData).await?;
                return Err(anyhow!("UKey2: Ukey2ClientInit::decode: {}", e));
            }
        };

        if client_init.version() != 1 {
            self.send_ukey2_alert(AlertType::BadVersion).await?;
            return Err(anyhow!("UKey2: client_init.version != 1"));
        }

        if client_init.random().len() != 32 {
            self.send_ukey2_alert(AlertType::BadRandom).await?;
            return Err(anyhow!("UKey2: client_init.random.len != 32"));
        }

        // Searching for preferred cipher commitment
        let mut found = false;
        for commitment in &client_init.cipher_commitments {
            trace!("CipherCommitment: {:?}", commitment.handshake_cipher());
            if Ukey2HandshakeCipher::P256Sha512 == commitment.handshake_cipher() {
                found = true;
                self.update_state(
                    |e| {
                        e.cipher_commitment = Some(commitment.clone());
                    },
                    false,
                )
                .await;
                break;
            }
        }

        if !found {
            self.send_ukey2_alert(AlertType::BadHandshakeCipher).await?;
            return Err(anyhow!("UKey2: badHandshakeCipher"));
        }

        if client_init.next_protocol() != "AES_256_CBC-HMAC_SHA256" {
            self.send_ukey2_alert(AlertType::BadNextProtocol).await?;
            return Err(anyhow!(
                "UKey2: badNextProtocol: {}",
                client_init.next_protocol()
            ));
        }

        let (secret_key, public_key) = gen_ecdsa_keypair();

        let encoded_point = public_key.to_encoded_point(false);
        let x = encoded_point.x().unwrap();
        let y = encoded_point.y().unwrap();

        let pkey = GenericPublicKey {
            r#type: PublicKeyType::EcP256.into(),
            ec_p256_public_key: Some(EcP256PublicKey {
                x: encode_point(Bytes::from(x.to_vec()))?,
                y: encode_point(Bytes::from(y.to_vec()))?,
            }),
            ..Default::default()
        };

        let server_init = Ukey2ServerInit {
            version: Some(1),
            random: Some(rand::rng().random::<[u8; 32]>().to_vec()),
            handshake_cipher: Some(Ukey2HandshakeCipher::P256Sha512.into()),
            public_key: Some(pkey.encode_to_vec()),
        };

        let server_init_msg = Ukey2Message {
            message_type: Some(ukey2_message::Type::ServerInit.into()),
            message_data: Some(server_init.encode_to_vec()),
        };

        let server_init_data = server_init_msg.encode_to_vec();
        self.update_state(
            |e| {
                e.private_key = Some(secret_key);
                e.public_key = Some(public_key);
                e.server_init_data = Some(server_init_data.clone());
            },
            false,
        )
        .await;

        self.send_frame(server_init_data).await?;

        Ok(())
    }

    async fn process_ukey2_client_finish(
        &mut self,
        msg: &Ukey2Message,
        frame_data: &Vec<u8>,
    ) -> Result<(), anyhow::Error> {
        if msg.message_type() != ukey2_message::Type::ClientFinish {
            self.send_ukey2_alert(AlertType::BadMessageType).await?;
            return Err(anyhow!(
                "UKey2: message_type({:?}) != ClientFinish",
                msg.message_type
            ));
        }

        let sha512 = Sha512::digest(frame_data);
        if self.state.cipher_commitment.as_ref().unwrap().commitment() != sha512.as_slice() {
            error!("cipher_commitment isn't equals to sha512(frame_data)");
            return Err(anyhow!("UKey2: cipher_commitment != sha512"));
        }

        let client_finish = match Ukey2ClientFinished::decode(msg.message_data()) {
            Ok(uk2cf) => uk2cf,
            Err(e) => {
                return Err(anyhow!("UKey2: Ukey2ClientFinished::decode: {}", e));
            }
        };

        if client_finish.public_key.is_none() {
            return Err(anyhow!("UKey2: client_finish.public_key None"));
        }

        let client_public_key = match GenericPublicKey::decode(client_finish.public_key()) {
            Ok(cpk) => cpk,
            Err(e) => {
                return Err(anyhow!("UKey2: GenericPublicKey::decode: {}", e));
            }
        };

        self.finalize_key_exchange(client_public_key).await?;

        Ok(())
    }

    async fn process_connection_response(
        &mut self,
        frame: &location_nearby_connections::OfflineFrame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        if v1_frame.r#type() != location_nearby_connections::v1_frame::FrameType::ConnectionResponse
        {
            return Err(anyhow!(format!(
                "Unexpected frame type: {:?}",
                v1_frame.r#type()
            )));
        }

        let response = location_nearby_connections::OfflineFrame {
			version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
			v1: Some(location_nearby_connections::V1Frame {
				r#type: Some(location_nearby_connections::v1_frame::FrameType::ConnectionResponse.into()),
				connection_response: Some(location_nearby_connections::ConnectionResponseFrame {
					response: Some(location_nearby_connections::connection_response_frame::ResponseStatus::Accept.into()),
					os_info: Some(location_nearby_connections::OsInfo {
						r#type: Some(location_nearby_connections::os_info::OsType::Linux.into())
					}),
					..Default::default()
				}),
				..Default::default()
			})
		};

        self.send_frame(response.encode_to_vec()).await?;

        let paired_encryption = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyEncryption.into()),
                paired_key_encryption: Some(sharing_nearby::PairedKeyEncryptionFrame {
                    secret_id_hash: Some(gen_random(6)),
                    signed_data: Some(gen_random(72)),
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_encryption).await?;

        Ok(())
    }

    async fn decrypt_and_process_secure_message(
        &mut self,
        smsg: &SecureMessage,
    ) -> Result<(), anyhow::Error> {
        let mut hmac = HmacSha256::new_from_slice(self.state.recv_hmac_key.as_ref().unwrap())?;
        hmac.update(&smsg.header_and_body);
        if !hmac
            .finalize()
            .into_bytes()
            .as_slice()
            .eq(smsg.signature.as_slice())
        {
            return Err(anyhow!("hmac!=signature"));
        }

        let header_and_body = HeaderAndBody::decode(&*smsg.header_and_body)?;

        let msg_data = header_and_body.body;
        let key = self.state.decrypt_key.as_ref().unwrap();

        let mut cipher = Cipher::new_256(key[..AES_256_KEY_LEN].try_into()?);
        cipher.set_auto_padding(true);
        let decrypted = cipher.cbc_decrypt(header_and_body.header.iv(), &msg_data);

        let d2d_msg = DeviceToDeviceMessage::decode(&*decrypted)?;

        let seq = self.get_client_seq_inc().await;
        if d2d_msg.sequence_number() != seq {
            return Err(anyhow!(
                "Error d2d_msg.sequence_number invalid ({} vs {})",
                d2d_msg.sequence_number(),
                seq
            ));
        }

        let offline = location_nearby_connections::OfflineFrame::decode(d2d_msg.message())?;
        self.process_offline_frame(offline).await
    }

    /// Dispatch a decrypted OfflineFrame (payload transfers, keep-alives, …).
    /// Factored out so the bandwidth-upgrade drain can process non-BWU frames the
    /// phone keeps sending over BLE while the upgrade completes.
    async fn process_offline_frame(
        &mut self,
        offline: OfflineFrame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = offline
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;
        match v1_frame.r#type() {
            location_nearby_connections::v1_frame::FrameType::PayloadTransfer => {
                trace!("Received FrameType::PayloadTransfer");
                let payload_transfer = v1_frame
                    .payload_transfer
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                let header = payload_transfer
                    .payload_header
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;
                let chunk = payload_transfer
                    .payload_chunk
                    .as_ref()
                    .ok_or_else(|| anyhow!("Missing required fields"))?;

                match header.r#type() {
                    payload_header::PayloadType::Bytes => {
                        info!("Processing PayloadType::Bytes");
                        let payload_id = header.id();

                        if header.total_size() > SANE_FRAME_LENGTH.into() {
                            self.state.payload_buffers.remove(&payload_id);
                            return Err(anyhow!(
                                "Payload too large: {} bytes",
                                header.total_size()
                            ));
                        }

                        self.state
                            .payload_buffers
                            .entry(payload_id)
                            .or_insert_with(|| Vec::with_capacity(header.total_size() as usize));

                        // Get the current length of the buffer, if it exists, without holding a mutable borrow.
                        let buffer_len = self.state.payload_buffers.get(&payload_id).unwrap().len();
                        if chunk.offset() != buffer_len as i64 {
                            self.state.payload_buffers.remove(&payload_id);
                            return Err(anyhow!(
                                "Unexpected chunk offset: {}, expected: {}",
                                chunk.offset(),
                                buffer_len
                            ));
                        }

                        let buffer = self.state.payload_buffers.get_mut(&payload_id).unwrap();
                        if let Some(body) = &chunk.body {
                            buffer.extend(body);
                        }

                        if (chunk.flags() & 1) == 1 {
                            debug!("Chunk flags & 1 == 1 ?? End of data ??");

                            if self.state.text_payload.is_some()
                                && self.state.text_payload.as_ref().unwrap().get_i64_value()
                                    == payload_id
                            {
                                info!("Transfer finished");

                                match self.state.text_payload.clone().unwrap() {
                                    TextPayloadInfo::Url(_) => {
                                        let payload = std::str::from_utf8(&buffer)?.to_owned();
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.payload =
                                                        Some(TransferPayload::Url(payload));
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                    TextPayloadInfo::Text(_) => {
                                        let payload = std::str::from_utf8(&buffer)?.to_owned();
                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.payload =
                                                        Some(TransferPayload::Text(payload));
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                    // FIXME: ChannelMessage's structure needs to be redone as well
                                    // It needs to have TextPayloadInfo instead of TextPayloadType
                                    TextPayloadInfo::Wifi((_, ssid, security_type)) => {
                                        // ~~Payload seems to be within two DLE (0x10) characters
                                        // At least for WpaPsk, not sure about Wep~~
                                        //
                                        // Nope, that's wrong, my Wi-Fi password just happened to have 16 characters
                                        // which tripped up the previous logic.
                                        //
                                        // So, the password seems to start with 0x0A followed by a byte indicating
                                        // the password or payload length. And, the payload ends with 0x10 0x??
                                        // The last byte is sometimes 00 and other times 01
                                        fn parse_password_payload(
                                            buffer: &mut Vec<u8>,
                                        ) -> anyhow::Result<String>
                                        {
                                            if buffer.len() < 4 {
                                                anyhow::bail!("Buffer too short ({buffer:?})");
                                            }

                                            if buffer[(buffer.len() - 1) - 1] != 0x10 {
                                                anyhow::bail!(
                                                    "Buffer ({buffer:?}) doesn't ends with 0x10 0x?? as expected"
                                                );
                                            }

                                            let len = *buffer
                                                .get(1)
                                                .expect("Validated for minimum length of 4")
                                                as usize;

                                            let payload_buffer = buffer.get(2..2 + len).with_context(||anyhow!( "Buffer too short ({buffer:?}) can't retrieve payload of length {len}"))?;

                                            Ok(String::from_utf8(payload_buffer.to_owned())?)
                                        }

                                        let payload = match security_type {
                                            kind @ SecurityType::UnknownSecurityType => {
                                                kind.as_str_name().into()
                                            }
                                            SecurityType::Open => "".into(),
                                            SecurityType::WpaPsk | SecurityType::Wep => {
                                                parse_password_payload(buffer)
                                                    .inspect_err(|err| error!("{err:#}"))
                                                    .unwrap_or_default()
                                            }
                                        };

                                        self.update_state(
                                            |e| {
                                                if let Some(tmd) = e.transfer_metadata.as_mut() {
                                                    tmd.payload = Some(TransferPayload::Wifi {
                                                        ssid,
                                                        password: payload,
                                                        security_type: security_type,
                                                    });
                                                }
                                            },
                                            false,
                                        )
                                        .await;
                                    }
                                }

                                self.update_state(
                                    |e| {
                                        e.state = TransferState::Finished;
                                    },
                                    true,
                                )
                                .await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            } else {
                                let inner_frame = sharing_nearby::Frame::decode(buffer.as_slice())?;
                                self.process_transfer_setup(&inner_frame).await?;
                            }
                        }
                    }
                    payload_header::PayloadType::File => {
                        info!("Processing PayloadType::File");
                        let payload_id = header.id();

                        let file_internal = self
                            .state
                            .transferred_files
                            .get_mut(&payload_id)
                            .ok_or_else(|| {
                                anyhow!("File payload ID ({}) is not known", payload_id)
                            })?;

                        let current_offset = file_internal.bytes_transferred;
                        if chunk.offset() != current_offset {
                            return Err(anyhow!(
                                "Invalid offset into file {}, expected {}",
                                chunk.offset(),
                                current_offset
                            ));
                        }

                        let chunk_size = chunk.body().len();
                        if current_offset + chunk_size as i64 > file_internal.total_size {
                            return Err(anyhow!(
                                "Transferred file size exceeds previously specified value: {} vs {}",
                                current_offset + chunk_size as i64,
                                file_internal.total_size
                            ));
                        }

                        if !chunk.body().is_empty() {
                            file_internal
                                .file
                                .as_ref()
                                .unwrap()
                                .write_all_at(chunk.body(), current_offset as u64)?;
                            file_internal.bytes_transferred += chunk_size as i64;

                            self.update_state(
                                |e| {
                                    if let Some(tmd) = e.transfer_metadata.as_mut() {
                                        tmd.ack_bytes += chunk_size as u64;
                                    }
                                },
                                true,
                            )
                            .await;
                        } else if (chunk.flags() & 1) == 1 {
                            self.state.transferred_files.remove(&payload_id);
                            if self.state.transferred_files.is_empty() {
                                info!("Transfer finished");
                                self.update_state(
                                    |e| {
                                        e.state = TransferState::Finished;
                                    },
                                    true,
                                )
                                .await;
                                self.disconnection().await?;
                                return Err(anyhow!(crate::errors::AppError::NotAnError));
                            }
                        }
                    }
                    payload_header::PayloadType::Stream => {
                        error!("Unhandled PayloadType::Stream: {:?}", header.r#type())
                    }
                    payload_header::PayloadType::UnknownPayloadType => {
                        error!(
                            "Invalid PayloadType::UnknownPayloadType: {:?}",
                            header.r#type()
                        )
                    }
                }
            }
            location_nearby_connections::v1_frame::FrameType::KeepAlive => {
                trace!("Sending keepalive");
                self.send_keepalive(true).await?;
            }
            _ => {
                error!("Unhandled offline frame encrypted: {:?}", offline);
            }
        }

        Ok(())
    }

    async fn process_transfer_setup(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let v1_frame = frame
            .v1
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        debug!(
            "process_transfer_setup: state={:?} inner frame type={:?}",
            self.state.state,
            v1_frame.r#type()
        );

        if v1_frame.r#type() == sharing_nearby::v1_frame::FrameType::Cancel {
            info!("Transfer canceled");
            self.update_state(
                |e| {
                    e.state = TransferState::Cancelled;
                },
                true,
            )
            .await;
            self.disconnection().await?;
            return Err(anyhow!(crate::errors::AppError::NotAnError));
        }

        match self.state.state {
            TransferState::SentConnectionResponse => {
                debug!("Processing State::SentConnectionResponse");
                self.process_paired_key_encryption_frame(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = TransferState::SentPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            TransferState::SentPairedKeyResult => {
                debug!("Processing State::SentPairedKeyResult");
                self.process_paired_key_result(v1_frame).await?;
                self.update_state(
                    |e| {
                        e.state = TransferState::ReceivedPairedKeyResult;
                    },
                    false,
                )
                .await;
            }
            TransferState::ReceivedPairedKeyResult => {
                debug!("Processing State::ReceivedPairedKeyResult");
                // Newer senders (Pixel) may interleave extra frames before the
                // introduction; wait for the actual introduction instead of erroring.
                if v1_frame.introduction.is_some() {
                    self.process_introduction(v1_frame).await?;
                } else {
                    debug!(
                        "Awaiting introduction; ignoring frame type={:?}",
                        v1_frame.r#type()
                    );
                }
            }
            _ => {
                info!(
                    "Unhandled connection state in process_transfer_setup: {:?}",
                    self.state.state
                );
            }
        }

        Ok(())
    }

    async fn process_paired_key_encryption_frame(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_encryption.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        let paired_result = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::PairedKeyResult.into()),
                paired_key_result: Some(sharing_nearby::PairedKeyResultFrame {
                    status: Some(paired_key_result_frame::Status::Unable.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&paired_result).await?;

        Ok(())
    }

    async fn process_paired_key_result(
        &self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        if v1_frame.paired_key_result.is_none() {
            return Err(anyhow!("Missing required fields"));
        }

        Ok(())
    }

    async fn process_introduction(
        &mut self,
        v1_frame: &sharing_nearby::V1Frame,
    ) -> Result<(), anyhow::Error> {
        let introduction = v1_frame
            .introduction
            .as_ref()
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        // No need to inform the channel here, we'll do it anyway with files info
        self.update_state(
            |e| {
                e.state = TransferState::WaitingForUserConsent;
            },
            false,
        )
        .await;

        if !introduction.file_metadata.is_empty() && introduction.text_metadata.is_empty() {
            trace!("process_introduction: handling file_metadata");
            let mut files_name = Vec::with_capacity(introduction.file_metadata.len());
            let mut total_bytes: u64 = 0;

            for file in &introduction.file_metadata {
                let resolved_name = dest_file_name(file.name(), file.mime_type());
                info!("File name: {} (as {})", file.name(), resolved_name);

                let mut dest = get_download_dir();
                dest.push(&resolved_name);

                info!("Destination: {:?}", dest);
                if dest.exists() {
                    let mut counter = 1;
                    dest.pop();

                    loop {
                        // How name conflict resolution happens in most software,
                        // lorem.txt
                        // lorem (1).txt
                        // ...
                        let incremented_file_path = {
                            let file_path = PathBuf::from(&resolved_name);

                            let incremented_file_stem = format!(
                                "{} ({counter})",
                                file_path
                                    .file_stem()
                                    .and_then(|it| it.to_str())
                                    .expect("Must be UTF-8 since Path is derived from String"),
                            );

                            let incremented_file_path =
                                file_path.with_file_name(incremented_file_stem);

                            file_path
                                .extension()
                                .map(|it| incremented_file_path.with_extension(it))
                                .unwrap_or_else(|| incremented_file_path)
                        };

                        dest.push(incremented_file_path);
                        if !dest.exists() {
                            break;
                        }
                        dest.pop();
                        counter += 1;
                    }

                    info!("New destination: {:?}", dest);
                }

                let info = InternalFileInfo {
                    payload_id: file.payload_id(),
                    file_url: dest,
                    bytes_transferred: 0,
                    total_size: file.size(),
                    file: None,
                };
                total_bytes += info.total_size as u64;
                self.state.transferred_files.insert(file.payload_id(), info);
                files_name.push(resolved_name.clone());
            }

            let metadata = TransferMetadata {
                id: self.state.id.clone(),
                source: self.state.remote_device_info.clone(),
                payload_kind: TransferPayloadKind::Files,
                payload_preview: Default::default(),
                payload: Some(TransferPayload::Files(files_name)),
                pin_code: self.state.pin_code.clone(),
                total_bytes,
                ack_bytes: Default::default(),
            };

            info!("Asking for user consent: {:?}", metadata);
            self.update_state(
                |e| {
                    e.transfer_metadata = Some(metadata);
                },
                true,
            )
            .await;
        } else if introduction.text_metadata.len() == 1 {
            trace!("process_introduction: handling text_metadata");
            let meta = introduction.text_metadata.first().unwrap();

            match meta.r#type() {
                text_metadata::Type::Url => {
                    let metadata = TransferMetadata {
                        id: self.state.id.clone(),
                        source: self.state.remote_device_info.clone(),
                        payload_kind: TransferPayloadKind::Url,
                        payload_preview: Some(meta.text_title.clone().unwrap_or_default()),
                        pin_code: self.state.pin_code.clone(),
                        payload: Default::default(),
                        total_bytes: Default::default(),
                        ack_bytes: Default::default(),
                    };

                    info!("Asking for user consent: {:?}", metadata);
                    self.update_state(
                        |e| {
                            e.text_payload = Some(TextPayloadInfo::Url(meta.payload_id()));
                            e.transfer_metadata = Some(metadata);
                        },
                        true,
                    )
                    .await;
                }
                text_metadata::Type::PhoneNumber
                | text_metadata::Type::Address
                | text_metadata::Type::Text => {
                    let metadata = TransferMetadata {
                        id: self.state.id.clone(),
                        source: self.state.remote_device_info.clone(),
                        payload_kind: TransferPayloadKind::Text,
                        payload_preview: Some(meta.text_title.clone().unwrap_or_default()),
                        pin_code: self.state.pin_code.clone(),
                        payload: Default::default(),
                        total_bytes: Default::default(),
                        ack_bytes: Default::default(),
                    };

                    info!("Asking for user consent: {:?}", metadata);
                    self.update_state(
                        |e| {
                            e.text_payload = Some(TextPayloadInfo::Text(meta.payload_id()));
                            e.transfer_metadata = Some(metadata);
                        },
                        true,
                    )
                    .await;
                }
                text_metadata::Type::Unknown => {
                    // Reject transfer
                    self.reject_transfer(Some(
						sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
					))
					.await?;
                }
            }
        } else if introduction.wifi_credentials_metadata.len() == 1 {
            trace!("process_introduction: handling wifi_credentials_metadata");
            let meta = introduction.wifi_credentials_metadata.first().unwrap();

            let metadata = TransferMetadata {
                id: self.state.id.clone(),
                source: self.state.remote_device_info.clone(),
                payload_kind: TransferPayloadKind::WiFi,
                payload_preview: Some(meta.ssid.clone().unwrap_or_default()),
                pin_code: self.state.pin_code.clone(),
                payload: Default::default(),
                total_bytes: Default::default(),
                ack_bytes: Default::default(),
            };

            self.update_state(
                |e| {
                    e.text_payload = Some(TextPayloadInfo::Wifi((
                        meta.payload_id(),
                        meta.ssid().to_owned(),
                        meta.security_type(),
                    )));
                    e.transfer_metadata = Some(metadata);
                },
                true,
            )
            .await;
        } else {
            // Reject transfer
            self.reject_transfer(Some(
                sharing_nearby::connection_response_frame::Status::UnsupportedAttachmentType,
            ))
            .await?;
        }

        Ok(())
    }

    async fn disconnection(&mut self) -> Result<(), anyhow::Error> {
        let frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::Disconnection.into(),
                ),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    ..Default::default()
                }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&frame).await
        } else {
            self.send_frame(frame.encode_to_vec()).await
        }
    }

    async fn accept_transfer(&mut self) -> Result<(), anyhow::Error> {
        let ids: Vec<i64> = self.state.transferred_files.keys().cloned().collect();

        for id in ids {
            let mfi = self.state.transferred_files.get_mut(&id).unwrap();

            let file = File::create(&mfi.file_url)?;
            info!("Created file: {:?}", &file);
            mfi.file = Some(file);
        }

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sharing_nearby::connection_response_frame::Status::Accept.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        self.update_state(
            |e| {
                e.state = TransferState::ReceivingFiles;
            },
            true,
        )
        .await;

        Ok(())
    }

    async fn reject_transfer(
        &mut self,
        reason: Option<sharing_nearby::connection_response_frame::Status>,
    ) -> Result<(), anyhow::Error> {
        let sreason = if let Some(r) = reason {
            r
        } else {
            sharing_nearby::connection_response_frame::Status::Reject
        };

        let frame = sharing_nearby::Frame {
            version: Some(sharing_nearby::frame::Version::V1.into()),
            v1: Some(sharing_nearby::V1Frame {
                r#type: Some(sharing_nearby::v1_frame::FrameType::Response.into()),
                connection_response: Some(sharing_nearby::ConnectionResponseFrame {
                    status: Some(sreason.into()),
                }),
                ..Default::default()
            }),
        };

        self.send_encrypted_frame(&frame).await?;

        Ok(())
    }

    async fn finalize_key_exchange(
        &mut self,
        raw_peer_key: GenericPublicKey,
    ) -> Result<(), anyhow::Error> {
        let peer_p256_key = raw_peer_key
            .ec_p256_public_key
            .ok_or_else(|| anyhow!("Missing required fields"))?;

        let mut bytes = vec![0x04];
        // Ensure no more than 32 bytes for the keys
        if peer_p256_key.x.len() > 32 {
            bytes.extend_from_slice(&peer_p256_key.x[peer_p256_key.x.len() - 32..]);
        } else {
            bytes.extend_from_slice(&peer_p256_key.x);
        }
        if peer_p256_key.y.len() > 32 {
            bytes.extend_from_slice(&peer_p256_key.y[peer_p256_key.y.len() - 32..]);
        } else {
            bytes.extend_from_slice(&peer_p256_key.y);
        }

        let encoded_point = EncodedPoint::from_bytes(bytes)?;
        let peer_key = PublicKey::from_encoded_point(&encoded_point).unwrap();
        let priv_key = self.state.private_key.as_ref().unwrap();

        let dhs = diffie_hellman(priv_key.to_nonzero_scalar(), peer_key.as_affine());
        let derived_secret = Sha256::digest(dhs.raw_secret_bytes());

        let mut ukey_info: Vec<u8> = vec![];
        ukey_info.extend_from_slice(self.state.client_init_msg_data.as_ref().unwrap());
        ukey_info.extend_from_slice(self.state.server_init_data.as_ref().unwrap());

        let auth_label = "UKEY2 v1 auth".as_bytes();
        let next_label = "UKEY2 v1 next".as_bytes();

        let auth_string = hkdf_extract_expand(auth_label, &derived_secret, &ukey_info, 32)?;
        let next_secret = hkdf_extract_expand(next_label, &derived_secret, &ukey_info, 32)?;

        let salt_hex = "82AA55A0D397F88346CA1CEE8D3909B95F13FA7DEB1D4AB38376B8256DA85510";
        let salt =
            hex::decode(salt_hex).map_err(|e| anyhow!("Failed to decode salt_hex: {}", e))?;

        let d2d_client = hkdf_extract_expand(&salt, &next_secret, "client".as_bytes(), 32)?;
        let d2d_server = hkdf_extract_expand(&salt, &next_secret, "server".as_bytes(), 32)?;

        let key_salt_hex = "BF9D2A53C63616D75DB0A7165B91C1EF73E537F2427405FA23610A4BE657642E";
        let key_salt = hex::decode(key_salt_hex)
            .map_err(|e| anyhow!("Failed to decode key_salt_hex: {}", e))?;

        let client_key = hkdf_extract_expand(&key_salt, &d2d_client, "ENC:2".as_bytes(), 32)?;
        let client_hmac_key = hkdf_extract_expand(&key_salt, &d2d_client, "SIG:1".as_bytes(), 32)?;
        let server_key = hkdf_extract_expand(&key_salt, &d2d_server, "ENC:2".as_bytes(), 32)?;
        let server_hmac_key = hkdf_extract_expand(&key_salt, &d2d_server, "SIG:1".as_bytes(), 32)?;

        self.update_state(
            |e| {
                e.decrypt_key = Some(client_key);
                e.recv_hmac_key = Some(client_hmac_key);
                e.encrypt_key = Some(server_key);
                e.send_hmac_key = Some(server_hmac_key);
                e.pin_code = Some(to_four_digit_string(&auth_string));
                e.encryption_done = true;
            },
            false,
        )
        .await;

        info!("Pin code: {:?}", self.state.pin_code);

        Ok(())
    }

    async fn send_ukey2_alert(&mut self, atype: AlertType) -> Result<(), anyhow::Error> {
        let alert = Ukey2Alert {
            r#type: Some(atype.into()),
            error_message: None,
        };

        let data = Ukey2Message {
            message_type: Some(atype.into()),
            message_data: Some(alert.encode_to_vec()),
        };

        self.send_frame(data.encode_to_vec()).await
    }

    async fn send_encrypted_frame(
        &mut self,
        frame: &sharing_nearby::Frame,
    ) -> Result<(), anyhow::Error> {
        let frame_data = frame.encode_to_vec();
        let body_size = frame_data.len();

        let payload_header = PayloadHeader {
            id: Some(rand::rng().random_range(i64::MIN..i64::MAX)),
            r#type: Some(payload_header::PayloadType::Bytes.into()),
            total_size: Some(body_size as i64),
            is_sensitive: Some(false),
            ..Default::default()
        };

        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(0),
                flags: Some(0),
                body: Some(frame_data),
            }),
            payload_header: Some(payload_header.clone()),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        // Send lastChunk
        let transfer = PayloadTransferFrame {
            packet_type: Some(PacketType::Data.into()),
            payload_chunk: Some(PayloadChunk {
                offset: Some(body_size as i64),
                flags: Some(1), // lastChunk
                body: Some(vec![]),
            }),
            payload_header: Some(payload_header),
            ..Default::default()
        };

        let wrapper = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(
                    location_nearby_connections::v1_frame::FrameType::PayloadTransfer.into(),
                ),
                payload_transfer: Some(transfer),
                ..Default::default()
            }),
        };

        // Encrypt and send offline
        self.encrypt_and_send(&wrapper).await?;

        Ok(())
    }

    async fn encrypt_and_send(&mut self, frame: &OfflineFrame) -> Result<(), anyhow::Error> {
        let d2d_msg = DeviceToDeviceMessage {
            sequence_number: Some(self.get_server_seq_inc().await),
            message: Some(frame.encode_to_vec()),
        };

        let key = self.state.encrypt_key.as_ref().unwrap();
        let msg_data = d2d_msg.encode_to_vec();
        let iv = gen_random(16);

        let mut cipher = Cipher::new_256(&key[..AES_256_KEY_LEN].try_into().unwrap());
        cipher.set_auto_padding(true);
        let encrypted = cipher.cbc_encrypt(&iv, &msg_data);

        let hb = HeaderAndBody {
            body: encrypted,
            header: Header {
                encryption_scheme: EncScheme::Aes256Cbc.into(),
                signature_scheme: SigScheme::HmacSha256.into(),
                iv: Some(iv),
                public_metadata: Some(
                    GcmMetadata {
                        r#type: Type::DeviceToDeviceMessage.into(),
                        version: Some(1),
                    }
                    .encode_to_vec(),
                ),
                ..Default::default()
            },
        };

        let mut hmac = HmacSha256::new_from_slice(self.state.send_hmac_key.as_ref().unwrap())?;
        hmac.update(&hb.encode_to_vec());
        let result = hmac.finalize();

        let smsg = SecureMessage {
            header_and_body: hb.encode_to_vec(),
            signature: result.into_bytes().to_vec(),
        };

        self.send_frame(smsg.encode_to_vec()).await?;

        Ok(())
    }

    async fn send_keepalive(&mut self, ack: bool) -> Result<(), anyhow::Error> {
        let ack_frame = location_nearby_connections::OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(location_nearby_connections::v1_frame::FrameType::KeepAlive.into()),
                keep_alive: Some(KeepAliveFrame { ack: Some(ack) }),
                ..Default::default()
            }),
        };

        if self.state.encryption_done {
            self.encrypt_and_send(&ack_frame).await
        } else {
            self.send_frame(ack_frame.encode_to_vec()).await
        }
    }

    async fn send_frame(&mut self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        let length = data.len();

        // Prepare length prefix in big-endian format
        let length_bytes = [
            (length >> 24) as u8,
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
        ];

        let mut prefixed_length = Vec::with_capacity(length + 4);
        prefixed_length.extend_from_slice(&length_bytes);
        prefixed_length.extend_from_slice(&data);

        self.socket.write_all(&prefixed_length).await?;
        self.socket.flush().await?;

        Ok(())
    }

    async fn get_server_seq_inc(&mut self) -> i32 {
        self.update_state(
            |e| {
                e.server_seq += 1;
            },
            false,
        )
        .await;

        self.state.server_seq
    }

    async fn get_client_seq_inc(&mut self) -> i32 {
        self.update_state(
            |e| {
                e.client_seq += 1;
            },
            false,
        )
        .await;

        self.state.client_seq
    }

    async fn update_state<F>(&mut self, f: F, inform: bool)
    where
        F: FnOnce(&mut InnerState),
    {
        f(&mut self.state);

        if !inform {
            return;
        }

        trace!("Sending msg into the channel");
        let _ = self.sender.send(ChannelMessage {
            id: self.state.id.clone(),
            msg: channel::Message::Client(MessageClient {
                kind: TransferKind::Inbound,
                state: Some(self.state.state.clone()),
                metadata: self.state.transfer_metadata.clone(),
            }),
        });
        // Add a small sleep timer to allow the Tokio runtime to have
        // some spare time to process channel's message. Otherwise it
        // get spammed by new requests. Currently set to 10 micro secs.
        tokio::time::sleep(SANITY_DURATION).await;
    }
}

#[cfg(all(feature = "experimental", target_os = "linux"))]
impl InboundRequest<crate::hdl::MigratableStream> {
    /// Run the Wi-Fi bandwidth upgrade: offer a TCP path over the (encrypted) BLE
    /// channel, accept the phone, exchange the plaintext CLIENT_INTRODUCTION/ACK,
    /// drain the BLE channel, then swap the socket to TCP so the (large) payload
    /// streams over Wi-Fi with the same keys/sequence numbers. On failure the
    /// session stays on BLE — never worse than BLE-only.
    pub async fn do_bwu(&mut self) -> Result<(), anyhow::Error> {
        use location_nearby_connections::bandwidth_upgrade_negotiation_frame::EventType;

        let listener = tokio::net::TcpListener::bind("0.0.0.0:0").await?;
        let port = listener.local_addr()?.port();

        // Offer WIFI_LAN over the encrypted BLE channel.
        self.send_upgrade_path_available(port).await?;

        // Wait for the phone to connect over TCP; if it doesn't, stay on BLE.
        let mut tcp = match tokio::time::timeout(Duration::from_secs(15), listener.accept()).await {
            Ok(Ok((s, peer))) => {
                info!("BWU: phone connected over TCP from {peer}");
                s
            }
            _ => {
                warn!("BWU: no TCP upgrade within timeout; staying on BLE");
                return Ok(());
            }
        };

        // Plaintext CLIENT_INTRODUCTION → CLIENT_INTRODUCTION_ACK on the new socket.
        // Bounded, so a stalled phone can't hold up the session (and its UI
        // accept/decline actions) indefinitely.
        let intro = tokio::time::timeout(Duration::from_secs(10), read_frame_from(&mut tcp))
            .await
            .map_err(|_| anyhow!("BWU: no CLIENT_INTRODUCTION within timeout"))??;
        if let Ok(f) = OfflineFrame::decode(&*intro) {
            debug!("BWU: TCP intro frame type={:?}", f.v1.as_ref().map(|v| v.r#type()));
        }
        send_frame_on(&mut tcp, &Self::bwu_ack_frame().encode_to_vec()).await?;

        // Drain the BLE channel: our LAST_WRITE, then read the peer's control frames
        // (advancing client_seq) until it's safe to close the prior channel.
        self.encrypt_and_send(&Self::bwu_frame(EventType::LastWriteToPriorChannel, None, None))
            .await?;
        for _ in 0..16 {
            let offline = match tokio::time::timeout(
                Duration::from_secs(5),
                self.read_encrypted_offline_frame(),
            )
            .await
            {
                Ok(Ok(f)) => f,
                _ => break,
            };
            let frame_type = offline.v1.as_ref().map(|v| v.r#type());
            if frame_type
                != Some(location_nearby_connections::v1_frame::FrameType::BandwidthUpgradeNegotiation)
            {
                // The phone keeps sending normal frames (paired-key, etc.) over BLE
                // until its LAST_WRITE — process them so the sharing handshake
                // continues correctly after the swap.
                if let Err(e) = self.process_offline_frame(offline).await {
                    debug!("BWU drain: error processing non-BWU frame: {e}");
                }
                continue;
            }
            let event = offline
                .v1
                .as_ref()
                .and_then(|v| v.bandwidth_upgrade_negotiation.as_ref())
                .map(|b| b.event_type());
            match event {
                Some(EventType::LastWriteToPriorChannel) => {
                    debug!("BWU drain: peer LAST_WRITE → sending SAFE_TO_CLOSE");
                    let _ = self
                        .encrypt_and_send(&Self::bwu_frame(
                            EventType::SafeToClosePriorChannel,
                            None,
                            None,
                        ))
                        .await;
                }
                Some(EventType::SafeToClosePriorChannel) => {
                    debug!("BWU drain: peer SAFE_TO_CLOSE → done");
                    break;
                }
                other => debug!("BWU drain: event {other:?}"),
            }
        }

        // Tell the phone the prior (BLE) channel is closing so it stops pausing the
        // new channel and resumes immediately (avoids a ~10s phone-side timeout).
        // Sent plaintext (unencrypted) per the protocol, and given a moment to flush
        // through the weave bridge before we drop the BLE side.
        let disc = OfflineFrame {
            version: Some(location_nearby_connections::offline_frame::Version::V1.into()),
            v1: Some(location_nearby_connections::V1Frame {
                r#type: Some(location_nearby_connections::v1_frame::FrameType::Disconnection.into()),
                disconnection: Some(location_nearby_connections::DisconnectionFrame {
                    request_safe_to_disconnect: Some(false),
                    ack_safe_to_disconnect: Some(false),
                }),
                ..Default::default()
            }),
        };
        let _ = self.send_frame(disc.encode_to_vec()).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Swap to the TCP channel; the payload loop resumes over Wi-Fi.
        self.socket = crate::hdl::MigratableStream::Tcp(tcp);
        info!("BWU: upgraded to Wi-Fi-LAN; payload continues over TCP");
        Ok(())
    }
}
