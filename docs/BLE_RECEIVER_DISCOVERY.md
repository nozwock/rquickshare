# Quick Share over Bluetooth — BLE receiver discovery & the weave data socket

> Reverse-engineered and implemented against a **Pixel 9 Pro** (Android, July 2026).
> This document describes how a Linux device (rquickshare / Packet) can be
> discovered and **receive a file over Bluetooth** from a phone that has dropped
> off Wi-Fi during Quick Share — the scenario that previously failed
> ([nozwock/packet#140](https://github.com/nozwock/packet/issues/140),
> [Martichou/rquickshare#425](https://github.com/Martichou/rquickshare/issues/425)).
>
> **Status:** working prototype — real files transfer end-to-end from an off-Wi-Fi
> Pixel, and the payload is **bandwidth-upgraded to Wi-Fi** so large files are fast
> (a 20 MB file transfers in seconds). See [Bandwidth upgrade](#7--bandwidth-upgrade-to-wi-fi)
> and [Limitations & performance](#8--limitations--performance).

---

## 1. The problem

Quick Share (Nearby Share) chooses the connection transport by **the medium it
discovered the peer on**, in a fixed priority order:

```
AWDL > WIFI_LAN > WIFI_DIRECT > WIFI_HOTSPOT > WEB_RTC > BLUETOOTH > BLE
```

Historically rquickshare/Packet only implemented the **Wi-Fi LAN** medium: it
advertises an mDNS service (`_FC9F5ED42C8A._tcp`) and accepts a TCP connection.
That works only when the phone discovers it **over mDNS**, i.e. while the phone
is on the same Wi-Fi network.

Google's *AirDrop-compatibility* update changed Pixel behaviour: when you open
the share sheet, the phone **disconnects from Wi-Fi** to do Quick Share / AirDrop
discovery over Bluetooth. While off Wi-Fi it can't see the mDNS service, so the
Linux box never appears as a target — and even if selected later, the phone only
holds a **BLE** endpoint for it, so it will only ever try to connect over BLE.

**Fixing it therefore requires implementing the Bluetooth path end-to-end:**
BLE discovery, a GATT server, and the Nearby Connections **"weave" data socket**
over which the encrypted transfer runs. No open-source project had done this;
this is the result.

---

## 2. End-to-end sequence

```mermaid
sequenceDiagram
    autonumber
    participant P as Pixel (sender, off Wi-Fi)
    participant L as Linux (Packet / rquickshare)

    rect rgb(235,244,255)
    Note over P,L: 1 — Discovery (BLE)
    L-->>P: Extended advertisement, service UUID 0xFEF3<br/>(endpoint_id + plaintext name "Packet Linux RX")
    Note over P: Shows Linux as a "computer" target
    end

    rect rgb(238,251,238)
    Note over P,L: 2 — GATT connect
    P->>L: LE connection (P = central, L = peripheral)
    P->>L: Discover service 0xFEF3
    P->>L: Read slot-0 characteristic (advertisement)
    end

    rect rgb(255,246,235)
    Note over P,L: 3 — Weave socket handshake
    P->>L: Subscribe (CCCD) to 0102 (notify)
    P->>L: Write 0101: CONN_REQUEST  80 0001 0001 01fd
    L-->>P: Notify 0102: CONN_CONFIRM 81 0001 01fd
    end

    rect rgb(245,238,255)
    Note over P,L: 4 — Nearby Connections handshake (over the socket)
    P->>L: INTRODUCTION control frame  (00 00 00 …)
    P->>L: ConnectionRequest (OfflineFrame)
    P->>L: UKEY2 ClientInit
    L-->>P: UKEY2 ServerInit  → PIN derived (matches on both devices)
    P->>L: UKEY2 ClientFinish
    L-->>P: ConnectionResponse
    P->>L: PairedKeyEncryption
    L-->>P: PairedKeyResult
    P->>L: PairedKeyResult
    P->>L: Introduction (file metadata)
    end

    rect rgb(238,251,238)
    Note over P,L: 5 — Consent & transfer
    Note over L: WaitingForUserConsent → accept
    L-->>P: Response = Accept
    P->>L: Payload chunks (the file bytes)
    Note over P,L: Transfer finished ✅ — file written to disk
    end
```

---

## 3. Protocol stack

Every message the phone sends over the socket is wrapped in four nested layers.
Reading top-to-bottom is receive; the reverse is send.

```mermaid
flowchart TB
    A["<b>A · Weave transport</b><br/>1-byte header per GATT write/notify:<br/>control? · counter(3b) · first · last · cmd(4b)<br/>reassemble first→last into a message"]
    B["<b>B · BLE socket demux</b><br/>[service_id_hash(3)][data]<br/>hash 00 00 00 ⇒ control (SocketControlFrame)<br/>hash FC 9F 5E ⇒ data"]
    C["<b>C · Endpoint channel</b><br/>[4-byte big-endian length][payload]<br/>(identical to the Wi-Fi-LAN / TCP framing)"]
    D["<b>D · Nearby Connections + Sharing</b><br/>OfflineFrame → UKEY2 → SecureMessage →<br/>ConnectionResponse / PairedKey / Introduction / Payload"]
    A --> B --> C --> D
```

The crucial reuse win: once the socket is up, **layer C is byte-for-byte the same
`[len][OfflineFrame]` stream that rquickshare already speaks over TCP** — so the
entire existing receive state machine runs unmodified over Bluetooth.

---

## 4. Byte-level reference

### 4.1 BLE advertisement (service data under UUID `0xFEF3`)

The advertised service data is a Nearby Connections *mediums* `BleAdvertisement`
carrying an inner *connections* advertisement, carrying the endpoint info:

```
BleAdvertisement (mediums)
  48                      version=2 | socket_version=2 | fast=0
  fc 9f 5e                service_id_hash = SHA-256("NearbySharing")[0:3]
  00 00 00 NN             DATA_SIZE (u32, big-endian)
  <DATA>                  ── connections advertisement ──
    23                    version=1 | PCP=3 (PointToPoint)
    fc 9f 5e              service_id_hash
    E0 E1 E2 E3           endpoint_id (4 bytes, MUST match the mDNS name)
    26                    endpoint_info size
    <endpoint_info>       ── Nearby Share application advertisement ──
      26                  header: version=1 | visible(0) | device_type=laptop(3)
      <16 bytes>          salt(2) + metadata-key hash(14)
      LL                  device-name length
      <name>              UTF-8 plaintext name  (visible/"Everyone" mode)
    <6+2 bytes>           bluetooth MAC + extra
  <trailer>              device_token(2) + Nearby-Presence data elements
```

The **same `endpoint_id`** is used in the mDNS instance name so Wi-Fi and BLE
resolve to one endpoint:
`mdns_name = base64url( 0x23 ‖ endpoint_id ‖ FC 9F 5E ‖ 00 00 )`.

### 4.2 GATT service `0xFEF3`

| Characteristic UUID | Props | Direction | Purpose |
|---|---|---|---|
| `00000000-0000-3000-8000-000000000000` | Read | L→P | advertisement slot 0 (full `BleAdvertisement`) |
| `00000100-0004-1000-8000-001a11000101` | **Write (with response)** | P→L | weave "ToPeripheral" — phone writes packets |
| `00000100-0004-1000-8000-001a11000102` | **Notify** (+CCCD) | L→P | weave "FromPeripheral" — we notify packets |

> Write-with-response (not write-without-response) is deliberate: it forces the
> phone to send one packet at a time so BlueZ delivers them **in order**
> (see [Limitations](#limitations--performance)).

### 4.3 Weave packet header (layer A)

```
 bit  7   6 5 4    3       2      1 0
     ┌───┬───────┬───────┬──────┬───────┐
     │ C │counter│ first │ last │  cmd  │      (cmd only meaningful when C=1)
     └───┴───────┴───────┴──────┴───────┘
  C=1 control · C=0 data      first=0x08  last=0x04
  cmd: 0 = CONNECTION_REQUEST   1 = CONNECTION_CONFIRM   2 = ERROR
```

| Packet | Bytes |
|---|---|
| CONNECTION_REQUEST (from phone) | `80` `min_ver(2)` `max_ver(2)` `max_pkt_size(2)` → e.g. `80 0001 0001 01fd` |
| CONNECTION_CONFIRM (our reply)  | `81` `sel_ver(2)` `sel_pkt_size(2)` → e.g. `81 0001 01fd` |
| DATA                            | header with first/last flags, then the layer-B bytes |

### 4.4 BLE socket packets (layer B) & control frames

```
data:     [fc 9f 5e][ layer-C bytes … ]
control:  [00 00 00][ SocketControlFrame protobuf ]
            08 01 …  ⇒ INTRODUCTION   (service_id_hash, socket_version)
            08 02 …  ⇒ DISCONNECTION
```

The receiver reads (and skips) the leading **INTRODUCTION**, then feeds every
subsequent data message's `[len][OfflineFrame]` straight into the existing
handshake.

---

## 5. Inbound state machine (unchanged core, over a new transport)

```mermaid
stateDiagram-v2
    [*] --> Initial
    Initial --> ReceivedConnectionRequest: ConnectionRequest
    ReceivedConnectionRequest --> SentUkeyServerInit: UKEY2 ClientInit → ServerInit (PIN)
    SentUkeyServerInit --> ReceivedUkeyClientFinish: UKEY2 ClientFinish
    ReceivedUkeyClientFinish --> SentConnectionResponse: ConnectionResponse
    SentConnectionResponse --> SentPairedKeyResult: PairedKeyEncryption
    SentPairedKeyResult --> ReceivedPairedKeyResult: PairedKeyResult
    ReceivedPairedKeyResult --> WaitingForUserConsent: Introduction (file metadata)
    WaitingForUserConsent --> ReceivingFiles: Accept
    ReceivingFiles --> Finished: last payload chunk
    Finished --> [*]
```

> **Tolerance fix:** newer Pixels interleave extra frames (including an unhandled
> outer `OfflineFrame` with `type = 12`) before the Introduction. The
> `ReceivedPairedKeyResult` state now *waits* for a frame that actually contains
> an `introduction` instead of erroring on the first non-introduction frame.

---

## 6. Implementation

All changes live in `core_lib`:

| File | Change |
|---|---|
| `src/hdl/blea.rs` | `receiver_service_data()` builds the 0xFEF3 advertisement; `ReceiverAdvertiser` advertises it (extended, connectable). |
| `src/hdl/gatt.rs` *(new)* | `ReceiverGattServer`: serves the 0xFEF3 GATT service (slot-0 read + weave `0101`/`0102`) and `weave_session()`, which does the weave handshake and bridges the socket to `InboundRequest` via an in-memory `tokio::io::duplex`. |
| `src/hdl/inbound.rs` | `InboundRequest<S>` made generic over any `AsyncRead + AsyncWrite` (was `TcpStream`); introduction-tolerance fix. |
| `src/utils.rs` | `stream_read_exact` generalized over `AsyncRead`. |
| `src/lib.rs` | `RQS::run()` spawns `ReceiverGattServer` + `ReceiverAdvertiser` (sharing one endpoint_id and advertisement) when visible. |
| `examples/rx_service.rs` | Standalone receive harness (auto-accepts, logs the flow) used to develop/verify this. |

The bridge in one picture:

```mermaid
flowchart LR
    subgraph BlueZ["BlueZ GATT (bluer)"]
      W0101["char 0101 (write)"]
      W0102["char 0102 (notify)"]
    end
    subgraph Weave["weave_session()"]
      RE["reassemble + strip weave/BLE headers"]
      FR["frame + fragment + counter"]
    end
    subgraph Inbound["InboundRequest&lt;DuplexStream&gt;"]
      HS["UKEY2 + Sharing handshake<br/>(unchanged from TCP path)"]
    end
    W0101 --> RE -->|"[len][OfflineFrame]"| HS
    HS -->|"[len][OfflineFrame]"| FR --> W0102
```

---

## 7. Bandwidth upgrade to Wi-Fi

BLE is slow (the weave socket + write-with-response is tens of KB/s), so once the
encrypted connection is up the receiver **upgrades the payload to Wi-Fi-LAN**,
keeping the same UKEY2 keys and sequence numbers. Only the handshake runs over
BLE; the file bytes stream over TCP.

```mermaid
sequenceDiagram
    autonumber
    participant P as Pixel
    participant L as Linux
    Note over P,L: encrypted connection established over BLE
    L-->>P: [BLE, enc] UPGRADE_PATH_AVAILABLE (WIFI_LAN, our ipv4:port)
    P->>L: [TCP] connect to ip:port
    P->>L: [TCP, plaintext] CLIENT_INTRODUCTION (endpoint_id)
    L-->>P: [TCP, plaintext] CLIENT_INTRODUCTION_ACK
    P->>L: [BLE, enc] LAST_WRITE_TO_PRIOR_CHANNEL
    L-->>P: [BLE, enc] SAFE_TO_CLOSE_PRIOR_CHANNEL
    L-->>P: [BLE, plaintext] DISCONNECTION
    Note over P,L: payload streams over TCP with the same keys/seq
    P->>L: [TCP, enc] file payload → done
```

**Key facts** (source-verified against `google/nearby`, confirmed on a Pixel 9 Pro):
- The **receiver is the initiator** — it hosts the TCP socket and offers the path.
- Sequence numbers **continue** across the swap (no reset) and WIFI_LAN keeps
  encryption **on**, so the receive handshake just swaps its socket
  (`MigratableStream`) and keeps all crypto state.
- The intro/ack and the final DISCONNECTION are **plaintext** — they bypass the
  cipher and must not touch the sequence counters.
- While draining the old channel the phone keeps sending normal frames
  (paired-key, etc.) over BLE until its LAST_WRITE — these must be **processed**,
  not dropped.
- The final plaintext **DISCONNECTION is required**: without it the phone keeps
  the new channel paused for a ~10s timeout before resuming.

**Result:** a 20 MB file transfers in seconds over Wi-Fi.

---

## 8. Limitations & performance

- **Connection latency, not transfer.** Once the phone connects, the handshake +
  upgrade take ~1s and the file runs at Wi-Fi speed. The user-visible delay
  (~15–20s) is almost entirely **BLE discovery + the GATT service discovery the
  phone does on connect** — largely phone-side, and about the floor for this
  transport. Fast advertising (100–150ms) helps only a little.
- **Single connection.** `weave_session` holds one shared packet channel /
  notifier; concurrent/repeat connections need per-connection state.
- **Prototype logging.** Verbose `rx pkt` / `rx msg` / `-> inbound` / `BWU drain`
  debug lines should be removed or gated for production.
- **Not yet wired into the Packet GTK app** — this lives in `rqs_lib`; Packet
  needs its dependency bumped to this fork.

---

## 9. References

- `google/nearby` — `connections/implementation/mediums/ble/*`,
  `internal/weave/packet.{h,cc}`, `connections/implementation/offline_frames.cc`,
  the Apple `.../Mediums/BLE/Sockets/` weave client.
- [grishka/NearDrop](https://github.com/grishka/NearDrop) `PROTOCOL.md` (mDNS/TCP
  receiver reference; documents the advertisement format).
- Issues: [nozwock/packet#140](https://github.com/nozwock/packet/issues/140),
  [Martichou/rquickshare#425](https://github.com/Martichou/rquickshare/issues/425).
