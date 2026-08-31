# Integration and ownership

`rns-lite-core` is synchronous and allocation-free. It does not start tasks,
open interfaces or access storage. Multiple independent `LiteNode` instances
can run in one process.

## Transport loop

The caller supplies a validated `LiteConfig` and transport identity hash.
Use `MicroNode` or `SmallNode` for predefined table capacities, or
`LiteNode` for explicit const-generic capacities. Construction rejects a
configuration whose requested table sizes exceed the selected profile.

Feed complete Reticulum wire frames to `ingest(raw, meta, now_ms)`.
`RxMeta` identifies the receiving interface and its mode; supplying the mode
lets learned paths use that interface's expiry policy. Inspect `IngestAction`
before committing endpoint state: an `AnnounceIgnored` result must not update
a peer's key or ratchet.

Call `tick(now_ms)` to expire state and schedule due traffic, then drain
`poll_tx()`. Each `OutboundFrame` includes wire bytes, interface metadata and
a reason. Queueing or draining a frame is not confirmation that a radio
accepted or transmitted it; the firmware owns that result.

The [path-request example](../../crates/rns-lite-core/examples/path_request.rs)
shows construction and outbound draining.

## Memory and time

Paths, packet hashes, reverse routes, links, announces, request tags and known
destinations have fixed capacities. Bounded queues can evict old entries;
`TransportStats` exposes drops and admission failures.

Supply monotonic milliseconds to time-dependent operations. Provide secure
entropy for identities, ephemeral keys and other random input. Deterministic
keys in examples and tests are not suitable for devices.

## Interfaces and IFAC

Interface drivers receive and transmit bytes outside the core. The LoRa module
provides split framing, airtime accounting and carrier-sense primitives;
it does not drive a radio.

The clear Reticulum MTU is 500 bytes. IFAC wire buffers allow up to 564 bytes
for the largest tag; LoRa split framing allows 508 bytes, enough for a
full-MTU packet with the default eight-byte IFAC tag.

IFAC verifies inbound frames before parsing and wraps outbound frames when
configured. Missing, invalid or unexpected IFAC is rejected. Configuration
adapters should normalize empty network names/passphrases to `None` to match
Python Reticulum's empty-string handling.

## Endpoint state

Link helpers provide handshake, key derivation, proof and encryption
operations. The caller owns Link sessions, their timers and teardown.

Resource helpers support encrypted, uncompressed, single-segment transfers,
up to eight parts and 3,659 application bytes. Unsupported compression,
metadata and multi-segment shapes are rejected. Relaying a Resource does not
require endpoint reassembly and is not limited by the local reassembly size.

Known destinations, ratchets and announce ordering expose validated state
encodings. The caller must commit persistent state successfully before
applying a prepared rotation or advancing durable state. The library does
not select a filesystem, format flash or retry failed writes.
