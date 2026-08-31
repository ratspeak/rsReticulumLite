//! Bounded Reticulum transport and endpoint primitives for MCU firmware.
//!
//! The crate is unconditionally `no_std`, performs no allocation, and leaves
//! clocks, entropy, persistence, and interface I/O to the embedding runtime.
//! [`MicroNode`] and [`SmallNode`] provide reviewed capacity profiles; the
//! const-generic [`LiteNode`] remains available for deliberate custom budgets.

#![no_std]
#![forbid(unsafe_code)]
#![deny(rustdoc::broken_intra_doc_links)]

#[cfg(test)]
extern crate std;

pub mod announce_admission;
pub mod announce_state;
pub mod auto;
pub mod config;
pub mod constants;
pub mod crypto;
pub mod identity;
pub mod ifac;
pub mod known_destinations;
pub mod link;
pub mod lora;
pub mod packet_buffer;
pub mod proof;
pub mod ratchet;
pub mod resource;
pub mod tables;
pub mod transport;
pub mod wire;

pub use announce_admission::{AnnounceAdmission, AnnounceAdmissionConfig};
pub use announce_state::{
    ANNOUNCE_TIME_MAX, ANNOUNCE_WIRE_STATE_BLOB_LEN, AnnounceWireError, AnnounceWireState,
};
pub use auto::{AutoError, IPV6_TEXT_MAX, beacon_token, format_ipv6, multicast_group_for};
pub use config::{ConfigError, IfacConfig, InterfaceMode, LiteConfig, TableCaps};
pub use identity::{AnnounceError, AnnounceView, LocalIdentity, compose_random_hash};
pub use ifac::{
    IFAC_FLAG, IFAC_KEY_LENGTH, IFAC_LORA_DEFAULT_SIZE, IfacError, derive_ifac_key, has_ifac_flag,
    ifac_sign_into, ifac_verify_into,
};
pub use known_destinations::{
    KNOWN_DESTINATIONS_MICRO, KNOWN_DESTINATIONS_SMALL, KnownDestination, KnownDestinationError,
    KnownDestinations,
};
pub use link::{
    LINK_MDU, LinkError, LinkKeys, LinkProofView, LinkRequestView, SignallingData,
    build_link_proof, build_link_request, compute_link_id, link_decrypt, link_encrypt, link_mdu,
};
pub use resource::{
    InboundResource, InboundState, OutboundResource, PartRequestView, ResourceAdv, ResourceError,
    ResourceFlags, WindowState, compute_expected_proof, compute_resource_hash, get_map_hash,
};
pub use transport::{
    IngestAction, LiteNode, MicroNode, OutboundFrame, OutboundReason, RxMeta, SmallNode,
    TransportError, TransportStats, path_request_destination,
};
