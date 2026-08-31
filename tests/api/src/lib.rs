//! Compile contract for representative use outside the rsReticulumLite workspace.

use rns_lite_core::{InterfaceMode, LiteConfig, MicroNode, OutboundFrame, RxMeta, TransportError};

pub fn construct_micro_node() -> Result<MicroNode, TransportError> {
    MicroNode::new(LiteConfig::ESP32_LORA_TRANSPORT_MICRO, [0x11; 16])
}

pub fn originate_path_request(
    node: &mut MicroNode,
) -> Result<Option<OutboundFrame>, TransportError> {
    node.request_path(&[0x22; 16], &[0x33; 16], 1, 0)?;
    Ok(node.poll_tx())
}

pub fn roaming_ingress(interface_id: u8) -> RxMeta {
    RxMeta::with_mode(interface_id, InterfaceMode::Roaming)
}
