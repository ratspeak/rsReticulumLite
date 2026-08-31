//! Build and drain a bounded endpoint-originated path request.

use rns_lite_core::{LiteConfig, MicroNode, OutboundReason};

fn main() {
    // Demonstration values only. Firmware must provision its transport identity
    // deliberately and generate a fresh random request tag.
    let mut node = MicroNode::new(LiteConfig::ESP32_LORA_TRANSPORT_MICRO, [0xa5; 16])
        .expect("reviewed MicroNode profile");

    let destination = [0x42; 16];
    let request_tag = [0x7c; 16];
    node.request_path(&destination, &request_tag, 1, 0)
        .expect("request packet fits the fixed buffer");

    let frame = node.poll_tx().expect("path request was queued");
    assert_eq!(frame.reason, OutboundReason::PathRequest);
    println!(
        "queued {}-byte path request for interface {}",
        frame.packet.len(),
        frame.interface_id
    );
}
