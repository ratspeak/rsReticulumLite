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

    // One available host interface. Generations retire permission when its driver changes.
    let queued = *node
        .retained_outbound_select(0, 0, [0, 1, 0, 0, 0, 0, 0])
        .expect("path request was queued");
    let frame = queued.frame;
    // Transfer ownership before handing bytes to a driver. A real driver retains the
    // lifetime and interface generation and rechecks both before transmission.
    assert!(node.retained_outbound_take(queued.delivery.identity));
    assert_eq!(frame.reason, OutboundReason::PathRequest);
    println!(
        "queued {}-byte path request for interface {}",
        frame.packet.len(),
        frame.interface_id
    );
}
