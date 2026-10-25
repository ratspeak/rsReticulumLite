#!/usr/bin/env python3
"""Authoritative tunnel-synthesis vector generator (rns-lite-core `tunnel` module).

Drives the REAL Python RNS pinned in `vectors/RNS_VERSION` (never a re-implementation):
`Transport.synthesize_tunnel` builds each packet with `Transport.outbound` captured and the
transport identity and `Identity.get_random_hash` fixed, for unconnected `TCPClientInterface`s
whose `str()` and `get_hash()` are upstream's own. `Transport.tunnel_synthesize_handler` must
then accept every generated synthesis. Aborts unless the installed RNS version matches
`RNS_VERSION`; the harness never installs or upgrades packages itself.
Output: tunnel_vectors.json (consumed by the rns-lite-core `tunnel_vectors` test).
"""

import json
import os
import shutil
import sys
import tempfile
import types
from pathlib import Path

import RNS
from RNS.Interfaces.Interface import Interface
from RNS.Interfaces.TCPInterface import TCPClientInterface

HERE = Path(__file__).resolve().parent
TARGET_RNS = (HERE / "RNS_VERSION").read_text().strip()

INTERFACES = {
    "tcp_ipv4": {"name": "Golden Uplink", "target_ip": "127.0.0.1", "target_port": 4242},
    "tcp_ipv6": {"name": "Golden Uplink", "target_ip": "::1", "target_port": 4242},
    "tcp_hostname": {"name": "Golden Uplink", "target_ip": "hub.example.org", "target_port": 4242},
}
IDENTITIES = {"first": bytes(range(64)), "second": bytes(range(64, 128))}
SYNTHESES = {
    "first_connect": ("first", "tcp_ipv4", bytes([0xA5] * 16)),
    "first_reconnect": ("first", "tcp_ipv4", bytes([0x5A] * 16)),
    "second_connect": ("second", "tcp_ipv4", bytes([0xC3] * 16)),
    "second_reconnect": ("second", "tcp_ipv4", bytes([0x3C] * 16)),
}


def client(attributes):
    interface = TCPClientInterface.__new__(TCPClientInterface)
    Interface.__init__(interface)
    for name, value in attributes.items():
        setattr(interface, name, value)
    return interface


class Receiver:
    def protocol_violation(self, reason):
        pass


def generate():
    interfaces = {case: client(attributes) for case, attributes in INTERFACES.items()}
    identities = {case: RNS.Identity.from_bytes(key) for case, key in IDENTITIES.items()}

    captured = []
    RNS.Transport.outbound = staticmethod(lambda packet: captured.append(packet) or True)
    accepted = []
    RNS.Transport.handle_tunnel = staticmethod(
        lambda tunnel_id, interface: accepted.append(tunnel_id)
    )

    syntheses = {}
    for case, (identity, interface, random_hash) in SYNTHESES.items():
        RNS.Transport.identity = identities[identity]
        RNS.Identity.get_random_hash = staticmethod(lambda random_hash=random_hash: random_hash)
        captured.clear()
        RNS.Transport.synthesize_tunnel(interfaces[interface])
        assert len(captured) == 1, "synthesize_tunnel emitted no packet"
        packet = captured[0]
        accepted.clear()
        RNS.Transport.tunnel_synthesize_handler(
            packet.data, types.SimpleNamespace(receiving_interface=Receiver())
        )
        assert len(accepted) == 1, "upstream rejected its own synthesis"
        syntheses[case] = {
            "identity": identity,
            "interface": interface,
            "random_hash": random_hash.hex(),
            "payload": packet.data.hex(),
            "raw": packet.raw.hex(),
            "packet_hash": packet.get_hash().hex(),
            "tunnel_id": accepted[0].hex(),
        }

    return {
        "rns_version": RNS.__version__,
        "note": f"Tunnel synthesis vectors from the REAL RNS {TARGET_RNS} "
        "Transport.synthesize_tunnel (fixed identity and random hash). "
        "Regenerate only via gen_tunnel_vectors.py.",
        "synthesize_destination_hash": RNS.Transport.tunnel_synthesize_destination.hash.hex(),
        "identities": {
            case: {
                "private_key": identity.get_private_key().hex(),
                "public_key": identity.get_public_key().hex(),
                "hash": identity.hash.hex(),
            }
            for case, identity in identities.items()
        },
        "interfaces": {
            case: {"str": str(interface), "hash": interface.get_hash().hex()}
            for case, interface in interfaces.items()
        },
        "syntheses": syntheses,
    }


def main():
    if RNS.__version__ != TARGET_RNS:
        print(f"ERROR: target RNS {TARGET_RNS}, found {RNS.__version__}", file=sys.stderr)
        return 1
    configdir = tempfile.mkdtemp(prefix="rns-lite-tunnel-vectors-")
    try:
        with open(os.path.join(configdir, "config"), "w") as config:
            config.write("[reticulum]\n  share_instance = No\n\n[interfaces]\n")
        RNS.Reticulum(configdir=configdir, loglevel=0)
        vectors = generate()
        with open(HERE / "tunnel_vectors.json", "w") as out:
            json.dump(vectors, out, indent=2, sort_keys=True)
            out.write("\n")
    finally:
        shutil.rmtree(configdir, ignore_errors=True)
    print(f"wrote {HERE / 'tunnel_vectors.json'} from RNS {RNS.__version__}")
    return 0


if __name__ == "__main__":
    status = main()
    sys.stdout.flush()
    # Skip Reticulum's exit handlers: the temporary config directory is already gone.
    os._exit(status)
