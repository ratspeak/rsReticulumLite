#!/usr/bin/env python3
"""Independent resource cross-check: a REAL pinned Python `RNS.Resource` consumes the
ACTUAL Rust-emitted resource wire bytes, exactly as a live peer would. Reads a
`resource payload=.. adv=.. parts=.. requests=.. proof=..` line (emitted by the rns-lite-core
`emit_resource_transfer_for_python` test) from stdin and:

  1. pins determinism: the Rust bytes must equal resource_vectors.json;
  2. RECEIVER: Python `Resource.accept`s the Rust advertisement, requests parts (its requests must
     match the Rust receiver's), reassembles the Rust ciphertext parts, and its own proof must
     equal the Rust proof;
  3. SENDER: a deterministic Python sender services the RUST part requests (its served parts must
     equal the Rust parts) and `validate_proof` accepts the Rust proof -> COMPLETE.

Shares the headless fake-link scaffolding and `RNS_VERSION` pin with gen_resource_vectors.py.
"""

import json
import os
import re
import sys
import tempfile
import time
from types import SimpleNamespace

import RNS
from RNS.Resource import Resource

from gen_resource_vectors import TARGET_RNS, Deterministic, FakeLink, build_sender, session_key

LINE = re.compile(
    r"resource\s+payload=([0-9a-f]+)\s+adv=([0-9a-f]+)\s+parts=([0-9a-f,]+)\s+"
    r"requests=([0-9a-f,]+)\s+proof=([0-9a-f]+)"
)


def python_receives(det, key, adv_bytes, rust_parts, rust_requests, payload):
    """Real Python receiver over the Rust bytes; returns (requests_match, data_match, proof)."""
    parts_by_maphash = {}
    assembled = {}

    def on_assembled(resource):
        assembled["data"] = resource.data.read()

    det.sent.clear()
    rx = Resource.accept(SimpleNamespace(plaintext=adv_bytes, link=FakeLink(key)),
                         callback=on_assembled)
    assert rx is not None, "Python Resource.accept rejected the Rust advertisement"
    for part in rust_parts:
        parts_by_maphash[rx.get_map_hash(part)] = part

    requests = []
    guard = 0
    while "data" not in assembled:
        guard += 1
        assert guard < 1000, "python receive flow did not converge"
        new_reqs = [d for (ctx, _pt, d) in det.sent if ctx == RNS.Packet.RESOURCE_REQ][len(requests):]
        for req in new_reqs:
            requests.append(req)
            wanted = [req[33 + i * 4:37 + i * 4] for i in range((len(req) - 33) // 4)]
            for mh in wanted:
                rx.receive_part(SimpleNamespace(data=parts_by_maphash[mh], raw=parts_by_maphash[mh]))
        if not new_reqs:
            time.sleep(0.01)
    deadline = time.time() + 10
    while rx.status < Resource.COMPLETE and time.time() < deadline:
        time.sleep(0.01)
    assert rx.status == Resource.COMPLETE, f"python receiver status {rx.status}"

    proofs = [d for (ctx, pt, d) in det.sent
              if ctx == RNS.Packet.RESOURCE_PRF and pt == RNS.Packet.PROOF]
    assert len(proofs) == 1
    return requests == rust_requests, assembled["data"] == payload, proofs[0]


def python_serves_and_validates(det, key, payload, rust_parts, rust_requests, rust_proof):
    """Real Python sender services the Rust receiver's requests and validates the Rust proof."""
    tx = build_sender(FakeLink(key), payload, auto_compress=False)
    tx.adv_sent = time.time()
    det.sent.clear()
    for req in rust_requests:
        tx.request(req)
    served = [d for (ctx, _pt, d) in det.sent if ctx == RNS.Packet.RESOURCE]
    served_ok = served == rust_parts and tx.status == Resource.AWAITING_PROOF

    tx.validate_proof(rust_proof)
    return served_ok, tx.status == Resource.COMPLETE


def main():
    if RNS.__version__ != TARGET_RNS:
        print(f"ERROR: target RNS {TARGET_RNS}, found {RNS.__version__}", file=sys.stderr)
        return 2
    here = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(here, "resource_vectors.json")) as f:
        v = json.load(f)

    cases = [m.groups() for m in (LINE.search(line) for line in sys.stdin) if m]
    if not cases:
        print("ERROR: no resource lines to verify (expected `resource payload=.. adv=.. ...`).",
              file=sys.stderr)
        return 2

    RNS.Reticulum.resourcepath = tempfile.mkdtemp(prefix="rns-lite-resource-verify-")
    key = session_key()
    assert key.hex() == v["session_key"], "session key drifted from the pinned vectors"

    ok = True
    for payload_hex, adv_hex, parts_hex, requests_hex, proof_hex in cases:
        payload = bytes.fromhex(payload_hex)
        adv = bytes.fromhex(adv_hex)
        parts = [bytes.fromhex(p) for p in parts_hex.split(",")]
        requests = [bytes.fromhex(r) for r in requests_hex.split(",")]
        proof = bytes.fromhex(proof_hex)

        m = v["multi"]
        pinned_ok = (
            adv.hex() == m["adv"]
            and [p.hex() for p in parts] == m["parts"]
            and [r.hex() for r in requests] == m["requests"]
            and proof.hex() == m["proof_packet"]
            and payload.hex() == m["payload"]
        )

        with Deterministic() as det:
            req_ok, data_ok, py_proof = python_receives(det, key, adv, parts, requests, payload)
            proof_ok = py_proof == proof
            served_ok, sender_ok = python_serves_and_validates(det, key, payload, parts,
                                                               requests, proof)

        print(f"resource hash={m['resource_hash'][:8]}.. pinned={pinned_ok} "
              f"python_reassembles={data_ok} requests_match={req_ok} proof_match={proof_ok} "
              f"python_serves_rust_requests={served_ok} python_validates_rust_proof={sender_ok}")
        ok = ok and pinned_ok and data_ok and req_ok and proof_ok and served_ok and sender_ok

    print(f"\nRNS {RNS.__version__} validated {len(cases)} Rust resource transfer(s)." if ok
          else "\nFAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
