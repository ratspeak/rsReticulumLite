#!/usr/bin/env python3
"""Validate rsReticulumLite's public source and dormant-release invariants."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://github.com/ratspeak/rsReticulumLite"
EXPECTED_VERSION = "0.1.0"
EXPECTED_RUST_VERSION = "1.87"
EXPECTED_RNS_VALIDATOR = "1.4.2"
SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
LINK_PATTERN = re.compile(r"\[[^]]+\]\(([^)]+)\)")


def fail(message: str) -> None:
    raise SystemExit(f"source-release contract failed: {message}")


def command(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def check_required_files() -> None:
    required = [
        ".github/workflows/ci.yml",
        ".github/workflows/release-readiness.yml",
        "LICENSE",
        "README.md",
        "SECURITY.md",
        "TRUSTED_REF",
        "tests/api/Cargo.lock",
        "tests/api/Cargo.toml",
        "rust-toolchain.toml",
    ]
    missing = [path for path in required if not (ROOT / path).is_file()]
    if missing:
        fail(f"required public files are missing: {', '.join(missing)}")


def check_metadata() -> None:
    document = json.loads(
        command("cargo", "metadata", "--format-version", "1", "--locked", "--no-deps")
    )
    packages = document["packages"]
    if len(packages) != 1:
        fail(f"expected one workspace package, found {len(packages)}")
    package = packages[0]
    problems = []
    expected = {
        "name": "rns-lite-core",
        "version": EXPECTED_VERSION,
        "rust_version": EXPECTED_RUST_VERSION,
        "license": "AGPL-3.0-or-later",
        "repository": REPOSITORY,
    }
    for key, value in expected.items():
        if package.get(key) != value:
            problems.append(f"{key}={package.get(key)!r}, expected {value!r}")
    if package.get("publish") != []:
        problems.append("package must remain publish = false until explicitly approved")
    if not package.get("description") or not package.get("keywords"):
        problems.append("package description/keywords are incomplete")
    if problems:
        fail("; ".join(problems))


def read_refs(path: str) -> dict[str, str]:
    refs: dict[str, str] = {}
    for line in (ROOT / path).read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        try:
            name, commit = line.split()
        except ValueError:
            fail(f"malformed {path} line: {line!r}")
        if not SHA_PATTERN.fullmatch(commit):
            fail(f"{path} does not pin {name} to a full commit")
        refs[name] = commit
    if not refs:
        fail(f"{path} contains no pins")
    return refs


def check_workflows(refs: dict[str, str]) -> None:
    workflows = ROOT / ".github/workflows"
    combined = ""
    for path in sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")]):
        text = path.read_text(encoding="utf-8")
        combined += text
        if "contents: write" in text:
            fail(f"workflow requests publishing permission: {path.name}")
        checkouts = re.findall(
            r"(?ms)^      - (?:name:[^\n]+\n        )?uses: actions/checkout@.*?(?=^      - |\Z)",
            text,
        )
        for checkout in checkouts:
            if "persist-credentials: false" not in checkout:
                fail(f"checkout retains credentials in {path.name}")
            if "secrets.PRIVATE_LITE_READ_TOKEN" in checkout:
                if "secrets.PRIVATE_LITE_READ_TOKEN || github.token" not in checkout:
                    fail(f"private checkout lacks a public-token fallback in {path.name}")
        for action in re.findall(r"^\s*(?:-\s+)?uses:\s+([^\s#]+)", text, re.MULTILINE):
            if action.startswith("./"):
                continue
            if "@" not in action or not SHA_PATTERN.fullmatch(action.rsplit("@", 1)[1]):
                fail(f"workflow action is not commit-pinned ({path.name}): {action}")
    for name, commit in refs.items():
        if commit not in combined:
            fail(f"workflow checkout does not use the reviewed {name} pin")

    release = (workflows / "release-readiness.yml").read_text(encoding="utf-8")
    forbidden = ["contents: write", "action-gh-release", "push:\n    tags:"]
    for token in forbidden:
        if token in release:
            fail(f"release-readiness workflow must remain non-publishing ({token!r})")
    if "workflow_dispatch:" not in release:
        fail("release-readiness workflow is not manual-only")

    validator_pin = f'RSLITE_PYTHON_RNS_VERSION: "{EXPECTED_RNS_VALIDATOR}"'
    if combined.count(validator_pin) != 2:
        fail("CI and release readiness must pin the reviewed Python RNS validator")
    if "rns==1.3.8" in combined or "RNS 1.3.8" in combined:
        fail("workflow still references the retired Python RNS 1.3.8 validator")


def check_python_validator() -> None:
    version = (ROOT / "vectors/RNS_VERSION").read_text(encoding="utf-8").strip()
    if version != EXPECTED_RNS_VALIDATOR:
        fail(
            f"vectors/RNS_VERSION={version!r}, expected {EXPECTED_RNS_VALIDATOR!r}"
        )
    for relative in [
        "vectors/gen_resource_vectors.py",
        "vectors/verify_rust_resource.py",
        "vectors/run.sh",
    ]:
        text = (ROOT / relative).read_text(encoding="utf-8")
        if "RNS_VERSION" not in text:
            fail(f"{relative} does not consume the exact validator version pin")


def check_documents() -> None:
    for path in source_files():
        if path.suffix.lower() != ".md":
            continue
        if path.relative_to(ROOT).as_posix() not in {"README.md", "SECURITY.md"}:
            fail(f"unexpected public Markdown file: {path.relative_to(ROOT)}")
        text = path.read_text(encoding="utf-8")
        for target in LINK_PATTERN.findall(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            relative = target.split("#", 1)[0]
            if relative:
                resolved = (path.parent / relative).resolve()
                if not resolved.is_relative_to(ROOT):
                    fail(f"Markdown link leaves the repository in {path.relative_to(ROOT)}: {target}")
                if not resolved.exists():
                    fail(f"broken local Markdown link in {path.relative_to(ROOT)}: {target}")


def source_files():
    excluded = {".git", "target", ".venv", "__pycache__"}
    for directory, subdirs, names in os.walk(ROOT):
        subdirs[:] = [name for name in subdirs if name not in excluded]
        for name in names:
            yield Path(directory) / name


def check_public_hygiene() -> None:
    banned_names = {
        "agents.md", "claude.md", ".cursorrules", "rsnode_sync",
        "check-rsnode-sync.sh",
    }
    banned_dirs = {".agents", ".claude", ".codex"}
    forbidden_text = [
        "/Users/",
        "main/scripts/adjudicate-window.sh",
        "docs/internal-ai-agent-backups",
        "docs/active/",
        "docs/audits/",
        "Private during development",
    ]
    suffixes = {".md", ".py", ".rs", ".sh", ".toml", ".yaml", ".yml"}
    for path in source_files():
        relative = path.relative_to(ROOT)
        lowered = path.name.lower()
        if (
            lowered in banned_names
            or lowered.startswith("codex")
            or banned_dirs.intersection(part.lower() for part in relative.parts)
            or relative.parts[:2] in {("docs", "audits"), ("docs", "plans")}
        ):
            fail(f"internal file present in public source: {relative}")
        if path.resolve() == Path(__file__).resolve() or path.suffix not in suffixes:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for token in forbidden_text:
            if token in text:
                fail(f"private/internal reference {token!r} in {relative}")


def check_toolchain() -> None:
    toolchain = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    if 'channel = "1.87.0"' not in toolchain:
        fail("rust-toolchain.toml does not pin Rust 1.87.0")
    if 'msrv = "1.87"' not in (ROOT / "clippy.toml").read_text(encoding="utf-8"):
        fail("clippy.toml MSRV does not match Cargo.toml")


def check_release_tag(release_tag: str) -> None:
    expected = f"v{EXPECTED_VERSION}"
    if release_tag != expected:
        fail(f"release tag {release_tag!r} does not match {expected!r}")
    try:
        if command("git", "cat-file", "-t", release_tag) != "tag":
            fail(f"release tag {release_tag!r} must be annotated")
    except subprocess.CalledProcessError:
        fail(f"release tag {release_tag!r} is not present")
    if command("git", "rev-parse", "HEAD") != command("git", "rev-list", "-n", "1", release_tag):
        fail(f"HEAD is not the commit named by {release_tag}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-tag")
    args = parser.parse_args()
    check_required_files()
    check_metadata()
    refs = read_refs("TRUSTED_REF")
    check_workflows(refs)
    check_python_validator()
    check_documents()
    check_public_hygiene()
    check_toolchain()
    if args.release_tag:
        check_release_tag(args.release_tag)
    print(f"source-release contract passed for rsReticulumLite {EXPECTED_VERSION}")


if __name__ == "__main__":
    main()
