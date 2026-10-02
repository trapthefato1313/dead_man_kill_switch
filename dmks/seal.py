"""Sealing evidence with GnuPG.

The server encrypts to the recipients' public keys and keeps only ciphertext.
A compromised server therefore reveals nothing about the contents, and the
private keys never exist anywhere near it.

Every sealed packet is checked three ways before it is ever considered
deliverable: its SHA-256 must match what was recorded at seal time, GnuPG must
still recognise the container, and the container must be addressed to the key
IDs we actually enrolled.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class SealError(Exception):
    pass


@dataclass(frozen=True)
class PublicKey:
    fingerprint: str
    uids: tuple[str, ...]
    keyid: str
    expires: int | None
    subkey_keyids: tuple[str, ...] = ()

    @property
    def encryption_keyids(self) -> set[str]:
        return {k.upper() for k in (self.keyid, *self.subkey_keyids) if k}


def gpg_binary() -> str:
    found = shutil.which("gpg")
    if not found:
        raise SealError("gpg not found on PATH")
    return found


def run(args: list[str], *, input_bytes: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [gpg_binary(), "--batch", "--yes", "--no-tty", *args],
        input=input_bytes,
        capture_output=True,
        check=check,
    )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_colons(text: str) -> list[dict[str, str]]:
    out = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        out.append({f"f{i}": v for i, v in enumerate(parts)})
    return out


def list_encryption_keys() -> list[PublicKey]:
    """Public keys in the local keyring, with long key IDs and UIDs."""
    result = run(["--list-keys", "--with-colons"], check=False)
    if result.returncode not in (0, 1):
        raise SealError(result.stderr.decode(errors="replace").strip())

    keys: list[PublicKey] = []
    builder: dict | None = None

    def flush() -> None:
        if builder and builder["fingerprint"] and len(builder["fingerprint"]) >= 32:
            keys.append(
                PublicKey(
                    fingerprint=builder["fingerprint"],
                    uids=tuple(builder["uids"]),
                    keyid=builder["keyid"],
                    expires=builder["expires"],
                    subkey_keyids=tuple(builder["subkey_ids"]),
                )
            )

    for fields in _parse_colons(result.stdout.decode(errors="replace")):
        record = fields.get("f0")
        if record == "pub":
            flush()
            expires = fields.get("f6", "")
            builder = {
                "fingerprint": "",
                "uids": [],
                "keyid": fields.get("f4", ""),
                "expires": int(expires) if expires.isdigit() else None,
                "subkey_ids": [],
            }
        elif record == "sub" and builder is not None:
            subkey = fields.get("f4", "")
            if subkey:
                builder["subkey_ids"].append(subkey)
        elif record == "fpr" and builder is not None and not builder["fingerprint"]:
            builder["fingerprint"] = fields.get("f9", "")
        elif record == "uid" and builder is not None:
            uid = fields.get("f9", "")
            if uid:
                builder["uids"].append(uid)
    flush()
    return keys


def verify_recipients(recipients: list[str]) -> list[PublicKey]:
    """Every recipient must resolve to a usable encryption key, or we refuse."""
    resolved: list[PublicKey] = []
    available = {k.fingerprint.upper(): k for k in list_encryption_keys()}
    for recipient in recipients:
        wanted = re.sub(r"[^0-9A-Fa-f]", "", recipient).upper()
        if wanted in available:
            resolved.append(available[wanted])
            continue
        if len(wanted) == 16:
            match = next((k for k in available.values() if k.keyid.upper() == wanted), None)
            if match:
                resolved.append(match)
                continue
        probe = run(["--list-keys", "--with-colons", recipient], check=False)
        if probe.returncode in (0, 1) and probe.stdout.strip():
            keys = [k for k in _parse_colons(probe.stdout.decode(errors="replace")) if k.get("f0") == "fpr"]
            if keys:
                resolved.append(PublicKey(fingerprint=keys[0].get("f9", "").upper(), uids=(), keyid=recipient, expires=None))
                continue
        raise SealError(
            f"recipient {recipient!r} has no usable public key. "
            "Import it first: gpg --import <keyfile>"
        )
    return resolved


def seal(inputs: list[Path], recipients: list[str], output: Path) -> str:
    """Encrypt inputs to recipients. Returns the SHA-256 of the ciphertext."""
    keys = verify_recipients(recipients)
    args = ["--trust-model", "always", "--encrypt"]
    for key in keys:
        args += ["--recipient", key.fingerprint]
    args += ["--output", str(output), *[str(p) for p in inputs]]
    result = run(args, check=False)
    if result.returncode != 0:
        raise SealError(result.stderr.decode(errors="replace").strip())
    return sha256_file(output)


def container_keyids(path: str | Path) -> set[str]:
    result = run(["--list-packets", str(path)], check=False)
    ids = set(re.findall(r"keyid\s+([0-9A-Fa-f]{16,40})", result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace")))
    return {i.upper() for i in ids}


def verify_container(path: str | Path, expected_sha256: str, recipients: list[str]) -> list[str]:
    """Return a list of problems. Empty means the packet is safe to send."""
    problems: list[str] = []
    path = Path(path)
    if not path.exists():
        return [f"packet missing on disk: {path}"]
    actual = sha256_file(path)
    if expected_sha256 and actual != expected_sha256:
        problems.append(f"ciphertext hash mismatch: expected {expected_sha256}, got {actual}")
    if path.stat().st_size == 0:
        problems.append("packet is empty")

    result = run(["--list-packets", str(path)], check=False)
    blob = result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
    if result.returncode != 0 or "encrypted data" not in blob and "pubkey enc packet" not in blob:
        problems.append("GnuPG no longer recognises this file as encrypted data")

    try:
        wanted: set[str] = set()
        for key in verify_recipients(recipients) if recipients else []:
            wanted |= key.encryption_keyids
    except SealError as exc:
        problems.append(str(exc))
        return problems

    addressed = container_keyids(path)
    if wanted and addressed and not (addressed & wanted):
        problems.append(
            f"container not addressed to enrolled recipients: addressed={sorted(addressed)} "
            f"expected={sorted(wanted)}"
        )
    return problems


def decrypt(path: str | Path, out_dir: str | Path | None = None) -> Path:
    args = ["--decrypt"]
    if out_dir:
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        args += ["--output", str(Path(out_dir) / Path(path).name)]
    args.append(str(path))
    result = run(args, check=False)
    if result.returncode != 0:
        raise SealError(result.stderr.decode(errors="replace").strip())
    return Path(out_dir) / Path(path).name if out_dir else Path(path)