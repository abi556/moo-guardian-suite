"""
guardian.py
-------------

A small security toolkit to defend against the teaching malware "moo".

Core capabilities:
- Detect the moo binary by exact SHA-256 fingerprint (stored in signatures.json)
- Quarantine or remove detected moo binaries
- Decrypt files that were scrambled by moo

This file exposes a single CLI with subcommands: scan, decrypt-file, decrypt-dir.
It is intended for classroom/lab demonstrations; use only on disposable test data.
"""

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
from typing import Optional, List, Tuple


def load_signatures() -> dict:
    """Load signatures from signatures.json located next to this script.

    Returns a mapping with at least the key "moo_sha256" containing the
    expected SHA-256 hash string for the moo binary to detect.
    """
    repo_dir = Path(__file__).resolve().parent
    sig_path = repo_dir / "signatures.json"
    if not sig_path.exists():
        raise FileNotFoundError(f"signatures.json not found at {sig_path}")
    with sig_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def file_sha256(path: Path, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 digest of a file efficiently in chunks."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def is_moo(path: Path, signatures: dict) -> bool:
    """Return True if the file's SHA-256 matches the known moo fingerprint."""
    try:
        return file_sha256(path) == signatures.get("moo_sha256")
    except Exception:
        return False


def ensure_quarantine_dir(path: Path) -> None:
    """Create the quarantine directory if it does not already exist."""
    path.mkdir(parents=True, exist_ok=True)


def quarantine(path: Path, quarantine_dir: Path) -> Path:
    """Move the detected file into the quarantine directory and return destination path."""
    ensure_quarantine_dir(quarantine_dir)
    dest = quarantine_dir / (path.name + ".quarantine")
    shutil.move(str(path), str(dest))
    return dest


def moo_decrypt_bytes(data: bytes) -> bytes:
    """Apply the inverse transform of moo to a bytes object and return plaintext.

    Moo encrypts each byte as E(x) = (x + 4) XOR 0xFF.
    The inverse is D(y) = (y XOR 0xFF) - 4 (mod 256).
    """
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = ((b ^ 0xFF) - 4) & 0xFF
    return bytes(out)


def decrypt_file(path: Path, in_place: bool = True, output: Optional[Path] = None) -> Path:
    """Decrypt a single file in place or write the result to an explicit output path."""
    with path.open("rb") as f:
        data = f.read()
    dec = moo_decrypt_bytes(data)
    if in_place or output is None:
        with path.open("wb") as f:
            f.write(dec)
        return path
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("wb") as f:
            f.write(dec)
        return output


def scan_directory(root: Path, signatures: dict, quarantine_dir: Optional[Path] = None, remove: bool = False) -> List[Tuple[Path, str]]:
    """Walk a directory tree recursively and act on any moo detections.

    Returns a list of (path, status) tuples where status is one of
    "detected", "quarantined -> <dest>", "removed", or "remove_failed".
    """
    findings: List[Tuple[Path, str]] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if is_moo(p, signatures):
                    if remove:
                        try:
                            p.unlink()
                            findings.append((p, "removed"))
                        except Exception:
                            findings.append((p, "remove_failed"))
                    elif quarantine_dir is not None:
                        dest = quarantine(p, quarantine_dir)
                        findings.append((p, f"quarantined -> {dest}"))
                    else:
                        findings.append((p, "detected"))
            except Exception:
                continue
    return findings


def scan_file(path: Path, signatures: dict, quarantine_dir: Optional[Path] = None, remove: bool = False) -> Optional[str]:
    """Check a single file and optionally quarantine or remove it if detected."""
    if is_moo(path, signatures):
        if remove:
            try:
                path.unlink()
                return "removed"
            except Exception:
                return "remove_failed"
        if quarantine_dir is not None:
            dest = quarantine(path, quarantine_dir)
            return f"quarantined -> {dest}"
        return "detected"
    return None


def cmd_scan(args) -> int:
    """CLI handler for the scan subcommand."""
    sigs = load_signatures()
    quarantine_dir = Path(args.quarantine_dir).expanduser().resolve() if args.quarantine else None
    target = Path(args.path).expanduser().resolve()
    if target.is_dir():
        results = scan_directory(target, sigs, quarantine_dir=quarantine_dir, remove=args.remove)
        for p, status in results:
            print(f"{p}: {status}")
        print(f"Total matches: {len(results)}")
        return 0
    else:
        status = scan_file(target, sigs, quarantine_dir=quarantine_dir, remove=args.remove)
        if status:
            print(f"{target}: {status}")
            return 0
        print("No match")
        return 0


def cmd_decrypt_file(args) -> int:
    """CLI handler for decrypting a single file."""
    target = Path(args.path).expanduser().resolve()
    if args.output:
        out = Path(args.output).expanduser().resolve()
        res = decrypt_file(target, in_place=False, output=out)
    else:
        res = decrypt_file(target, in_place=True)
    print(f"Decrypted: {res}")
    return 0


def cmd_decrypt_dir(args) -> int:
    """CLI handler for decrypting all files under a directory recursively (in place)."""
    root = Path(args.path).expanduser().resolve()
    count = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            p = Path(dirpath) / name
            try:
                decrypt_file(p, in_place=True)
                count += 1
            except Exception:
                continue
    print(f"Decrypted files: {count}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build and return the argument parser for the guardian CLI."""
    parser = argparse.ArgumentParser(prog="guardian", description="Detect/quarantine/remove moo and decrypt files")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan file or directory for moo binary and optionally quarantine or remove")
    p_scan.add_argument("path", help="Path to file or directory to scan")
    group = p_scan.add_mutually_exclusive_group()
    group.add_argument("--quarantine", action="store_true", help="Quarantine detected moo binaries")
    group.add_argument("--remove", action="store_true", help="Delete detected moo binaries")
    p_scan.add_argument("--quarantine-dir", default=str(Path.home() / "quarantine"), help="Quarantine directory (default: ~/quarantine)")
    p_scan.set_defaults(func=cmd_scan)

    p_dec_f = sub.add_parser("decrypt-file", help="Decrypt a single file in-place or to an output path")
    p_dec_f.add_argument("path", help="Path to encrypted file")
    p_dec_f.add_argument("--output", help="Optional output path; if omitted, decrypts in place")
    p_dec_f.set_defaults(func=cmd_decrypt_file)

    p_dec_d = sub.add_parser("decrypt-dir", help="Decrypt all files under a directory in-place (recursive)")
    p_dec_d.add_argument("path", help="Directory to decrypt recursively")
    p_dec_d.set_defaults(func=cmd_decrypt_dir)

    return parser


def main() -> int:
    """Entry point for the CLI program."""
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
