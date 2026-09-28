#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
from collections import Counter
from pathlib import Path

PROTOCOLS = ("vless", "vmess", "trojan", "shadowsocks")
EXPECTED_SCHEMES = {
    "vless": "vless://",
    "vmess": "vmess://",
    "trojan": "trojan://",
    "shadowsocks": "ss://",
}

def export_protocols(input_path: Path, output_dir: Path) -> dict[str, int]:
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    nodes = payload.get("nodes")
    if not isinstance(nodes, list):
        raise ValueError("xray_candidates.json does not contain a nodes list")
    declared_total = payload.get("tcp_reachable")
    if declared_total is not None and int(declared_total) != len(nodes):
        raise ValueError(f"candidate count mismatch: declared={declared_total} actual={len(nodes)}")

    tmp_dir = output_dir.parent / f".{output_dir.name}.tmp"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True, exist_ok=True)

    handles = {
        proto: (tmp_dir / f"{proto}.txt").open("w", encoding="utf-8", newline="\n")
        for proto in PROTOCOLS
    }
    counts: Counter[str] = Counter()
    try:
        for index, item in enumerate(nodes):
            if not isinstance(item, dict):
                raise ValueError(f"candidate #{index} is not an object")
            protocol = str(item.get("protocol") or "").lower()
            if protocol not in handles:
                raise ValueError(f"candidate #{index} has unsupported protocol {protocol!r}")
            uri = item.get("uri")
            if not isinstance(uri, str) or not uri:
                raise ValueError(f"candidate #{index} has an empty URI")
            if "\n" in uri or "\r" in uri:
                raise ValueError(f"candidate #{index} URI contains a newline")
            if not uri.lower().startswith(EXPECTED_SCHEMES[protocol]):
                raise ValueError(f"candidate #{index} protocol/URI mismatch: {protocol!r}")
            handles[protocol].write(uri + "\n")
            counts[protocol] += 1
    finally:
        for handle in handles.values():
            handle.close()

    if sum(counts.values()) != len(nodes):
        raise ValueError("exported protocol count does not match candidate count")

    if output_dir.exists():
        shutil.rmtree(output_dir)
    os.replace(tmp_dir, output_dir)

    actual = sorted(p.name for p in output_dir.iterdir() if p.is_file())
    expected = sorted(f"{p}.txt" for p in PROTOCOLS)
    if actual != expected:
        raise ValueError(f"unexpected output files: {actual!r}")

    print(f"SOURCE_CANDIDATES={len(nodes)}")
    for proto in PROTOCOLS:
        path = output_dir / f"{proto}.txt"
        print(f"{proto.upper()}={counts[proto]} bytes={path.stat().st_size}")
    return dict(counts)

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    export_protocols(args.input, args.output)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
