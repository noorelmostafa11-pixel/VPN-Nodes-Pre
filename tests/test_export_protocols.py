import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.export_protocols import export_protocols

nodes = [
    {"protocol": "vless", "uri": "vless://a@host:443?type=ws"},
    {"protocol": "vmess", "uri": "vmess://abc"},
    {"protocol": "trojan", "uri": "trojan://p@host:443"},
    {"protocol": "shadowsocks", "uri": "ss://abc"},
]
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    src = root / "xray_candidates.json"
    src.write_text(json.dumps({"tcp_reachable": 4, "nodes": nodes}), encoding="utf-8")
    out = root / "protocols"
    counts = export_protocols(src, out)
    assert counts == {"vless": 1, "vmess": 1, "trojan": 1, "shadowsocks": 1}
    assert sorted(p.name for p in out.iterdir()) == [
        "shadowsocks.txt", "trojan.txt", "vless.txt", "vmess.txt"
    ]
print("PASS")
