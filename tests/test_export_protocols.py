import json
import io
import sys
import tempfile
from contextlib import redirect_stdout
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

base = "vless://a@host:443?type=ws&path=%2Fws"
nodes_with_duplicates = [
    {"protocol": "vless", "uri": base + "#first"},
    {"protocol": "vless", "uri": base + "#second"},
    {"protocol": "vless", "uri": base + "#first"},
    {"protocol": "vless", "uri": base.replace("type=ws&path=%2Fws", "path=%2Fws&type=ws") + "#other"},
    {"protocol": "vless", "uri": base.replace("%2Fws", "/ws") + "#decoded"},
    *nodes[1:],
]
with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    src = root / "xray_candidates.json"
    src.write_text(json.dumps({"tcp_reachable": len(nodes_with_duplicates), "nodes": nodes_with_duplicates}), encoding="utf-8")
    out = root / "protocols"
    log = io.StringIO()
    with redirect_stdout(log):
        counts = export_protocols(src, out)
    assert counts == {"vless": 3, "vmess": 1, "trojan": 1, "shadowsocks": 1}
    assert (out / "vless.txt").read_text(encoding="utf-8").splitlines() == [
        base + "#first",
        base.replace("type=ws&path=%2Fws", "path=%2Fws&type=ws") + "#other",
        base.replace("%2Fws", "/ws") + "#decoded",
    ]
    assert "EXACT_DUPLICATES_REMOVED=1" in log.getvalue()
    assert "LITERAL_BEFORE_FRAGMENT_REMOVED=1" in log.getvalue()
    assert nodes_with_duplicates[0]["uri"] == base + "#first"
print("PASS")
