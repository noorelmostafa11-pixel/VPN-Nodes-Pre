from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
workflow = (ROOT / ".github/workflows/prepare.yml").read_text(encoding="utf-8")
assert "noorelmostafa11-pixel/VPN-Nodes" not in workflow
assert "public/output" not in workflow
assert "Checkout this repository only" in workflow
for path in (
    ROOT / "sources/sources.json",
    ROOT / "scripts/merge_and_build_tcp_pool.py",
    ROOT / "scripts/node_identity.py",
    ROOT / "scripts/xray_matrix/build_tcp_candidates.py",
):
    assert path.is_file(), path
print("PASS: scanner is operationally independent")
