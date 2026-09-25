"""Правило атакующей стороны (research R8, FR-023): по данным самого потока, без сетей и меток."""

import ast
from pathlib import Path

import polars as pl
import pytest

from mlsiem.soc.direction import as_is, attacker_side, sides

SRC = Path(__file__).parents[2] / "src" / "mlsiem" / "soc" / "direction.py"


def flow(uid, src, sport, dst, dport, proto, s2d_syn=0, d2s_syn=0):
    return {
        "flow_uid": uid,
        "src_ip": src,
        "src_port": sport,
        "dst_ip": dst,
        "dst_port": dport,
        "protocol": proto,
        "src2dst_syn_packets": s2d_syn,
        "dst2src_syn_packets": d2s_syn,
    }


CASES = [
    # (поток, перевёрнут?, правило)
    (flow("t1", "149.171.126.17", 80, "175.45.176.0", 40000, 6, 0, 1), True, "tcp_syn"),
    (flow("t2", "175.45.176.1", 443, "149.171.126.3", 80, 6, 1, 1), False, "tcp_syn_src"),
    (flow("t3", "149.171.126.11", 25, "175.45.176.1", 50000, 6, 0, 0), True, "service_port"),
    (flow("u1", "59.166.0.4", 5227, "149.171.126.5", 53, 17), False, "default"),
    (flow("u2", "149.171.126.5", 53, "59.166.0.4", 5227, 17), True, "service_port"),
    (flow("e1", "59.166.0.4", 40000, "149.171.126.5", 50000, 6, 0, 0), False, "default"),
    (flow("i1", "10.0.0.1", None, "10.0.0.2", None, 1), False, "default"),
]


@pytest.mark.parametrize("f, rev, rule", CASES)
def test_rules(f, rev, rule):
    out = attacker_side(pl.DataFrame([f])).row(0, named=True)
    assert (out["reversed"], out["direction_rule"]) == (rev, rule)
    if rev:
        assert (out["attacker_ip"], out["victim_ip"]) == (f["dst_ip"], f["src_ip"])
    else:
        assert (out["attacker_ip"], out["victim_ip"]) == (f["src_ip"], f["dst_ip"])


def test_vector_equals_row_by_row():
    frame = pl.DataFrame([c[0] for c in CASES])
    vec = attacker_side(frame)
    one = pl.concat([attacker_side(pl.DataFrame([c[0]])) for c in CASES])
    assert vec.equals(one)


def test_as_is_mode():
    frame = pl.DataFrame([c[0] for c in CASES])
    out = as_is(frame)
    assert not out["reversed"].any()
    assert out["attacker_ip"].to_list() == frame["src_ip"].to_list()
    assert sides(frame, "as_is").equals(out)
    with pytest.raises(ValueError, match="auto или as_is"):
        sides(frame, "reverse")


def test_missing_columns():
    with pytest.raises(ValueError, match="src2dst_syn_packets"):
        attacker_side(pl.DataFrame([{"flow_uid": "x", "src_ip": "1.1.1.1"}]))


def test_rule_knows_no_networks_and_no_labels():
    tree = ast.parse(SRC.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
    for forbidden in ("mlsiem.soc.config", "mlsiem.soc.flags", "mlsiem.soc.review", "ipaddress"):
        assert forbidden not in imported, forbidden
    strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant)}
    assert "label" not in strings and "true_label" not in strings
    # и никаких адресов сетей UNSW-NB15 в коде правила
    code = SRC.read_text(encoding="utf-8").split('"""', 2)[2]
    assert "149.171" not in code and "59.166" not in code and "175.45" not in code
