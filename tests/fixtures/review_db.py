"""База для тестов разбора источников (US4): прогоны «до» (группировка как в 002) и «после».

Прогоны пишутся прямо через `store.write_run`, а рядом кладутся `verdicts.parquet` (метки) и
`flows.parquet` (поля потока для правила направления) — ровно то, что читает `soc.review`.
Так тест не зависит от того, что именно найдёт детектор на синтетике, и каждый случай
(ответный поток, ошибка детектора, настоящие атакующие) задан явно.

Потоки:
- r1: 149.171.126.17:80 → 175.45.176.0 — TCP, SYN только у второй стороны → ответный,
  по разметке exploits («атака, записанная от сервера»);
- d1: 59.166.0.3:5227 → 149.171.126.5:53 — UDP DNS фона, по разметке норма → ошибка детектора;
- a1, a2: настоящие атаки с 175.45.176.1 (dos) и 175.45.176.2 (exploits).
"""

from __future__ import annotations

import json
from pathlib import Path

import polars as pl

from mlsiem.soc import store

FLOWS = [
    # flow_uid, src, sport, dst, dport, proto, s2d_syn, d2s_syn, label, class
    ("r1", "149.171.126.17", 80, "175.45.176.0", 40000, 6, 0, 1, "exploits", "exploits"),
    ("d1", "59.166.0.3", 5227, "149.171.126.5", 53, 17, 0, 0, "benign", "dos"),
    ("a1", "175.45.176.1", 41000, "149.171.126.3", 80, 6, 1, 1, "dos", "dos"),
    ("a2", "175.45.176.2", 42000, "149.171.126.4", 445, 6, 1, 1, "exploits", "exploits"),
]


def _write(conn, cfg, run_id, incidents: list[tuple[str, str, list[str]]], *, labels=True):
    """incidents: (атакующий IP, класс, flow_uid алертов)."""
    by_uid = {f[0]: f for f in FLOWS}
    alerts, incs = [], []
    for k, (ip, cls, uids) in enumerate(incidents):
        iid = f"{run_id}-inc{k}"
        targets = sorted({by_uid[u][3] if by_uid[u][1] == ip else by_uid[u][1] for u in uids})
        incs.append(
            {
                "incident_id": iid,
                "src_ip": ip,
                "attack_class": cls,
                "targets": json.dumps(targets),
                "first_seen_ms": k,
                "last_seen_ms": k + 1,
                "n_alerts": len(uids),
                "max_score": 0.99,
                "mean_score": 0.99,
                "severity": "medium",
                "severity_reason": "база",
            }
        )
        for u in uids:
            f = by_uid[u]
            alerts.append(
                {
                    "flow_uid": u,
                    "capture_id": "c",
                    "src_ip": f[1],
                    "src_port": f[2],
                    "dst_ip": f[3],
                    "dst_port": f[4],
                    "protocol": f[5],
                    "first_seen_ms": k,
                    "last_seen_ms": k + 1,
                    "predicted_class": cls,
                    "attack_score": 0.99,
                    "incident_id": iid,
                }
            )
    store.write_run(
        conn,
        {
            "run_id": run_id,
            "source": f"pcap:{run_id}.pcap",
            "input_hash": run_id,
            "detector_version": "det",
            "started_at": f"2026-01-0{len(run_id) % 9 + 1}T00:00:00Z",
            "n_flows": len(FLOWS),
            "summary": {},
        },
        alerts,
        incs,
    )
    run_dir = Path(cfg.runs_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    flows = pl.DataFrame(
        {
            "flow_uid": [f[0] for f in FLOWS],
            "src_ip": [f[1] for f in FLOWS],
            "src_port": [f[2] for f in FLOWS],
            "dst_ip": [f[3] for f in FLOWS],
            "dst_port": [f[4] for f in FLOWS],
            "protocol": [f[5] for f in FLOWS],
            "src2dst_syn_packets": [f[6] for f in FLOWS],
            "dst2src_syn_packets": [f[7] for f in FLOWS],
        }
    )
    flows.write_parquet(run_dir / "flows.parquet")
    verdicts = {"flow_uid": [f[0] for f in FLOWS], "is_alert": [True] * len(FLOWS)}
    if labels:
        verdicts["true_label"] = [f[8] for f in FLOWS]
    pl.DataFrame(verdicts).write_parquet(run_dir / "verdicts.parquet")


def build_review_db(cfg, *, lose_attacker: bool = False) -> None:
    """Прогоны `before` (как 002: ключ — src_ip) и `after` (атакующая сторона по правилу)."""
    conn = store.connect(cfg.db)
    store.init_db(conn)
    _write(
        conn,
        cfg,
        "before",
        [
            ("149.171.126.17", "exploits", ["r1"]),
            ("59.166.0.3", "dos", ["d1"]),
            ("175.45.176.1", "dos", ["a1"]),
            ("175.45.176.2", "exploits", ["a2"]),
        ],
    )
    after = [
        ("175.45.176.0", "exploits", ["r1"]),
        ("59.166.0.3", "dos", ["d1"]),
        ("175.45.176.1", "dos", ["a1"]),
    ]
    if not lose_attacker:
        after.append(("175.45.176.2", "exploits", ["a2"]))
    _write(conn, cfg, "after", after)
    _write(conn, cfg, "nolabels", [("175.45.176.1", "dos", ["a1"])], labels=False)
    conn.close()
