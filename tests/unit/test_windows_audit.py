"""Аудит модели окон на артефакты (фича 007, US2, research R10, FR-012).

Проверяется логика по частям: откуда берутся подозрительные признаки, когда вердикт
«опирается на артефакты», как решение аудита ложится в карточку, и групповая перестановка
канала у нейросети. Весь аудит целиком на синтетике — в integration/test_windows_audit_cli.py.
"""

import json
import shutil

import numpy as np
import polars as pl
import pytest

from mlsiem.detect import windows_audit as A
from mlsiem.detect.windows import seq_feature_names, summary_feature_names
from mlsiem.detect.windows_expert import read_card, update_decision

# ---------------------------------------------------------------- подозрительные признаки


def _write_data_audit(data_dir, rows):
    (data_dir / "audit").mkdir(parents=True, exist_ok=True)
    pl.DataFrame(
        rows,
        schema={"field": pl.String, "variant": pl.String, "status": pl.String},
        orient="row",
    ).with_columns(
        pl.lit(0.5).alias("pr_auc_macro"), pl.lit(0.1).alias("baseline"), pl.lit(0.4).alias("lift")
    ).write_parquet(data_dir / "audit" / "unsw_time.parquet")


def test_data_audit_fields_not_ok(tmp_path):
    """Подозрительные из аудита 001 — всё, кроме ok и n/a (n/a — «не оценивалось»)."""
    _write_data_audit(
        tmp_path,
        [
            ("bidirectional_bytes", "raw", "suspicious"),
            ("requested_server_name", "raw", "dangerous"),
            ("src_port", "raw", "ok"),
            ("vlan_id", "raw", "n/a"),
        ],
    )
    got = A.data_audit_fields("unsw_time", tmp_path)
    assert got["found"]
    assert {f["field"] for f in got["fields"]} == {"bidirectional_bytes", "requested_server_name"}


def test_data_audit_missing_is_not_error(tmp_path):
    got = A.data_audit_fields("unsw_time", tmp_path)
    assert got == {
        "found": False,
        "path": (tmp_path / "audit" / "unsw_time.parquet").as_posix(),
        "fields": [],
    }


def test_window_features_of_maps_all_stats():
    """Поле потока → все три его статистики во входе бустинга и канал у нейросети; поле,
    которого во входе нет (DPI), ничего не даёт."""
    summary = summary_feature_names()
    got = A.window_features_of(["bidirectional_bytes", "requested_server_name"], summary)
    assert got == [f"f_bidirectional_bytes_{s}" for s in ("mean", "max", "std")]
    assert A.window_features_of(["bidirectional_bytes"], seq_feature_names()) == [
        "bidirectional_bytes"
    ]


def test_inputs_have_no_forbidden():
    assert A.forbidden_inputs(summary_feature_names()) == []
    assert A.forbidden_inputs(seq_feature_names()) == []
    assert A.forbidden_inputs(["f_src_port_max", "w_n_targets", "attacker_ip"]) == [
        "f_src_port_max",
        "attacker_ip",
    ]


def test_fill_nan_uses_column_median():
    X = np.array([[1.0, np.nan], [3.0, 2.0], [np.nan, 4.0]])
    out = A._fill_nan(X)
    assert not np.isnan(out).any()
    assert out[2, 0] == 2.0 and out[0, 1] == 3.0
    assert np.isnan(X).sum() == 2  # вход не портится


# ---------------------------------------------------------------- вердикт и решение


def _retrain(drop, done=True):
    return {"done": done, "removed": ["f_x_mean"] if done else [], "drop": drop}


@pytest.mark.parametrize(
    ("drop", "expected"),
    [(0.0, "clean"), (0.099, "clean"), (0.10, "relies_on_artifacts"), (0.3, "relies_on_artifacts")],
)
def test_verdict_by_max_drop(drop, expected):
    """Вердикт — только по падению метрики выбора на val без подозрительных (порог включён)."""
    verdict = "relies_on_artifacts" if drop >= 0.10 else "clean"
    assert verdict == expected
    text = A._verdict_text(verdict, _retrain(drop), {"forbidden": []}, 0.10)
    assert ("опирается на артефакты" in text) == (expected == "relies_on_artifacts")


def test_verdict_text_no_suspicious():
    text = A._verdict_text("clean", _retrain(0.0, done=False), {"forbidden": []}, 0.10)
    assert "подозрительных признаков нет" in text


@pytest.fixture
def card_copy(tiny_windows, tmp_path):
    """Копия модели tiny_windows: аудит переписывает карточку, общую фикстуру трогать нельзя."""
    dst = tmp_path / "windows"
    shutil.copytree(tiny_windows, dst)
    return dst


def _set_passed(path, passed):
    card = json.loads((path / "window_card.json").read_text(encoding="utf-8"))
    card["decision"]["passed_selection"] = passed
    (path / "window_card.json").write_text(json.dumps(card, ensure_ascii=False), encoding="utf-8")


@pytest.mark.parametrize(
    ("passed", "verdict", "accepted"),
    [
        (True, "clean", True),
        (True, "relies_on_artifacts", False),
        (False, "clean", False),
        (False, "relies_on_artifacts", False),
    ],
)
def test_accepted_requires_selection_and_clean(card_copy, passed, verdict, accepted):
    """FR-012: итоговое accepted = шаг 2 выбора пройден И аудит clean; версия не меняется."""
    _set_passed(card_copy, passed)
    before = read_card(card_copy)
    card = update_decision(card_copy, {"verdict": verdict, "text": "проверка"})
    assert card["decision"]["accepted"] is accepted
    assert card["decision"]["audit_verdict"] == verdict
    assert card["window_version"] == before["window_version"]
    assert read_card(card_copy)["decision"]["accepted"] is accepted
    if passed and verdict == "relies_on_artifacts":
        assert "снято аудитом" in card["decision"]["reason"]


def test_update_decision_rejects_unknown_verdict(card_copy):
    with pytest.raises(ValueError):
        update_decision(card_copy, {"verdict": "maybe", "text": ""})


# ---------------------------------------------------------------- полнота по атакующим


def test_recall_by_attacker():
    windows = pl.DataFrame(
        {
            "attacker_ip": ["a"] * 6 + ["b"] * 2 + ["c"],
            "label": ["exploits"] * 5 + ["benign"] + ["dos", "dos"] + ["benign"],
        }
    )
    score = np.array([0.9, 0.9, 0.9, 0.1, 0.1, 0.9, 0.9, 0.1, 0.9])
    got = A.recall_by_attacker(windows, score, 0.5)
    rows = {r["attacker_ip"]: r for r in got["rows"]}
    assert set(rows) == {"a", "b"}  # у c атак нет
    assert rows["a"] == {"attacker_ip": "a", "n_attack_windows": 5, "caught": 3, "recall": 0.6}
    assert rows["b"]["recall"] == 0.5
    # разброс — только по адресам с ≥ 5 окнами-атаками
    assert got["min_recall"] == got["max_recall"] == 0.6


# ---------------------------------------------------------------- нейросеть


@pytest.mark.nn
def test_group_permutation_hits_used_channel():
    """Скор зависит только от канала 1 → у него большое падение, у остальных — ноль; паддинг
    после перестановки остаётся нулём."""
    pytest.importorskip("torch")
    from mlsiem.detect.windows_nn import SeqData

    rng = np.random.default_rng(0)
    n, t, c = 200, 6, 3
    y = rng.random(n) < 0.3
    X = rng.normal(size=(n, t, c)).astype(np.float32)
    X[:, :, 1] = np.where(y[:, None], 3.0, -3.0)
    mask = np.ones((n, t), dtype=bool)
    mask[:, 4:] = False
    X[~mask] = 0.0
    seen = []

    def score(s):
        seen.append(s)
        return s.X[:, 0, 1].astype(np.float64)

    got = A.group_permutation_importance(
        score, SeqData(X, mask, np.zeros((n, 4), np.float32)), y, ["a", "b", "c"], seed=1
    )
    assert got["top"][0]["feature"] == "b" and got["top"][0]["drop"] > 0.3
    assert {r["feature"]: r["drop"] for r in got["top"]}["a"] == 0.0
    assert all((s.X[~mask] == 0).all() for s in seen)
