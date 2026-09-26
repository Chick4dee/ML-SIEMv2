"""Контракт сообщений о потоках (contracts/messages.md): обе стороны формата.

Главная проверка — train = serve: то, что пишет `encode_flow`, `decode_flows` читает в кадр,
РАВНЫЙ исходным потокам 001 по значениям и типам всех колонок схемы (кроме группы label),
включая пропуски и float64 без потери точности. Метка — только в отдельном поле.
"""

import orjson
import polars as pl
import pytest

from mlsiem.data.schema import SCHEMA
from mlsiem.stream.broker import Message
from mlsiem.stream.messages import (
    FEATURE_FIELDS,
    H_KIND,
    H_SCHEMA,
    H_SOURCE,
    REASONS,
    decode_flows,
    encode_end,
    encode_flow,
    rejected_payload,
)

SRC = "replay:unsw_time/test:20260925T101500"


def _msg(key, value, headers, offset=0) -> Message:
    return Message("mlsiem.flows", 0, offset, key, value, headers, 0)


def _encode_all(df: pl.DataFrame) -> list[Message]:
    out = []
    for seq, row in enumerate(df.iter_rows(named=True)):
        key, value, headers = encode_flow(row, SRC, seq, 1_790_000_000_000 + seq, row["label"])
        out.append(_msg(key, value, headers, seq))
    return out


@pytest.fixture(scope="module")
def flows(synthetic_flows) -> pl.DataFrame:
    df = next(iter(synthetic_flows.values())).head(400)
    # Пропуски и «неудобные» дроби — чтобы проверка точности не была тривиальной
    return df.with_columns(
        pl.when(pl.int_range(pl.len()) % 7 == 0)
        .then(None)
        .otherwise(pl.col("application_name"))
        .alias("application_name"),
        pl.when(pl.int_range(pl.len()) % 5 == 0)
        .then(None)
        .otherwise(pl.col("bidirectional_mean_ps") / 3.0)
        .alias("bidirectional_mean_ps"),
    )


def test_fields_are_schema_without_label():
    assert list(FEATURE_FIELDS) == [c.name for c in SCHEMA.columns if c.group != "label"]
    assert "label" not in FEATURE_FIELDS and "label_raw" not in FEATURE_FIELDS


def test_roundtrip_equals_source(flows):
    frame, rejected, ends = decode_flows(_encode_all(flows))
    assert rejected == [] and ends == []
    got = frame.select(FEATURE_FIELDS)
    want = flows.select(FEATURE_FIELDS)
    assert got.schema == want.schema
    assert got.equals(want, null_equal=True)
    # float64 бит в бит, а не «примерно»
    a = got["bidirectional_mean_ps"].to_list()
    b = want["bidirectional_mean_ps"].to_list()
    assert a == b
    assert frame["seq"].to_list() == list(range(flows.height))
    assert set(frame["source_id"].to_list()) == {SRC}
    assert frame["label"].to_list() == flows["label"].to_list()


def test_label_only_in_label_field(flows):
    row = flows.row(0, named=True)
    _, value, headers = encode_flow(row, SRC, 0, 1, "exploits")
    body = orjson.loads(value)
    assert body["label"] == "exploits"
    assert not {"label", "label_raw", "label_detail"} & set(body["fields"])
    assert headers == {H_KIND: "flow", H_SCHEMA: SCHEMA.version, H_SOURCE: SRC}
    _, value, _ = encode_flow(row, SRC, 0, 1)
    assert "label" not in orjson.loads(value)


def test_end_roundtrip():
    key, value, headers = encode_end(SRC, 42, 123)
    frame, rejected, ends = decode_flows([_msg(key, value, headers)])
    assert frame.height == 0 and rejected == []
    assert (ends[0].source_id, ends[0].n_sent, ends[0].last_seq) == (SRC, 42, 41)


def _flow_body(flows) -> dict:
    _, value, _ = encode_flow(flows.row(0, named=True), SRC, 0, 1)
    return orjson.loads(value)


def _headers() -> dict:
    return {H_KIND: "flow", H_SCHEMA: SCHEMA.version, H_SOURCE: SRC}


def _reject_code(value: bytes, headers=None) -> str:
    frame, rejected, ends = decode_flows([_msg(SRC, value, headers or _headers())])
    assert frame.height == 0 and len(rejected) == 1
    r = rejected[0]
    assert r.reason_code in REASONS
    # Текст — по-русски
    assert any("а" <= ch <= "я" for ch in r.text.lower())
    return r.reason_code


def test_reject_bad_json():
    assert _reject_code(b"{not json") == "bad_json"
    assert _reject_code(b"[1, 2]") == "bad_json"


def test_reject_missing_field(flows):
    body = _flow_body(flows)
    del body["fields"]["bidirectional_packets"]
    assert _reject_code(orjson.dumps(body)) == "missing_field"
    body = _flow_body(flows)
    del body["seq"]
    assert _reject_code(orjson.dumps(body)) == "missing_field"


def test_reject_schema_major(flows):
    body = _flow_body(flows)
    body["schema_version"] = "2.0.0"
    assert _reject_code(orjson.dumps(body)) == "schema_major"


def test_minor_version_accepted(flows):
    body = _flow_body(flows)
    body["schema_version"] = "1.1.0"
    body["fields"]["new_field_from_minor"] = 5  # лишнее поле игнорируется
    frame, rejected, _ = decode_flows([_msg(SRC, orjson.dumps(body), _headers())])
    assert rejected == [] and frame.height == 1
    assert "new_field_from_minor" not in frame.columns


def test_reject_bad_type(flows):
    body = _flow_body(flows)
    body["fields"]["bidirectional_packets"] = "много"
    assert _reject_code(orjson.dumps(body)) == "bad_type"
    body = _flow_body(flows)
    body["fields"]["src_ip"] = 5
    assert _reject_code(orjson.dumps(body)) == "bad_type"


def test_reject_source_mismatch(flows):
    body = _flow_body(flows)
    headers = {**_headers(), H_SOURCE: "replay:другой"}
    assert _reject_code(orjson.dumps(body), headers) == "source_mismatch"


def test_good_and_bad_in_one_batch(flows):
    good = _encode_all(flows.head(3))
    bad = _msg(SRC, b"oops", _headers(), 99)
    frame, rejected, _ = decode_flows([good[0], bad, good[1], good[2]])
    assert frame.height == 3 and len(rejected) == 1
    assert rejected[0].message.offset == 99


def test_rejected_payload_keeps_body_and_reason():
    msg = _msg(SRC, b"x" * (70 * 1024), _headers(), 5)
    frame, rejected, _ = decode_flows([msg])
    key, value, headers = rejected_payload(rejected[0])
    body = orjson.loads(value)
    assert key == SRC
    assert body["reason"].startswith("bad_json: ")
    assert body["offset"] == 5 and body["topic"] == "mlsiem.flows"
    assert len(body["value"]) == 64 * 1024
    assert headers["mlsiem-reason"] == "bad_json"
