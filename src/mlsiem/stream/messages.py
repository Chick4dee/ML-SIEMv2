"""Формат сообщений о потоках (research R5, contracts/messages.md).

Одно сообщение — один поток; значение — JSON (orjson), ключ — `source_id` (все потоки
источника в одной партиции, порядок сохраняется). Заголовки `mlsiem-kind`, `mlsiem-schema`,
`mlsiem-source` позволяют отбраковать сообщение, не разбирая тело.

Главное правило — train = serve (принцип II). В `fields` лежат ВСЕ колонки схемы 001, кроме
группы `label`, а список колонок берётся из `SCHEMA`, не пишется руками: добавится колонка в
схему — она сама появится в сообщении. Потребитель собирает кадр строго по типам схемы,
поэтому модель видит те же имена и типы, что при обучении. Метка (только у размеченного
входа) едет отдельным полем `label` и в признаки не попадает (FR-007).

Точность чисел: orjson пишет float64 кратчайшей записью, которая читается обратно в то же
самое число (round-trip), int64 — как есть. Единственная потеря — NaN: в JSON его нет, и он
становится `null`. В потоках 001 NaN не бывает (nfstream отдаёт числа или пропуск), а модель
пропуск и так превращает в 0.

Разбор идёт пачкой: сначала все тела разбираются и проверяются в Python (orjson быстрый), и
только потом из готовых столбцов одним вызовом строится кадр polars — построчное создание
кадров на пачке в 2000 сообщений было бы в сотни раз медленнее.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import orjson
import polars as pl

from mlsiem.data.schema import SCHEMA
from mlsiem.stream.broker import Message

KIND_FLOW, KIND_END = "flow", "end"
H_KIND, H_SCHEMA, H_SOURCE = "mlsiem-kind", "mlsiem-schema", "mlsiem-source"

# Колонки `fields`: схема 001 без группы label — из схемы, а не списком руками
FEATURE_FIELDS: tuple[str, ...] = tuple(c.name for c in SCHEMA.columns if c.group != "label")
FIELD_DTYPES: dict[str, pl.DataType] = {c.name: c.dtype for c in SCHEMA.columns}
# Служебные колонки кадра рядом с полями схемы (не признаки модели)
META_COLUMNS = ("source_id", "seq", "sent_at_ms", "label")
FLOW_REQUIRED = ("flow_uid", "source_id", "seq", "sent_at_ms", "schema_version", "fields")
END_REQUIRED = ("source_id", "n_sent", "last_seq", "sent_at_ms")
# Коды причин отказа (data-model «Отвергнутое сообщение»)
REASONS = ("bad_json", "missing_field", "schema_major", "bad_type", "source_mismatch")
# Сколько байт исходного тела сохранять в топике отвергнутых
REJECTED_VALUE_LIMIT = 64 * 1024


@dataclass(frozen=True)
class Rejected:
    reason_code: str
    text: str
    message: Message

    @property
    def reason(self) -> str:
        return f"{self.reason_code}: {self.text}"


@dataclass(frozen=True)
class EndMark:
    source_id: str
    n_sent: int
    last_seq: int
    sent_at_ms: int
    message: Message


def schema_major(version: str | None) -> str | None:
    if not isinstance(version, str) or not version:
        return None
    return version.split(".", 1)[0]


def check_schema_major(version: str | None, model_schema: str = SCHEMA.version) -> bool:
    """Мажорная версия схемы сообщения совпадает с моделью? Минорная может отличаться."""
    return version is not None and schema_major(version) == schema_major(model_schema)


def _headers(kind: str, source_id: str, schema_version: str) -> dict[str, str]:
    return {H_KIND: kind, H_SCHEMA: schema_version, H_SOURCE: source_id}


def encode_flow(
    row: dict[str, Any],
    source_id: str,
    seq: int,
    sent_at_ms: int,
    label: str | None = None,
    *,
    schema_version: str = SCHEMA.version,
) -> tuple[str, bytes, dict[str, str]]:
    """(ключ, тело, заголовки) сообщения `flow`. `row` — строка потоков 001 (все колонки)."""
    body: dict[str, Any] = {
        "flow_uid": row["flow_uid"],
        "source_id": source_id,
        "seq": int(seq),
        "sent_at_ms": int(sent_at_ms),
        "schema_version": schema_version,
        "fields": {name: row[name] for name in FEATURE_FIELDS},
    }
    if label is not None:
        body["label"] = label
    return source_id, orjson.dumps(body), _headers(KIND_FLOW, source_id, schema_version)


def encode_end(
    source_id: str, n_sent: int, sent_at_ms: int, *, schema_version: str = SCHEMA.version
) -> tuple[str, bytes, dict[str, str]]:
    body = {
        "source_id": source_id,
        "n_sent": int(n_sent),
        "last_seq": int(n_sent) - 1,
        "sent_at_ms": int(sent_at_ms),
    }
    return source_id, orjson.dumps(body), _headers(KIND_END, source_id, schema_version)


# ---------------------------------------------------------------- разбор

_INT, _FLOAT, _STR = pl.Int64(), pl.Float64(), pl.String()


# Проверка типов — самое горячее место потребителя (87 полей × каждое сообщение). Сравнение
# типов polars (`dtype == pl.Int64()`) в цикле на миллионы значений занимало 70% времени
# пачки, поэтому допустимые типы Python для каждого поля считаются один раз здесь.
# bool в Python — подкласс int, поэтому его отсекает отдельный флаг «целое/число».
_ALLOWED: dict[str, tuple[type, ...]] = {}
for _name in FEATURE_FIELDS:
    _dt = FIELD_DTYPES[_name]
    _ALLOWED[_name] = (int,) if _dt == _INT else (int, float) if _dt == _FLOAT else (str,)
_NUMERIC = frozenset(n for n, kinds in _ALLOWED.items() if kinds[0] is int)
_FIELD_CHECKS = tuple((n, _ALLOWED[n], n in _NUMERIC) for n in FEATURE_FIELDS)
_MISSING = object()
# Схема кадра признаков: из готовых словарей его собирает сам polars (в Rust), а не цикл Python
_FIELDS_SCHEMA = {n: FIELD_DTYPES[n] for n in FEATURE_FIELDS}


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class _Reject(Exception):
    def __init__(self, code: str, text: str) -> None:
        self.code, self.text = code, text


def _check_common(body: Any, msg: Message, required: tuple[str, ...], model_schema: str) -> dict:
    if not isinstance(body, dict):
        raise _Reject("bad_json", "тело сообщения — не JSON-объект")
    missing = [k for k in required if k not in body]
    if missing:
        raise _Reject("missing_field", f"в сообщении нет обязательных полей: {', '.join(missing)}")
    header_source = msg.headers.get(H_SOURCE)
    if header_source is not None and header_source != body["source_id"]:
        raise _Reject(
            "source_mismatch",
            f"источник в заголовке ({header_source}) не совпадает с телом ({body['source_id']})",
        )
    if not isinstance(body["source_id"], str) or not body["source_id"]:
        raise _Reject("bad_type", "source_id должен быть непустой строкой")
    version = body.get("schema_version", msg.headers.get(H_SCHEMA))
    if version is not None and not check_schema_major(version, model_schema):
        raise _Reject(
            "schema_major",
            f"версия схемы сообщения {version} несовместима с моделью (схема {model_schema}): "
            "мажорные версии должны совпадать",
        )
    return body


def _check_flow(body: dict, msg: Message, model_schema: str) -> dict:
    for k in ("seq", "sent_at_ms"):
        if not _is_int(body[k]) or body[k] < 0:
            raise _Reject("bad_type", f"поле {k} должно быть целым ≥ 0, а пришло {body[k]!r}")
    if not isinstance(body["flow_uid"], str) or not body["flow_uid"]:
        raise _Reject("bad_type", "flow_uid должен быть непустой строкой")
    fields = body["fields"]
    if not isinstance(fields, dict):
        raise _Reject("bad_type", "поле fields должно быть JSON-объектом «имя → значение»")
    # Один проход по полям: и «есть ли», и «того ли типа». Нехватка полей важнее неверного
    # типа — поэтому первую ошибку типа только запоминаем
    missing: list[str] = []
    bad: tuple[str, Any] | None = None
    for name, kinds, numeric in _FIELD_CHECKS:
        value = fields.get(name, _MISSING)
        if value is None:
            continue
        if value is _MISSING:
            missing.append(name)
        elif bad is None and (
            not isinstance(value, kinds) or (numeric and value.__class__ is bool)
        ):
            bad = (name, value)
    if missing:
        head = ", ".join(missing[:5]) + (f" и ещё {len(missing) - 5}" if len(missing) > 5 else "")
        raise _Reject("missing_field", f"в fields нет полей схемы: {head}")
    if bad is not None:
        name, value = bad
        raise _Reject(
            "bad_type",
            f"поле {name}: ожидался тип {FIELD_DTYPES[name]} (или null), а пришло {value!r}",
        )
    if fields["flow_uid"] != body["flow_uid"]:
        raise _Reject("bad_type", "flow_uid в теле и в fields различаются")
    label = body.get("label")
    if label is not None and not isinstance(label, str):
        raise _Reject("bad_type", f"поле label должно быть строкой, а пришло {label!r}")
    return body


def decode_flows(
    messages: list[Message], *, model_schema: str = SCHEMA.version
) -> tuple[pl.DataFrame, list[Rejected], list[EndMark]]:
    """Пачка сообщений → (кадр потоков по типам схемы + META_COLUMNS, отвергнутые, концы).

    Порядок строк кадра — порядок сообщений в пачке. Лишние поля в `fields` игнорируются
    (минорная версия схемы могла их добавить).
    """
    rows: list[dict] = []
    meta: dict[str, list[Any]] = {name: [] for name in META_COLUMNS}
    rejected: list[Rejected] = []
    ends: list[EndMark] = []
    for msg in messages:
        try:
            try:
                body = orjson.loads(msg.value)
            except orjson.JSONDecodeError as exc:
                raise _Reject("bad_json", f"тело не разбирается как JSON UTF-8 ({exc})") from None
            kind = msg.headers.get(H_KIND)
            if kind is None and isinstance(body, dict):
                # Без заголовка — по содержимому (производитель мог не поставить заголовки)
                kind = KIND_END if "n_sent" in body else KIND_FLOW
            if kind == KIND_END:
                body = _check_common(body, msg, END_REQUIRED, model_schema)
                if not all(_is_int(body[k]) for k in ("n_sent", "last_seq", "sent_at_ms")):
                    raise _Reject(
                        "bad_type", "поля n_sent, last_seq, sent_at_ms должны быть целыми"
                    )
                ends.append(
                    EndMark(
                        body["source_id"], body["n_sent"], body["last_seq"], body["sent_at_ms"], msg
                    )
                )
                continue
            if kind != KIND_FLOW:
                raise _Reject("missing_field", f"заголовок {H_KIND}: неизвестный вид {kind!r}")
            body = _check_flow(
                _check_common(body, msg, FLOW_REQUIRED, model_schema), msg, model_schema
            )
        except _Reject as r:
            rejected.append(Rejected(r.code, r.text, msg))
            continue
        rows.append(body["fields"])
        meta["source_id"].append(body["source_id"])
        meta["seq"].append(body["seq"])
        meta["sent_at_ms"].append(body["sent_at_ms"])
        meta["label"].append(body.get("label"))

    # Лишние поля минорной версии схемы в кадр не попадают: берутся только колонки схемы
    frame = pl.DataFrame(rows, schema=_FIELDS_SCHEMA, strict=False, orient="row")
    meta_types = {"source_id": _STR, "seq": _INT, "sent_at_ms": _INT, "label": _STR}
    frame = frame.with_columns(
        pl.Series(name, values, dtype=meta_types[name], strict=False)
        for name, values in meta.items()
    )
    return frame, rejected, ends


def rejected_payload(rej: Rejected, *, now: datetime | None = None) -> tuple[str, bytes, dict]:
    """(ключ, тело, заголовки) для топика отвергнутых: причина + исходное сообщение."""
    msg = rej.message
    raw = msg.value[:REJECTED_VALUE_LIMIT].decode("utf-8", errors="replace")
    body = {
        "reason": rej.reason,
        "topic": msg.topic,
        "partition": msg.partition,
        "offset": msg.offset,
        "headers": msg.headers,
        "value": raw,
        "rejected_at": (now or datetime.now(UTC)).isoformat(timespec="milliseconds"),
    }
    key = msg.headers.get(H_SOURCE) or msg.key or "—"
    return key, orjson.dumps(body), {"mlsiem-reason": rej.reason_code}
