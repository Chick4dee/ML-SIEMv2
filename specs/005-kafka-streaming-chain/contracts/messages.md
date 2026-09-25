# Контракт: сообщения о потоках (фича 005)

Единый формат для всех производителей (проигрыватель 005, сенсор 006) и потребителя. Полное
описание полей — [../data-model.md](../data-model.md) «Сообщения Kafka». Тест контракта
проверяет обе стороны: то, что пишет `stream.messages.encode_flow`, `decode_flow` читает в кадр,
идентичный по значениям и типам исходным потокам 001.

## Пример `flow`

Заголовки: `mlsiem-kind: flow`, `mlsiem-schema: 1.0.0`, `mlsiem-source: replay:unsw_time/test:20260925T101500`.
Ключ: `replay:unsw_time/test:20260925T101500`.

```json
{
  "flow_uid": "unsw_17-2-2015_24/9",
  "source_id": "replay:unsw_time/test:20260925T101500",
  "seq": 1042,
  "sent_at_ms": 1790331300123,
  "schema_version": "1.0.0",
  "fields": {
    "flow_uid": "unsw_17-2-2015_24/9",
    "capture_id": "unsw_17-2-2015_24",
    "src_ip": "149.171.126.17",
    "src_port": 80,
    "dst_ip": "175.45.176.0",
    "dst_port": 39574,
    "protocol": 6,
    "bidirectional_first_seen_ms": 1424219423000,
    "bidirectional_packets": 12,
    "bidirectional_mean_ps": 512.25,
    "src2dst_syn_packets": 0,
    "dst2src_syn_packets": 1,
    "application_name": null
  },
  "label": "exploits"
}
```

(`fields` в примере сокращён; в сообщении — все колонки схемы, кроме группы `label`.)

## Пример `end`

Заголовки: `mlsiem-kind: end`, `mlsiem-schema: 1.0.0`, `mlsiem-source: …`.

```json
{"source_id": "replay:unsw_time/test:20260925T101500", "n_sent": 281774, "last_seq": 281773, "sent_at_ms": 1790331480000}
```

## Правила совместимости

- Мажорная версия схемы в сообщении обязана совпадать с моделью; минорная может отличаться, если
  все поля модели есть.
- Лишние поля в `fields` игнорируются; отсутствие любого поля схемы — `missing_field`.
- Порядок ключей JSON не важен; кодировка UTF-8.
- Метка `label` никогда не попадает в кадр признаков модели (FR-007) — только в `true_label`
  вердиктов для сводки и сравнения.
