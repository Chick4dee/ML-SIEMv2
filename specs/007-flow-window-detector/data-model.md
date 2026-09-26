# Data Model: Детектор на окнах потоков (007)

Сущности спеки (Key Entities) в терминах данных. Решения, на которые ссылается текст, — в
[research.md](research.md) (R1–R18).

## Окно (в памяти / parquet)

Строится функцией `build_windows(flows, sides, cfg)` — **одной** для обучения, пакетного прогона
и потребителя (FR-003).

| Поле | Тип | Смысл |
|---|---|---|
| `window_id` | str | `w-` + digest(attacker_ip, window_start_ms, length_ms)[:16] (R1) |
| `attacker_ip` | str | ключ окна: атакующая сторона по правилу направления 004 |
| `window_start_ms` | int64 | `floor(first_seen_ms / L) · L` |
| `window_end_ms` | int64 | `window_start_ms + L` (правая граница не включается) |
| `shift_ms` | int32 | сдвиг сетки: 0 — основная; 15/30/45 с — только аугментация train (R9) |
| `part` | str \| null | train/val/test (только при обучении) |
| `n_flows` | int32 | число потоков окна (всех, до усечения) |
| `truncated` | bool | `n_flows > seq_max` (128) |
| `flow_uids` | list[str] | потоки окна по порядку (`first_seen_ms`, `flow_uid`) |
| `first_seen_ms` / `last_seen_ms` | int64 | старт первого потока / конец последнего |
| `targets` | list[{ip, n}] | цели (`victim_ip`) с числом потоков, по убыванию |
| `label` / `label_class` | str | только для оценки (R2): `benign` или класс атаки |
| `n_attack_classes`, `attack_share` | int, float | для отчёта о смешанных окнах |

**Правила валидации**:
- все потоки окна принадлежат одной части разбиения (SC-004, тест);
- `window_start_ms ≤ first_seen_ms(потока) < window_end_ms`;
- `window_id` одинаков в пакетном и онлайн-режиме для одного входа (тест эквивалентности).

## Входы моделей окон

**Сводные признаки** (`summary_features`, около 190 колонок float32, R3): `f_<признак>_{mean,max,std}`
для 58 признаков схемы; `w_log_n_flows`, `w_n_targets`, `w_n_dst_ports`, `w_n_src_ports`,
`w_share_tcp|udp|icmp|other`, `w_span_s`, `w_gap_{mean,std,min}_s`, `w_share_reversed`,
`w_share_low_port`.

**Последовательность** (R4): тензор `[n_windows, 128, 62]` float32 и маска `[n_windows, 128]`
bool. 62 = 58 признаков после `log1p` и стандартизации + `t_from_start_s`, `log_gap_s`,
`new_target`, `new_dst_port`. Скаляры окна `[n_windows, 4]`: `w_log_n_flows`, `truncated`,
`w_log_n_targets`, `w_log_n_dst_ports`.

**Запрещено во входах** (FR-004, тест по списку имён): `*_ip`, `src_port`, `dst_port` как значения,
`flow_uid`, `capture_id`, `id`, `expiration_id`, `*_first_seen_ms`, `*_last_seen_ms`, DPI-поля.

## Вердикт окна (`windows.parquet` прогона; `windows/part-*.parquet` сеанса)

| Поле | Тип | Смысл |
|---|---|---|
| `window_id`, `attacker_ip`, `window_start_ms`, `n_flows`, `truncated` | | как у окна |
| `predicted_class` | str | класс с максимальной вероятностью среди атакующих, если `is_alert`, иначе `benign` |
| `attack_score` | float64 | `1 − p_benign` |
| `is_alert` | bool | `attack_score ≥ threshold` карточки |
| `p_<класс>` | float64 | вероятности классов в порядке `classes` карточки |
| `true_label` | str | только для размеченного входа |

Правило «класс атаки при алерте» — то же, что у детектора 002 (`final_class`/`top_attack`).

## Модель окон (артефакт `models/windows/`, R11)

`window_card.json`:

```json
{
  "window_version": "20260927-1a2b3c4d",
  "kind": "lgbm | gru",
  "classes": ["analysis", "backdoor", "benign", "..."],
  "threshold": 0.42,
  "window": {"length_ms": 60000, "key": "attacker_ip", "direction": "auto", "seq_max": 128},
  "summary_features": ["f_..._mean", "..."],
  "seq_features": ["...", "t_from_start_s", "log_gap_s", "new_target", "new_dst_port"],
  "schema_version": "1.x",
  "decision": {
    "accepted": false,
    "step": "vs_current | nn_vs_boosting | audit",
    "metric": "macro_pr_auc_reliable_val",
    "reliable_classes": ["benign", "exploits", "fuzzers", "reconnaissance"],
    "values": {"lgbm": 0.0, "gru": 0.0, "current": 0.0},
    "min_gain": 0.01,
    "audit_verdict": "clean | relies_on_artifacts | not_run",
    "reason": "текст по-русски"
  },
  "current_model": {"kind": "ensemble", "version": "20260924-57d174a4"},
  "data": {"split": "unsw_time", "split_hash": "...", "input_hashes": {}},
  "seed": 42, "device": "cuda:0 NVIDIA GeForce RTX 3060 Ti", "libraries": {}
}
```

Файлы: `model.joblib` (LightGBM-конвейер) или `model.pt` + `preprocess.joblib`. Загрузчик
`load_window_expert(path, *, force=False)` → `WindowExpert` с методами `check(soc_cfg)`,
`verdicts(windows) -> DataFrame`, `explain(windows, verdicts) -> list[str]`; при
`accepted=false` и без `force` — отказ `WindowExpertNotAccepted`.

## Алерт окна (SQLite `alerts`, схема 5, R12, R14)

Та же таблица, что алерты потоков: `alert_kind = 'window'`, `flow_uid = window_id` (уникальность
`(run_id, flow_uid)` = идемпотентность), `src_ip = attacker_ip`, `dst_ip = victim_ip` (самая
частая цель), `src_port/dst_port/protocol = NULL`, `first_seen_ms/last_seen_ms` — границы потоков
окна, `predicted_class`, `attack_score`, `fired_experts = 'windows'`, `experts =
{"windows": {"score", "threshold", "fired": true}}`, `explanation`, `late = 0`.

`window_info` (JSON):

```json
{
  "window_id": "w-…", "start_ms": 0, "end_ms": 60000, "n_flows": 117, "truncated": false,
  "targets": [{"ip": "149.171.126.14", "n": 90}],
  "n_dst_ports": 57, "top_flows": [{"flow_uid": "…", "dst_ip": "…", "dst_port": 80,
  "protocol": 6, "flow_score": 0.93}],
  "top_features": [{"name": "w_n_dst_ports", "value": 57, "contribution": 1.8}],
  "expert_version": "20260927-1a2b3c4d", "kind": "lgbm"
}
```

`top_flows` — до 20 потоков окна с наибольшим `attack_score` потоковой модели; `top_features` —
до 5 (для `gru` пусто, пояснение строится по `top_flows`).

## Незакрытые окна сеанса (SQLite, схема 5, R13)

- `window_pending(run_id, flow_uid, window_id, window_start_ms, attacker_ip, payload BLOB,
  PRIMARY KEY (run_id, flow_uid))` + индекс `(run_id, window_start_ms)`. `payload` — orjson
  колонок, нужных `build_windows` (контекст + признаки эксперта окон).
- `window_closed(run_id, window_id, closed_at, n_flows, PRIMARY KEY (run_id, window_id))`.

**Переходы окна в сеансе**: *нет* → **открыто** (первый поток окна записан в `window_pending`) →
**закрыто** (`window_start_ms + L ≤ max_first_seen_ms − allowed_lateness_ms` или отметка `end`
или `stream close`: вердикт, алерт при `is_alert`, строки `pending` удалены, запись в
`window_closed`). Поток закрытого окна → в окно не добавляется, `n_window_late_dropped += 1`.
Остановка потребителя не меняет состояния открытых окон.

## Прогон / сеанс (`runs.summary`, дополнения)

```json
"windows": {
  "mode": "auto | off | force", "enabled": true, "expert_version": "…", "kind": "lgbm",
  "accepted": true, "n_windows": 2642, "n_window_alerts": 310,
  "n_window_late_dropped": 0, "n_open_windows": 0
}
```

Отсутствие раздела = прогон до 007 (консоль показывает «эксперт окон: нет»).

## Отчёты

- **Отчёт эксперимента** (`reports/windows_experiment.md`, `models/windows/experiment.json`):
  участники, метрики val/test (macro надёжных, macro всех, «атака/нет», per-class, точность и
  полнота на пороге), решение по шагам, число окон по классам, доли усечённых и смешанных окон,
  время обучения и предсказания, устройство, допуск воспроизводимости.
- **Отчёт аудита** (`reports/windows_audit.md`): состав входов, важности, одиночные признаки,
  результат без подозрительных (падение), перенос на `unsw_cross_day`, полнота по атакующим
  адресам, вердикт.
- **Разбор ошибок** (`reports/windows_errors.md`): матрица ошибок, качество по корзинам размера
  окна, таблица «только окна / только потоки / обе / никто» по классам, примеры пропусков.
- **Сравнение пакет ↔ онлайн** (дополнение 005): вердикты окон, алерты окон в подписи инцидентов,
  причина `window_late_dropped`.
