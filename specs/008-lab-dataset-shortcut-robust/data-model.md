# Data Model: Содержательный набор стенда, устойчивый к «ярлыкам»

Все структуры — расширения 006; необязательные поля старых записей по умолчанию пусты.

## Конфиг (`configs/stream.yaml`)

```yaml
lab:
  sources:                       # реестр источников трафика (R2)
    - {name: attacker,  vm: mlsiem-attacker,  ip: 10.88.0.30, role: attacker, os: ubuntu-24.04}
    - {name: attacker_a2, alias_of: attacker, ip: 10.88.0.32, role: attacker}
    - {name: attacker2, vm: mlsiem-attacker2, ip: 10.88.0.31, role: attacker, os: debian-12, mgmt: com}
    - {name: client,    vm: mlsiem-client,    ip: 10.88.0.40, role: client,   os: ubuntu-24.04, mgmt: com}
scenarios:
  - name: port_scan             # версия 2: сценарий сгруппирован в варианты
    version: "2"
    expected_class: reconnaissance
    reserve_unknown: false      # true — класс только в тесте (FR-021)
    variants:
      - name: nmap_syn
        tool: nmap
        args: "-sS -p {ports} -T{timing} {target}"
        source_bind: "-S {src} -e {iface}"
        params:
          ports:  {values: ["1-1024", "1-65535", "22,80,443,8080"], holdout: ["1-65535"]}
          timing: {values: [2, 3, 4], holdout: [2]}
        duration_limit_s: 120
      - name: masscan_syn
        tool: masscan
        ...
normal:
  clients: [client, attacker]    # какие источники порождают норму
  hard:                          # сложная норма (FR-004), метка benign
    - {name: web_loadtest, tool: ab, args: "-n 2000 -c 20 http://{target}/", expected_class: benign}
    - {name: monitor_scan, tool: nmap, args: "-sT -p 22,80,443 {target}", expected_class: benign}
collection:
  seed: 7
  repeats: 10
  pause_s: 150                   # >= idle_timeout + 30
  concurrent_normal_share: 0.34
  dual_attack_runs: 3
  parts: {train: [1, 2, 3, 4, 5, 6], val: [7, 8], test: [9, 10]}
shortcuts:
  nmi_threshold: 0.9
  env_features: [bidirectional_ece_packets, bidirectional_cwr_packets, bidirectional_urg_packets,
                 bidirectional_min_ps, bidirectional_max_ps]
  min_test_flows: 100
  seeds: [0, 1, 2]
  fpr_levels: [0.001, 0.01, 0.05]
```

## План сбора (`plan.json`)

| Поле | Смысл |
|---|---|
| `plan_version`, `seed`, `config_hash` | воспроизводимость |
| `runs[]` | список запусков |
| `runs[].run_uid` | идентификатор (детерминированный по плану) |
| `runs[].scenario`, `.variant`, `.params` | что запускать |
| `runs[].source` | имя источника из `lab.sources` |
| `runs[].repeat`, `.part` | номер повтора и часть разбиения |
| `runs[].concurrent` | `normal`, `attack:<run_uid>` или пусто |
| `runs[].reserve_unknown` | запуск из резерва «неизвестное» |
| `runs[].start_offset_s` | планируемое смещение старта |

## Запись журнала версии 2

Поля версии 1 (006): `run_uid`, `scenario`, `scenario_version`, `attacker_ip`, `targets`,
`expected_class`, `start`, `end`, `status`. Новые необязательные: `record_version: 2`, `variant`,
`tool`, `tool_version`, `params`, `source` (имя), `source_ip` (то же значение, что `attacker_ip`),
`repeat`, `part`, `concurrent`, `reserve_unknown`, `plan_run_uid`.

## Строка набора

К колонкам 006 (признаки 001 + `label`) добавляются метаданные: `variant`, `tool`, `source`,
`run_uid`, `repeat`, `part`, `reserve_unknown`, `hard_normal` (bool), `session_bucket`
(интервал времени сеанса). Адреса, порты и время остаются в метаданных 001 и в признаки не идут.

## Отчёт качества (`quality.json`)

`counts` (класс × инструмент × источник × часть × интервал), `nmi` (класс против инструмента,
источника, интервала), `warnings[]` (тип, класс, значение), `ambiguous_share`, `verdict`
(`clean` | `suspect`), `reasons[]`.

## Отчёт исключения и аудита (`shortcuts.json`)

`leave_tool[]` и `leave_source[]`: класс, исключённый инструмент/источник, полнота (по долям
ложных срабатываний) с интервалом Уилсона, контроль, разность; `audit`: перестановочная
важность, одиночная полнота, повторная оценка без `env_features`, `verdict`.

## Отчёт неизвестных атак (`unknown.json`)

По каждому резервному классу и варианту: полнота при 0,1% / 1% / 5% для способов оценки
(атака/норма, MSP, энергия, объединения), контроль (класс известен), разность, `nearest` — на
какие известные классы или норму модель относит; `scope_note` — фиксированная оговорка FR-023.

## Состояние сбора и сеансы (остановка и возобновление, FR-024…FR-029)

`collect_state.json` (рядом с планом):

| Поле | Смысл |
|---|---|
| `plan_hash`, `seed` | привязка к плану |
| `sessions[]` | сеансы: `session_id`, `started`, `stopped`, `stop_kind` (`soft` / `hard` / `crash`), файлы `pcap` и `journal`, их хеши |
| `runs{}` | по `plan_run_uid`: `status` (`pending` / `done` / `aborted` / `rejected`), `attempts`, `last_run_uid` |
| `remaining`, `eta_s` | сколько запусков осталось и оценка времени |
| `safe_to_power_off` | `true`, если дренаж завершён и сенсор остановлен |

Запись журнала версии 2 получает `status` ∈ {`started`, `completed`, `aborted`, `rejected`}, `attempt`,
`session_id`. Незавершённая запись `started` без `completed` трактуется как `aborted` с концом = последнему
временному штампу сегмента записи.

