"""Seed-ISO автоустановки брокерной машины (фича 005, research R3).

Ubuntu Server ставится без вопросов, если рядом с установочным образом подключён второй
диск с меткой тома `CIDATA` и файлами `user-data`/`meta-data` (источник NoCloud cloud-init).
Этот модуль собирает такой диск из шаблонов `stand/broker/` и параметров `configs/stream.yaml`.

Почему Python и pycdlib: на Windows нет штатных `genisoimage`/`oscdimg`, а тащить ради одного
файла отдельный инструмент — лишняя установка на машину владельца. pycdlib — чистый Python.

Воспроизводимость. Один и тот же конфиг и ключ дают ISO байт в байт: даты файлов и тома
фиксированы (иначе pycdlib ставит текущее время), порядок файлов постоянный. Так повторная
сборка не выглядит «изменением», а два владельца с одинаковым конфигом получают одинаковый
образ.

Команда ничего в системе не меняет — только пишет файл образа (атомарно).
"""

from __future__ import annotations

import io
import json
import time as _time
from contextlib import contextmanager
from pathlib import Path

import jinja2

from mlsiem.data.captures import atomic_path
from mlsiem.stream.broker import topic_specs

REPO = Path(__file__).resolve().parents[3]
TEMPLATES = REPO / "stand" / "broker"
DEFAULT_OUT = Path("var/stand/seed.iso")
ROLES = ("broker", "victim", "attacker")
# Пакеты атакующей машины (R5): всё из репозиториев Ubuntu, без Metasploit и подобного
ATTACKER_PACKAGES = (
    "nmap",
    "ffuf",
    "hydra",
    "slowhttptest",
    "hping3",
    "tcpreplay",
    "curl",
    "sshpass",
    "bind9-dnsutils",
    "python3",
)
# Модули раннера, которые копируются на атакующую машину как есть (только stdlib, R6) — тест
# проверяет именно тот код, что поедет на машину
RUNNER_MODULES = ("journal", "scenarios", "normal", "runner")
LAB_SRC = Path(__file__).resolve().parents[1] / "lab"
RUNNER_ROOT = "/opt/mlsiem/lib"
DEFAULT_PUBKEY = Path.home() / ".ssh" / "id_ed25519.pub"
VOLUME_ID = "CIDATA"
# Фиксированная дата всех записей образа: 2026-01-01 00:00:00 UTC
FIXED_EPOCH = 1767225600.0
KEY_PREFIXES = ("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")


class SeedError(ValueError):
    """Ошибка сборки seed-ISO; сообщение — что сделать по-русски."""


def read_pubkey(path: Path) -> str:
    path = Path(path)
    if not path.exists():
        raise SeedError(
            f"нет открытого SSH-ключа {path} — создайте его командой "
            f"`ssh-keygen -t ed25519` (или укажите другой ключ: --pubkey <файл.pub>)"
        )
    key = path.read_text(encoding="utf-8").strip()
    if not key.startswith(KEY_PREFIXES) or "\n" in key:
        raise SeedError(
            f"{path} не похож на открытый SSH-ключ (одна строка вида «ssh-ed25519 AAAA… имя») — "
            "нужен файл .pub, а не закрытый ключ"
        )
    return key


def render(cfg, pubkey: str, templates: Path = TEMPLATES) -> dict[str, str]:
    """Тексты `user-data` и `meta-data` (и вложенных в user-data файлов) по конфигу."""
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(templates)),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    ctx = {"s": cfg.stand, "t": cfg.topics, "topics": topic_specs(cfg), "pubkey": pubkey}
    parts = {
        "server_properties": env.get_template("server.properties.j2").render(ctx).rstrip("\n"),
        "kafka_service": env.get_template("kafka.service.j2").render(ctx).rstrip("\n"),
        "install_script": env.get_template("install-kafka.sh.j2").render(ctx).rstrip("\n"),
    }
    return {
        "user-data": env.get_template("user-data.yaml.j2").render({**ctx, **parts}),
        "meta-data": env.get_template("meta-data.j2").render(ctx),
        **parts,
    }


def default_out(role: str) -> Path:
    """Куда писать образ по умолчанию: брокер — как в 005, остальные — `seed-<роль>.iso`."""
    return DEFAULT_OUT if role == "broker" else DEFAULT_OUT.with_name(f"seed-{role}.iso")


def runner_files() -> list[dict]:
    """Файлы раннера для атакующей машины: пакеты-заглушки и модули `mlsiem.lab.*`."""
    files = [
        {
            "path": f"{RUNNER_ROOT}/mlsiem/__init__.py",
            "text": "# заглушка: на машине только подпакет lab\n",
        },
        {
            "path": f"{RUNNER_ROOT}/mlsiem/lab/__init__.py",
            "text": (LAB_SRC / "__init__.py").read_text(encoding="utf-8"),
        },
    ]
    for name in RUNNER_MODULES:
        files.append(
            {
                "path": f"{RUNNER_ROOT}/mlsiem/lab/{name}.py",
                "text": (LAB_SRC / f"{name}.py").read_text(encoding="utf-8"),
            }
        )
    return files


def render_role(cfg, role: str, pubkey: str, templates: Path = TEMPLATES) -> dict[str, str]:
    """`user-data` и `meta-data` машины стенда (роль victim|attacker); для broker — `render`."""
    if role == "broker":
        return render(cfg, pubkey, templates)
    if role not in ROLES:
        raise SeedError(f"роль {role!r}: допустимы {', '.join(ROLES)}")
    if cfg.lab is None:
        raise SeedError("в конфиге нет раздела lab (машины стенда — configs/stream.yaml)")
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(templates)),
        undefined=jinja2.StrictUndefined,
        keep_trailing_newline=True,
        autoescape=False,
    )
    lab_json = json.dumps(
        {k: cfg.raw[k] for k in ("lab", "normal", "scenarios") if k in cfg.raw},
        ensure_ascii=False,
        indent=2,
    )
    ctx = {
        "s": cfg.stand,
        "lab": cfg.lab,
        "pubkey": pubkey,
        "role": role,
        "vm": getattr(cfg.lab, role).vm,
        "packages": ATTACKER_PACKAGES,
        "runner_files": runner_files() if role == "attacker" else [],
        "lab_json": lab_json,
    }
    return {
        "user-data": env.get_template(f"user-data-{role}.yaml.j2").render(ctx),
        "meta-data": env.get_template("meta-data-role.j2").render(ctx),
    }


class _FixedTime:
    """Подмена модуля `time` внутри pycdlib: «сейчас» — фиксированная дата, часовой пояс UTC."""

    def __getattr__(self, name):
        return getattr(_time, name)

    @staticmethod
    def time() -> float:
        return FIXED_EPOCH

    @staticmethod
    def localtime(secs=None):
        return _time.gmtime(FIXED_EPOCH if secs is None else secs)


@contextmanager
def _fixed_dates():
    import pycdlib.dates
    import pycdlib.headervd
    import pycdlib.pycdlib
    import pycdlib.utils

    modules = [pycdlib.dates, pycdlib.headervd, pycdlib.pycdlib, pycdlib.utils]
    saved = [m.time for m in modules]
    try:
        for m in modules:
            m.time = _FixedTime()
        yield
    finally:
        for m, t in zip(modules, saved, strict=True):
            m.time = t


def iso_bytes(files: dict[str, str]) -> bytes:
    """ISO 9660 + Joliet + Rock Ridge с меткой тома CIDATA и файлами в корне."""
    try:
        import pycdlib
    except ImportError as exc:  # pragma: no cover - зависит от окружения
        raise SeedError("для сборки seed-ISO нужен pycdlib: `uv sync --extra stand`") from exc
    with _fixed_dates():
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, joliet=3, rock_ridge="1.09", vol_ident=VOLUME_ID)
        for i, (name, text) in enumerate(sorted(files.items())):
            data = text.encode("utf-8")
            iso.add_fp(
                io.BytesIO(data),
                len(data),
                f"/FILE{i}.;1",
                rr_name=name,
                joliet_path=f"/{name}",
            )
        out = io.BytesIO()
        iso.write_fp(out)
        iso.close()
    return out.getvalue()


def build_seed_iso(
    cfg,
    pubkey: str,
    out: Path | None = None,
    templates: Path = TEMPLATES,
    role: str = "broker",
) -> Path:
    """Собирает seed-ISO роли (по умолчанию брокер, как в 005) и пишет его атомарно."""
    out = default_out(role) if out is None else out
    rendered = render_role(cfg, role, pubkey, templates)
    data = iso_bytes({"user-data": rendered["user-data"], "meta-data": rendered["meta-data"]})
    out = Path(out)
    with atomic_path(out) as tmp:
        tmp.write_bytes(data)
    return out
