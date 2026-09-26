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
import time as _time
from contextlib import contextmanager
from pathlib import Path

import jinja2

from mlsiem.data.captures import atomic_path
from mlsiem.stream.broker import topic_specs

REPO = Path(__file__).resolve().parents[3]
TEMPLATES = REPO / "stand" / "broker"
DEFAULT_OUT = Path("var/stand/seed.iso")
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


def build_seed_iso(cfg, pubkey: str, out: Path = DEFAULT_OUT, templates: Path = TEMPLATES) -> Path:
    """Собирает seed-ISO и пишет его атомарно; возвращает путь."""
    rendered = render(cfg, pubkey, templates)
    data = iso_bytes({"user-data": rendered["user-data"], "meta-data": rendered["meta-data"]})
    out = Path(out)
    with atomic_path(out) as tmp:
        tmp.write_bytes(data)
    return out
