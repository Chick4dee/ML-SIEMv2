"""Тесты захватов: отпечатки, манифесты, атомарная запись, решение о пересчёте."""

import os

import pytest

from mlsiem.data.captures import (
    CaptureManifest,
    atomic_path,
    fingerprint,
    needs_processing,
    read_manifest,
    write_manifest,
)

MB = 1024 * 1024


@pytest.fixture
def big_file(tmp_path):
    # 40 МБ: голова и хвост по 16 МБ не пересекаются, и есть середина, которую отпечаток не читает
    path = tmp_path / "big.pcap"
    path.write_bytes(bytes(40 * MB))
    os.utime(path, ns=(1_000_000_000, 1_000_000_000))
    return path


def _patch(path, offset, value=b"\x01"):
    """Меняет байт внутри файла, сохраняя mtime, — проверяем именно чтение содержимого."""
    stat = path.stat()
    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(value)
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns))


def test_fingerprint_changes_on_head_tail_size_mtime(big_file):
    base = fingerprint(big_file)
    assert fingerprint(big_file) == base

    _patch(big_file, 10)
    head = fingerprint(big_file)
    assert head != base

    _patch(big_file, 40 * MB - 10)
    assert fingerprint(big_file) != head

    os.utime(big_file, ns=(2_000_000_000, 2_000_000_000))
    assert fingerprint(big_file)["mtime_ns"] == 2_000_000_000

    with open(big_file, "ab") as f:
        f.write(b"x")
    assert fingerprint(big_file)["size"] == 40 * MB + 1


def test_full_hash_flag(big_file):
    partial = fingerprint(big_file)
    full = fingerprint(big_file, full=True)
    assert partial["full_sha256"] is None
    assert full["full_sha256"]
    # полный отпечаток совместим с частичным: пересчёт не нужен
    assert full["partial_sha256"] == partial["partial_sha256"]


def _manifest(**overrides) -> CaptureManifest:
    base = dict(
        capture_id="ctu13_07",
        fingerprint={"size": 1, "mtime_ns": 2, "partial_sha256": "a", "full_sha256": None},
        label_source_fingerprint={
            "size": 3,
            "mtime_ns": 4,
            "partial_sha256": "b",
            "full_sha256": None,
        },
        labeling_params_hash="p",
        schema_version="1.0.0",
        labeling_version="1.0.0",
        status="done",
    )
    base.update(overrides)
    return CaptureManifest(**base)


def test_manifest_roundtrip(tmp_path):
    m = _manifest(n_flows=51, label_counts={"botnet": 44}, warnings=["обрыв"])
    path = tmp_path / "ctu13_07.json"
    write_manifest(m, path)
    assert read_manifest(path) == m


def test_atomic_write_leaves_nothing_on_error(tmp_path):
    final = tmp_path / "out.parquet"
    with pytest.raises(RuntimeError), atomic_path(final) as tmp:
        tmp.write_bytes(b"half")
        raise RuntimeError("упали посреди записи")
    assert not final.exists()
    assert list(tmp_path.iterdir()) == []


def _needs(m, **kw):
    args = dict(
        fingerprint=_manifest().fingerprint,
        label_source_fingerprint=_manifest().label_source_fingerprint,
        labeling_params_hash="p",
        schema_version="1.0.0",
        labeling_version="1.0.0",
        output_exists=True,
    )
    args.update(kw)
    return needs_processing(m, **args)


def test_needs_processing_rules():
    done = _manifest()
    assert not _needs(done)
    assert _needs(None)
    assert _needs(_manifest(status="failed"))
    assert _needs(done, output_exists=False)
    assert _needs(done, fingerprint={**done.fingerprint, "size": 999})
    assert _needs(done, schema_version="2.0.0")
    assert _needs(done, labeling_version="1.1.0")
    assert _needs(
        done, label_source_fingerprint={**done.label_source_fingerprint, "partial_sha256": "c"}
    )
    # смена timezone в конфиге меняет хеш параметров разметки
    assert _needs(done, labeling_params_hash="другой")
    assert _needs(done, force=True)


def test_full_hash_compared_only_when_both_known():
    done = _manifest(
        fingerprint={"size": 1, "mtime_ns": 2, "partial_sha256": "a", "full_sha256": "F"}
    )
    assert not _needs(done)  # сейчас полного хеша нет — сравниваем только частичный
    assert _needs(
        done, fingerprint={"size": 1, "mtime_ns": 2, "partial_sha256": "a", "full_sha256": "G"}
    )
