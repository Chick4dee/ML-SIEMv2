"""Seed-ISO автоустановки брокерной машины (US1, research R3).

Проверяем то, от чего зависит, поднимется ли машина с первого раза: метка тома CIDATA,
корректный YAML автоустановки с адресом, пользователем, ключом и пакетами, установка Kafka с
проверкой SHA-512, брандмауэр, топики — и то, что сборка воспроизводима байт в байт.
"""

import io
import re
from pathlib import Path

import pycdlib
import pytest
import yaml

from mlsiem.stand.seed import SeedError, build_seed_iso, read_pubkey, render
from mlsiem.stream.config import load_stream_config

REPO = Path(__file__).parents[2]
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlsiemTestKeyOnly vlad@host"


@pytest.fixture(scope="module")
def cfg():
    return load_stream_config(REPO / "configs" / "stream.yaml")


@pytest.fixture
def pubkey(tmp_path) -> Path:
    p = tmp_path / "id_ed25519.pub"
    p.write_text(KEY + "\n", encoding="utf-8")
    return p


def _iso_files(path: Path) -> tuple[str, dict[str, str]]:
    iso = pycdlib.PyCdlib()
    iso.open(str(path))
    try:
        label = iso.pvd.volume_identifier.decode().strip()
        files = {}
        for child in iso.list_children(rr_path="/"):
            if child.is_file():
                name = child.rock_ridge.name().decode()
                buf = io.BytesIO()
                iso.get_file_from_iso_fp(buf, rr_path=f"/{name}")
                files[name] = buf.getvalue().decode("utf-8")
        return label, files
    finally:
        iso.close()


def test_iso_has_cidata_and_files(cfg, pubkey, tmp_path):
    out = build_seed_iso(cfg, read_pubkey(pubkey), tmp_path / "seed.iso")
    label, files = _iso_files(out)
    assert label == "CIDATA"
    assert set(files) == {"user-data", "meta-data"}
    assert "instance-id:" in files["meta-data"]
    assert files["user-data"].startswith("#cloud-config")


def test_user_data_autoinstall(cfg):
    doc = yaml.safe_load(render(cfg, KEY)["user-data"])
    ai = doc["autoinstall"]
    assert ai["version"] == 1
    mgmt = ai["network"]["ethernets"]["mgmt"]
    assert mgmt["addresses"] == [f"{cfg.stand.broker_ip}/{cfg.stand.prefix}"]
    assert mgmt["match"]["macaddress"] == cfg.stand.mgmt_mac
    assert ai["network"]["ethernets"]["install"]["dhcp4"] is True
    assert {"openjdk-21-jre-headless", "ufw"} <= set(ai["packages"])
    user = ai["user-data"]["users"][0]
    assert user["name"] == cfg.stand.admin_user
    assert user["ssh_authorized_keys"] == [KEY]
    assert user["lock_passwd"] is True
    assert ai["ssh"]["allow-pw"] is False
    paths = {f["path"] for f in ai["user-data"]["write_files"]}
    assert {"/etc/mlsiem/server.properties", "/etc/systemd/system/kafka.service"} <= paths


def test_server_properties(cfg):
    props = render(cfg, KEY)["server_properties"]
    assert "process.roles=broker,controller" in props
    assert f"listeners=PLAINTEXT://{cfg.stand.broker_ip}:9092,CONTROLLER://127.0.0.1:9093" in props
    assert "auto.create.topics.enable=false" in props
    # В user-data свойства лежат целиком (write_files)
    doc = yaml.safe_load(render(cfg, KEY)["user-data"])
    files = {f["path"]: f["content"] for f in doc["autoinstall"]["user-data"]["write_files"]}
    assert files["/etc/mlsiem/server.properties"].strip() == props.strip()


def test_kafka_service_heap(cfg):
    unit = render(cfg, KEY)["kafka_service"]
    heap = cfg.stand.kafka_heap_mb
    assert f"KAFKA_HEAP_OPTS=-Xms{heap}m -Xmx{heap}m" in unit
    assert "User=kafka" in unit


def test_install_script(cfg):
    script = render(cfg, KEY)["install_script"]
    s = cfg.stand
    assert f'VERSION="{s.kafka_version}"' in script
    assert f'SHA512="{s.kafka_sha512}"' in script
    assert "sha512sum -c -" in script
    assert "downloads.apache.org/kafka" in script
    assert 'kafka-storage.sh format -t "${CLUSTER_ID}"' in script
    # ufw: 9092 только из служебной сети, 22 только с хоста
    assert f"ufw allow from {s.network} to any port 9092 proto tcp" in script
    assert f"ufw allow from {s.host_ip} to any port 22 proto tcp" in script
    assert "ufw default deny incoming" in script
    for topic, parts in ((cfg.topics.flows, cfg.topics.partitions), (cfg.topics.rejected, 1)):
        assert re.search(
            rf"--topic {re.escape(topic)} --partitions {parts} .*\n.*retention.ms="
            rf"{cfg.topics.retention_ms}",
            script,
        ), topic


def test_missing_key_explains(tmp_path):
    with pytest.raises(SeedError, match="ssh-keygen -t ed25519"):
        read_pubkey(tmp_path / "nope.pub")


def test_private_key_refused(tmp_path):
    p = tmp_path / "id"
    p.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nxxx\n", encoding="utf-8")
    with pytest.raises(SeedError, match="открытый"):
        read_pubkey(p)


def test_deterministic(cfg, tmp_path):
    a = build_seed_iso(cfg, KEY, tmp_path / "a.iso").read_bytes()
    b = build_seed_iso(cfg, KEY, tmp_path / "b.iso").read_bytes()
    assert a == b
    c = build_seed_iso(cfg, KEY.replace("vlad", "other"), tmp_path / "c.iso").read_bytes()
    assert a != c
