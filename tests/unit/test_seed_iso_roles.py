"""Seed-ISO по ролям машин стенда (фича 006, US1, research R3–R5).

Жертва: службы R4 и тестовая SSH-учётка. Атакующий: инструменты R5 и раннер сценариев (тот
самый код `mlsiem.lab`, что проверяется остальными тестами). MAC и адрес — из конфига.
"""

import io
from pathlib import Path

import pycdlib
import pytest
import yaml

from mlsiem.stand.seed import (
    SeedError,
    build_seed_iso,
    default_out,
    render_role,
    runner_files,
)
from mlsiem.stream.config import load_stream_config

REPO = Path(__file__).parents[2]
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMlsiemTestKeyOnly vlad@host"


@pytest.fixture(scope="module")
def cfg():
    return load_stream_config(REPO / "configs" / "stream.yaml")


def _doc(cfg, role) -> dict:
    return yaml.safe_load(render_role(cfg, role, KEY)["user-data"])["autoinstall"]


def _files(ai) -> dict[str, str]:
    return {f["path"]: f["content"] for f in ai["user-data"]["write_files"]}


def test_victim_network_and_services(cfg):
    ai = _doc(cfg, "victim")
    lab = ai["network"]["ethernets"]["lab"]
    assert lab["addresses"] == ["10.88.0.20/24"]
    assert lab["match"]["macaddress"] == cfg.lab.lab_mac["victim"]
    assert "gateway4" not in lab and "routes" not in lab  # наружу пути нет (изоляция)
    assert ai["network"]["ethernets"]["install"]["dhcp4"] is True
    # Службы ставятся в runcmd (на этапе curtin dnsmasq конфликтует с resolved и валит
    # установку), а на этапе установки — только curl
    assert "curl" in ai["packages"]
    rc = [" ".join(c) if isinstance(c, list) else c for c in ai["user-data"]["runcmd"]]
    assert any("install -y nginx vsftpd dnsmasq" in c for c in rc)
    assert any("DNSStubListener" in c for c in rc)
    # SSH с паролем нужен ради тестовой учётки, пароль — из конфига
    assert ai["ssh"]["allow-pw"] is True
    users = {u["name"]: u for u in ai["user-data"]["users"]}
    assert cfg.lab.victim.ssh_user in users and cfg.stand.admin_user in users
    chp = ai["user-data"]["chpasswd"]["users"][0]
    assert chp["name"] == cfg.lab.victim.ssh_user
    assert chp["password"] == cfg.lab.victim.ssh_password
    files = _files(ai)
    assert "listen-address=10.88.0.20" in files["/etc/dnsmasq.d/mlsiem-lab.conf"]
    assert "anonymous_enable=YES" in files["/etc/vsftpd.conf"]
    assert "write_enable=NO" in files["/etc/vsftpd.conf"]
    assert "/var/www/html/admin/index.html" in files  # пути для фаззинга


def test_attacker_tools_and_runner(cfg):
    ai = _doc(cfg, "attacker")
    assert ai["network"]["ethernets"]["lab"]["addresses"] == ["10.88.0.30/24"]
    # Инструменты ставятся в runcmd (ffuf нет в штатных репозиториях — иначе install_fail),
    # на этапе установки — только база
    assert "python3" in ai["packages"]
    rc = [" ".join(c) if isinstance(c, list) else c for c in ai["user-data"]["runcmd"]]
    joined = "\n".join(rc)
    for tool in ("nmap", "hydra", "tcpreplay", "slowhttptest"):
        assert tool in joined, tool
    assert "ffuf" in joined  # ставится из snap с запасным gobuster
    files = _files(ai)
    # Раннер — те же файлы, что в репозитории
    for f in runner_files():
        assert files[f["path"]].strip() == f["text"].strip()
    assert "/opt/mlsiem/lib/mlsiem/lab/runner.py" in files
    import json

    lab_json = json.loads(files["/etc/mlsiem/lab.json"])
    assert lab_json["lab"]["subnet"] == "10.88.0.0/24"
    assert [s["name"] for s in lab_json["scenarios"]] == [s.name for s in cfg.scenarios]
    # Верный пароль тестовой учётки есть среди словаря подбора
    assert cfg.lab.victim.ssh_password in files["/usr/share/wordlists/pass.txt"]
    cmds = [" ".join(c) if isinstance(c, list) else c for c in ai["user-data"]["runcmd"]]
    assert any("mlsiem-lab-runner" in c for c in cmds)
    assert any("serial-getty" in c for c in cmds)


def test_attacker_has_no_mgmt_adapter(cfg):
    """У машин стенда нет служебной сети: из сети стенда к хосту/брокеру пути нет (FR-005)."""
    for role in ("victim", "attacker"):
        text = render_role(cfg, role, KEY)["user-data"]
        assert cfg.stand.mgmt_mac not in text
        assert cfg.stand.broker_ip not in text


def test_meta_data_and_default_out(cfg):
    assert "local-hostname: mlsiem-victim" in render_role(cfg, "victim", KEY)["meta-data"]
    assert default_out("broker") == Path("var/stand/seed.iso")
    assert default_out("attacker") == Path("var/stand/seed-attacker.iso")


def test_role_errors(cfg):
    with pytest.raises(SeedError, match="роль"):
        render_role(cfg, "sensor", KEY)
    no_lab = type(cfg)(**{**cfg.__dict__, "lab": None})
    with pytest.raises(SeedError, match="lab"):
        render_role(no_lab, "victim", KEY)


def test_iso_per_role_cidata_and_deterministic(cfg, tmp_path):
    a = build_seed_iso(cfg, KEY, tmp_path / "a.iso", role="attacker")
    b = build_seed_iso(cfg, KEY, tmp_path / "b.iso", role="attacker")
    assert a.read_bytes() == b.read_bytes()
    iso = pycdlib.PyCdlib()
    iso.open(str(a))
    try:
        assert iso.pvd.volume_identifier.decode().strip() == "CIDATA"
        buf = io.BytesIO()
        iso.get_file_from_iso_fp(buf, rr_path="/user-data")
        assert buf.getvalue().decode("utf-8").startswith("#cloud-config")
    finally:
        iso.close()
