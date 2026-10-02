"""Собрать cloud-init NoCloud seed-ISO для облачного образа Ubuntu (обход сломанной автоустановки).

Облачный образ — уже установленная система; при загрузке cloud-init читает том CIDATA с
user-data (обычный #cloud-config, НЕ autoinstall), meta-data и network-config. Пакеты служб
ставятся на первой загрузке (apt), сеть — статический адрес стенда + install-адаптер с DHCP и
жёстким DNS. Значения берём из configs/stream.yaml, как и обычный seed.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from mlsiem.stand.seed import DEFAULT_PUBKEY, iso_bytes, read_pubkey  # noqa: E402
from mlsiem.stream.config import load_stream_config  # noqa: E402

cfg = load_stream_config(REPO / "configs" / "stream.yaml")
lab = cfg.lab
pubkey = read_pubkey(DEFAULT_PUBKEY)

VICTIM_WWW = {
    "/var/www/html/index.html": (
        "<html><body><h1>mlsiem lab victim</h1>"
        '<a href="/login">login</a><a href="/admin">admin</a>'
        '<a href="/api/status">api</a></body></html>\n'
    ),
    "/var/www/html/login/index.html": "<html><body>login page of the lab stand</body></html>\n",
    "/var/www/html/admin/index.html": "<html><body>admin page of the lab stand</body></html>\n",
    "/var/www/html/api/status": '{"status": "ok", "stand": "mlsiem-lab"}\n',
}


def _indent(text: str, n: int) -> str:
    pad = " " * n
    return "".join(pad + line if line.strip() else line for line in text.splitlines(keepends=True))


def victim_user_data() -> str:
    v = lab.victim
    parts = [
        "#cloud-config",
        f"hostname: {v.vm}",
        "ssh_pwauth: true",
        "users:",
        "  - name: default",
        f"  - name: {cfg.stand.admin_user}",
        "    groups: [sudo]",
        "    shell: /bin/bash",
        "    lock_passwd: true",
        '    sudo: "ALL=(ALL) NOPASSWD:ALL"',
        "    ssh_authorized_keys:",
        f"      - {pubkey}",
        f"  - name: {v.ssh_user}",
        "    shell: /bin/bash",
        "    lock_passwd: false",
        "chpasswd:",
        "  expire: false",
        "  users:",
        f"    - name: {v.ssh_user}",
        f"      password: {v.ssh_password}",
        "      type: text",
        "write_files:",
    ]
    files = dict(VICTIM_WWW)
    files["/etc/dnsmasq.d/mlsiem-lab.conf"] = (
        f"listen-address={v.ip}\nbind-interfaces\nno-resolv\naddress=/lab.test/{v.ip}\n"
    )
    files["/etc/vsftpd.conf"] = (
        "listen=YES\nanonymous_enable=YES\nlocal_enable=NO\nwrite_enable=NO\n"
        "anon_root=/srv/ftp\npasv_enable=YES\npasv_min_port=40000\npasv_max_port=40100\n"
    )
    files["/srv/ftp/readme.txt"] = "mlsiem lab stand: public file\n"
    files["/etc/apt/apt.conf.d/99force-ipv4"] = 'Acquire::ForceIPv4 "true";\n'
    for path, content in files.items():
        parts += [
            f"  - path: {path}",
            '    permissions: "0644"',
            "    content: |",
            _indent(content, 6).rstrip("\n"),
        ]
    parts += [
        "runcmd:",
        "  - [bash, -c, \"sed -i 's/^#\\\\?DNSStubListener=.*/DNSStubListener=no/'"
        ' /etc/systemd/resolved.conf && systemctl restart systemd-resolved || true"]',
        '  - [bash, -c, "export DEBIAN_FRONTEND=noninteractive; apt-get update &&'
        ' apt-get install -y nginx vsftpd dnsmasq"]',
        "  - [systemctl, enable, --now, nginx]",
        "  - [systemctl, enable, --now, vsftpd]",
        "  - [systemctl, enable, --now, dnsmasq]",
    ]
    return "\n".join(parts) + "\n"


def network_config(ip: str, lab_mac: str, install_mac: str) -> str:
    return (
        "version: 2\n"
        "ethernets:\n"
        "  lab:\n"
        f'    match: {{macaddress: "{lab_mac}"}}\n'
        "    set-name: lab0\n"
        "    dhcp4: false\n"
        f"    addresses: [{ip}/{lab.subnet.prefixlen}]\n"
        "  install:\n"
        f'    match: {{macaddress: "{install_mac}"}}\n'
        "    set-name: inst0\n"
        "    dhcp4: true\n"
        "    dhcp4-overrides: {use-dns: false}\n"
        "    nameservers: {addresses: [8.8.8.8, 1.1.1.1]}\n"
        "    optional: true\n"
    )


RUNNER_SVC = """[Unit]
Description=mlsiem lab runner (команды хоста по COM-порту)
After=multi-user.target

[Service]
Environment=PYTHONPATH=/opt/mlsiem/lib
Environment=MLSIEM_LAB_CONFIG=/etc/mlsiem/lab.json
Environment=MLSIEM_LAB_JOURNAL=/var/lib/mlsiem/journal.jsonl
ExecStart=/usr/bin/python3 -m mlsiem.lab.runner /dev/ttyS0
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
"""

COMMON_WORDS = "admin\nlogin\napi\napi/status\nstatic\nbackup\nconfig\nconsole\ntest\nindex.html\nrobots.txt\n"


def attacker_user_data() -> str:
    import json

    from mlsiem.stand.seed import runner_files

    parts = [
        "#cloud-config",
        f"hostname: {lab.attacker.vm}",
        "ssh_pwauth: false",
        "users:",
        "  - name: default",
        f"  - name: {cfg.stand.admin_user}",
        "    groups: [sudo]",
        "    shell: /bin/bash",
        "    lock_passwd: true",
        '    sudo: "ALL=(ALL) NOPASSWD:ALL"',
        "    ssh_authorized_keys:",
        f"      - {pubkey}",
        "write_files:",
    ]
    lab_json = json.dumps(
        {k: cfg.raw[k] for k in ("lab", "normal", "scenarios") if k in cfg.raw},
        ensure_ascii=False,
        indent=2,
    )
    files = {
        "/etc/mlsiem/lab.json": lab_json + "\n",
        "/usr/share/wordlists/common.txt": COMMON_WORDS,
        "/usr/share/wordlists/pass.txt": "123456\npassword\nqwerty\n" + lab.victim.ssh_password + "\nwelcome1\n",
        "/etc/apt/apt.conf.d/99force-ipv4": 'Acquire::ForceIPv4 "true";\n',
        "/etc/systemd/system/mlsiem-lab-runner.service": RUNNER_SVC,
    }
    for rf in runner_files():
        files[rf["path"]] = rf["text"]
    for path, content in files.items():
        parts += [
            f"  - path: {path}",
            '    permissions: "0644"',
            "    content: |",
            _indent(content, 6).rstrip("\n"),
        ]
    parts += [
        "runcmd:",
        "  - [mkdir, -p, /var/lib/mlsiem]",
        "  - [bash, -c, \"sed -i 's/^#\\\\?DNSStubListener=.*/DNSStubListener=no/'"
        ' /etc/systemd/resolved.conf && systemctl restart systemd-resolved || true"]',
        '  - [bash, -c, "export DEBIAN_FRONTEND=noninteractive; apt-get update &&'
        ' apt-get install -y nmap hydra slowhttptest hping3 tcpreplay sshpass bind9-dnsutils'
        ' gobuster || true"]',
        '  - [bash, -c, "snap install ffuf 2>/dev/null || apt-get install -y ffuf 2>/dev/null'
        ' || true"]',
        "  - [systemctl, mask, serial-getty@ttyS0.service]",
        "  - [systemctl, daemon-reload]",
        "  - [systemctl, enable, --now, mlsiem-lab-runner.service]",
    ]
    return "\n".join(parts) + "\n"


def sensor_user_data() -> str:
    parts = [
        "#cloud-config",
        "hostname: mlsiem-sensor",
        "ssh_pwauth: false",
        "users:",
        "  - name: default",
        f"  - name: {cfg.stand.admin_user}",
        "    groups: [sudo]",
        "    shell: /bin/bash",
        "    lock_passwd: true",
        '    sudo: "ALL=(ALL) NOPASSWD:ALL"',
        "    ssh_authorized_keys:",
        f"      - {pubkey}",
        "write_files:",
        "  - path: /etc/apt/apt.conf.d/99force-ipv4",
        '    permissions: "0644"',
        "    content: |",
        '      Acquire::ForceIPv4 "true";',
        "runcmd:",
        "  - [bash, -c, \"sed -i 's/^#\\\\?DNSStubListener=.*/DNSStubListener=no/'"
        ' /etc/systemd/resolved.conf && systemctl restart systemd-resolved || true"]',
        '  - [bash, -c, "export DEBIAN_FRONTEND=noninteractive; apt-get update &&'
        ' apt-get install -y python3-pip python3-venv libpcap0.8 tcpdump || true"]',
    ]
    return "\n".join(parts) + "\n"


def sensor_network() -> str:
    # lab — приёмник зеркала, БЕЗ IP (видит копии кадров стенда); mgmt — чтобы слать потоки
    # брокеру 10.77.0.10; install — интернет для разворачивания окружения
    return (
        "version: 2\n"
        "ethernets:\n"
        "  labmir:\n"
        f'    match: {{macaddress: "{lab.lab_mac["sensor"]}"}}\n'
        "    set-name: labmir\n"
        "    dhcp4: false\n"
        "    accept-ra: false\n"
        "    optional: true\n"
        "  mgmt:\n"
        '    match: {macaddress: "00:15:5d:4d:00:50"}\n'
        "    set-name: mgmt0\n"
        "    dhcp4: false\n"
        f"    addresses: [10.77.0.50/{cfg.stand.prefix}]\n"
        "  install:\n"
        '    match: {macaddress: "00:15:5d:4d:00:51"}\n'
        "    set-name: inst0\n"
        "    dhcp4: true\n"
        "    dhcp4-overrides: {use-dns: false}\n"
        "    nameservers: {addresses: [8.8.8.8, 1.1.1.1]}\n"
        "    optional: true\n"
    )


def build(role: str) -> Path:
    if role == "sensor":
        ud = sensor_user_data()
        net = sensor_network()
        vm = "mlsiem-sensor"
        meta = f"instance-id: {vm}-cloud-1\nlocal-hostname: {vm}\n"
        data = iso_bytes({"user-data": ud, "meta-data": meta, "network-config": net})
        out = REPO / "var" / "stand" / "seed-cloud-sensor.iso"
        out.write_bytes(data)
        return out
    if role == "victim":
        ud = victim_user_data()
        net = network_config(lab.victim.ip, lab.lab_mac["victim"], lab.lab_mac["victim_install"])
        vm = lab.victim.vm
    elif role == "attacker":
        ud = attacker_user_data()
        net = network_config(
            lab.attacker.ip, lab.lab_mac["attacker"], lab.lab_mac["attacker_install"]
        )
        vm = lab.attacker.vm
    else:
        raise SystemExit("роль: victim|attacker")
    meta = f"instance-id: {vm}-cloud-1\nlocal-hostname: {vm}\n"
    data = iso_bytes({"user-data": ud, "meta-data": meta, "network-config": net})
    out = REPO / "var" / "stand" / f"seed-cloud-{role}.iso"
    out.write_bytes(data)
    return out


if __name__ == "__main__":
    role = sys.argv[1] if len(sys.argv) > 1 else "victim"
    p = build(role)
    print(f"seed: {p} ({p.stat().st_size} bytes)")
