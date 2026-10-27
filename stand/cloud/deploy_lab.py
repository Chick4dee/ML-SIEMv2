"""Обновление машин стенда под фичу 008: инструменты, словари, код раннера, уязвимое приложение.

Запускается на хосте, когда у машин на время работы подключены адаптеры «install» (интернет и SSH):
    uv run python stand/cloud/deploy_lab.py --attacker <ip> --victim <ip>
Адреса адаптеров install можно узнать командой `--discover` (по MAC из configs/stream.yaml).

Что делает (всё повторяемо):
- атакующая: ставит инструменты сценариев 008 из репозиториев Ubuntu (недоступный пакет не
  останавливает установку — его варианты потом пропустит сбор), кладёт большие словари, код раннера
  (`mlsiem.lab.*`, включая variants.py) и конфиг `/etc/mlsiem/lab.json`, перезапускает службу раннера;
- жертва: ставит намеренно уязвимое веб-приложение (SQL-инъекция) на порту 8080 — цель варианта sqlmap.
После работы отключите адаптеры install (`Disconnect-VMNetworkAdapter`) и проверьте `stand check`.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "src"))

from mlsiem.stand.seed import runner_files  # noqa: E402
from mlsiem.stream.config import load_stream_config  # noqa: E402

SSH_OPTS = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "StrictHostKeyChecking=no",
]
PACKAGES = [
    "nmap",
    "masscan",
    "hydra",
    "medusa",
    "gobuster",
    "ffuf",
    "slowhttptest",
    "slowloris",
    "hping3",
    "nikto",
    "sqlmap",
    "apache2-utils",
    "wget",
    "curl",
    "sshpass",
    "bind9-dnsutils",
    "tcpreplay",
    "tcpdump",
    "iproute2",
]

VULNAPP = '''#!/usr/bin/env python3
"""Намеренно уязвимое приложение изолированного стенда: SQL-инъекция в /search. Только для сети стенда."""
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript(
    "create table items(id integer primary key, name text, price integer);"
    "insert into items(name, price) values ('apple', 10), ('orange', 12), ('pear', 9), ('plum', 15), ('melon', 30);"
    "create table users(id integer primary key, login text, secret text);"
    "insert into users(login, secret) values ('admin', 's3cret'), ('guest', 'guest');"
)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        if url.path == "/search":
            q = urllib.parse.parse_qs(url.query).get("q", [""])[0]
            try:
                # намеренно уязвимо: строка запроса склеивается с вводом пользователя
                rows = DB.execute("select id, name from items where name like '%" + q + "%'").fetchall()
                body, code = "\\n".join(f"{i}:{n}" for i, n in rows) or "нет совпадений", 200
            except Exception as exc:
                body, code = f"ошибка запроса: {exc}", 500
        else:
            body, code = "<html><body>lab vulnapp: /search?q=</body></html>", 200
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
'''

VULNAPP_SVC = """[Unit]
Description=mlsiem lab vulnerable app (SQL injection, only inside the lab network)
After=network.target

[Service]
ExecStart=/usr/bin/python3 /opt/mlsiem/vulnapp.py
Restart=always

[Install]
WantedBy=multi-user.target
"""


def words(n: int, seed: int) -> list[str]:
    """Детерминированный словарь путей: связки слов и числовых суффиксов, n уникальных строк."""
    rng = random.Random(seed)
    base = [
        "admin",
        "login",
        "api",
        "static",
        "backup",
        "config",
        "console",
        "test",
        "index",
        "user",
        "users",
        "data",
        "files",
        "upload",
        "download",
        "images",
        "css",
        "js",
        "docs",
        "help",
        "search",
        "status",
        "health",
        "old",
        "new",
        "dev",
        "stage",
        "private",
        "public",
        "tmp",
        "cache",
        "logs",
        "report",
        "export",
        "import",
        "panel",
        "manage",
        "portal",
        "shop",
        "cart",
        "order",
        "pay",
        "account",
        "profile",
        "settings",
        "assets",
        "media",
    ]
    out: set[str] = set(base)
    while len(out) < n:
        out.add(
            f"{rng.choice(base)}{rng.choice(['', '_', '-', '/'])}{rng.choice(base)}{rng.randrange(0, 200) if rng.random() < 0.7 else ''}"
        )
    return sorted(out)


def passwords(n: int, seed: int, real: str) -> list[str]:
    """Словарь паролей: n-1 правдоподобных неверных и настоящий пароль учётки В КОНЦЕ (перебор не заканчивается рано)."""
    rng = random.Random(seed)
    base = [
        "welcome",
        "qwerty",
        "password",
        "letmein",
        "admin",
        "monkey",
        "dragon",
        "master",
        "sunshine",
        "football",
    ]
    out: list[str] = []
    seen = {real}
    while len(out) < n - 1:
        w = f"{rng.choice(base)}{rng.randrange(0, 10000)}"
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out + [real]


def run(argv: list[str], timeout: int = 600, check: bool = True) -> subprocess.CompletedProcess:
    done = subprocess.run(
        argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout
    )
    if check and done.returncode != 0:
        raise SystemExit(
            f"команда {' '.join(argv[:3])}… вернула {done.returncode}: {(done.stderr or done.stdout).strip()[:300]}"
        )
    return done


def ssh(
    target: str, command: str, timeout: int = 900, check: bool = True
) -> subprocess.CompletedProcess:
    return run(["ssh", *SSH_OPTS, target, command], timeout, check)


def scp_text(target: str, remote_path: str, text: str) -> None:
    """Кладёт текст на машину: во временный файл, затем sudo install (каталог создаётся)."""
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", suffix=".tmp", delete=False
    ) as f:
        f.write(text)
        tmp = f.name
    try:
        run(["scp", *SSH_OPTS, tmp, f"{target}:/tmp/_deploy.tmp"])
        ssh(
            target,
            f"sudo install -D -m 0644 /tmp/_deploy.tmp {remote_path} && rm -f /tmp/_deploy.tmp",
        )
    finally:
        Path(tmp).unlink(missing_ok=True)


def discover(macs: dict[str, str]) -> dict[str, str | None]:
    """IP адаптеров install по MAC через таблицу соседей хоста (после пинг-прогона домашней сети)."""
    ps = (
        "Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } | "
        'ForEach-Object { "$($_.LinkLayerAddress) $($_.IPAddress)" }'
    )
    out = run(["powershell", "-NoProfile", "-Command", ps], 60).stdout.upper().replace("-", ":")
    found: dict[str, str | None] = {}
    for name, mac in macs.items():
        key = mac.upper()
        ip = next(
            (line.split()[1] for line in out.splitlines() if line.strip().startswith(key)), None
        )
        found[name] = ip
    return found


def deploy_attacker(cfg, target: str) -> None:
    print(f"[атакующая] {target}: обновление индекса и пакеты…")
    ssh(target, "sudo apt-get update >/dev/null 2>&1 || true", check=False)
    for pkg in PACKAGES:
        done = ssh(
            target,
            f"export DEBIAN_FRONTEND=noninteractive; sudo apt-get install -y {pkg} >/dev/null 2>&1 && echo OK || echo MISSING",
            check=False,
        )
        print(f"  {pkg}: {'ok' if 'OK' in done.stdout else 'НЕТ В РЕПОЗИТОРИИ'}")
    print("[атакующая] словари…")
    scp_text(target, "/usr/share/wordlists/common.txt", "\n".join(words(20000, 1)) + "\n")
    scp_text(
        target,
        "/usr/share/wordlists/pass.txt",
        "\n".join(passwords(1500, 2, cfg.lab.victim.ssh_password)) + "\n",
    )
    print("[атакующая] код раннера и конфиг…")
    for rf in runner_files():
        scp_text(target, rf["path"], rf["text"])
    lab_json = json.dumps(
        {k: cfg.raw[k] for k in ("lab", "normal", "scenarios") if k in cfg.raw},
        ensure_ascii=False,
        indent=2,
    )
    scp_text(target, "/etc/mlsiem/lab.json", lab_json + "\n")
    ssh(
        target,
        "sudo systemctl restart mlsiem-lab-runner && sleep 2 && systemctl is-active mlsiem-lab-runner",
    )
    print("[атакующая] готово")


def deploy_victim(cfg, target: str) -> None:
    print(f"[жертва] {target}: уязвимое приложение…")
    scp_text(target, "/opt/mlsiem/vulnapp.py", VULNAPP)
    scp_text(target, "/etc/systemd/system/mlsiem-vulnapp.service", VULNAPP_SVC)
    ssh(
        target,
        "sudo systemctl daemon-reload && sudo systemctl enable --now mlsiem-vulnapp && sleep 2 && "
        f"curl -s 'http://127.0.0.1:8080/search?q=app' && echo && curl -s -o /dev/null -w '%{{http_code}}\\n' 'http://127.0.0.1:8080/search?q=%27'",
    )
    print("[жертва] готово")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--attacker", help="IP адаптера install атакующей машины")
    ap.add_argument("--victim", help="IP адаптера install жертвы")
    ap.add_argument("--user", default="mlsiem")
    ap.add_argument(
        "--discover", action="store_true", help="найти IP адаптеров install по MAC и выйти"
    )
    args = ap.parse_args()
    cfg = load_stream_config(REPO / "configs" / "stream.yaml")
    macs = {
        "attacker": cfg.lab.lab_mac["attacker_install"],
        "victim": cfg.lab.lab_mac["victim_install"],
        "sensor": cfg.lab.lab_mac.get("sensor_install", "00:15:5D:4D:00:51"),
    }
    if args.discover:
        print(json.dumps(discover(macs), ensure_ascii=False, indent=1))
        return 0
    if args.attacker:
        deploy_attacker(cfg, f"{args.user}@{args.attacker}")
    if args.victim:
        deploy_victim(cfg, f"{args.user}@{args.victim}")
    if not (args.attacker or args.victim):
        print("Нужно --attacker и/или --victim (или --discover)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
