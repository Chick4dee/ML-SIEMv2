"""Крошечная запись «трафика стенда» 006 для тестов без ВМ (tasks T010).

Запуск из корня: `uv run python tests/fixtures/make_lab_pcap.py` → lab_sample.pcap.
Результат коммитится: тесты сенсора подменяют живой захват этой записью (research R18).

Что в записи — адреса сети стенда `10.88.0.0/24` (жертва .20, атакующий .30):
- норма: несколько веб-сессий и DNS-запросов обычного клиента .31 → жертва (benign);
- атака: «скан портов» атакующего .30 → жертва, по одному SYN на порт с ответом RST — узнаваемый
  скан (десятки коротких односторонних потоков); окно атаки лежит в `ATTACK_WINDOW_MS`.
Метки времени фиксированы → файл побайтно один и тот же при каждом запуске.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import DNS, DNSQR, IP, TCP, UDP, Ether, Raw, wrpcap

HERE = Path(__file__).parent
LAB_PCAP = HERE / "lab_sample.pcap"

VICTIM_IP = "10.88.0.20"
ATTACKER_IP = "10.88.0.30"
CLIENT_IP = "10.88.0.31"  # «обычный» клиент для нормы
VICTIM_MAC = "00:15:5d:4d:00:20"
ATTACKER_MAC = "00:15:5d:4d:00:30"
CLIENT_MAC = "00:15:5d:4d:00:31"

BASE_TS = 1790848800.0  # 2026-10-01 10:00:00 UTC — условное начало сеанса стенда
# Окно атаки (секунды от BASE_TS): журнал сценария в тестах описывает ровно его
ATTACK_START_S = 60.0
ATTACK_END_S = 70.0
# Порты, которые «сканирует» атакующий: открытые отвечают SYN-ACK, закрытые — RST
SCAN_PORTS = list(range(1, 41))
OPEN_PORTS = {22, 80}


def _tcp_session(t0: float, cli: str, cmac: str, sport: int, payload: bytes) -> list:
    c2s = Ether(src=cmac, dst=VICTIM_MAC) / IP(src=cli, dst=VICTIM_IP)
    s2c = Ether(src=VICTIM_MAC, dst=cmac) / IP(src=VICTIM_IP, dst=cli)
    seq_c, seq_s, answer = 1000, 5000, b"HTTP/1.1 200 OK\r\n\r\nhello"
    pkts = [
        c2s / TCP(sport=sport, dport=80, flags="S", seq=seq_c),
        s2c / TCP(sport=80, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
        c2s / TCP(sport=sport, dport=80, flags="A", seq=seq_c + 1, ack=seq_s + 1),
        c2s / TCP(sport=sport, dport=80, flags="PA", seq=seq_c + 1, ack=seq_s + 1) / Raw(payload),
        s2c
        / TCP(sport=80, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(payload))
        / Raw(answer),
        c2s / TCP(sport=sport, dport=80, flags="FA", seq=seq_c + 1 + len(payload), ack=seq_s + 25),
        s2c / TCP(sport=80, dport=sport, flags="FA", seq=seq_s + 25, ack=seq_c + 2 + len(payload)),
        c2s / TCP(sport=sport, dport=80, flags="A", seq=seq_c + 2 + len(payload), ack=seq_s + 26),
    ]
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.01
    return pkts


def _dns(t0: float, sport: int, name: str) -> list:
    q = (
        Ether(src=CLIENT_MAC, dst=VICTIM_MAC)
        / IP(src=CLIENT_IP, dst=VICTIM_IP)
        / UDP(sport=sport, dport=53)
        / DNS(id=sport, rd=1, qd=DNSQR(qname=name))
    )
    a = (
        Ether(src=VICTIM_MAC, dst=CLIENT_MAC)
        / IP(src=VICTIM_IP, dst=CLIENT_IP)
        / UDP(sport=53, dport=sport)
        / DNS(id=sport, qr=1, qd=DNSQR(qname=name))
    )
    q.time, a.time = t0, t0 + 0.005
    return [q, a]


def _scan(t0: float) -> list:
    pkts = []
    for i, port in enumerate(SCAN_PORTS):
        t = t0 + i * 0.2
        sport = 40000 + i
        syn = (
            Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
            / IP(src=ATTACKER_IP, dst=VICTIM_IP)
            / TCP(sport=sport, dport=port, flags="S", seq=777)
        )
        flags = "SA" if port in OPEN_PORTS else "RA"
        reply = (
            Ether(src=VICTIM_MAC, dst=ATTACKER_MAC)
            / IP(src=VICTIM_IP, dst=ATTACKER_IP)
            / TCP(sport=port, dport=sport, flags=flags, seq=9000, ack=778)
        )
        syn.time, reply.time = t, t + 0.001
        pkts += [syn, reply]
    return pkts


def build_lab_packets() -> list:
    pkts: list = []
    for i in range(6):  # норма: веб-сессии с 5-секундным шагом, потом DNS
        pkts += _tcp_session(
            BASE_TS + 5 * i,
            CLIENT_IP,
            CLIENT_MAC,
            50000 + i,
            f"GET /page{i} HTTP/1.1\r\n\r\n".encode(),
        )
    for i in range(4):
        pkts += _dns(BASE_TS + 2 + 7 * i, 53000 + i, f"host{i}.lab")
    pkts += _scan(BASE_TS + ATTACK_START_S)
    pkts.sort(key=lambda p: float(p.time))
    return pkts


if __name__ == "__main__":
    packets = build_lab_packets()
    wrpcap(str(LAB_PCAP), packets)
    print(f"{LAB_PCAP.name}: {len(packets)} пакетов")
