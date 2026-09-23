"""Генерирует маленькие PCAP-фикстуры для тестов экстрактора и конвейера.

Запуск (из корня репозитория): `uv run python tests/fixtures/make_synthetic_pcap.py`.
Результат коммитится в git — так тесты не зависят от 100 ГБ настоящих датасетов.

Временные метки фиксированы, поэтому файлы получаются побайтно одинаковыми при каждом
запуске. Базовое время — 2015-01-22 10:00:00 UTC: условный «день UNSW», чтобы мини-разметка
в тестах выглядела правдоподобно.
"""

from pathlib import Path

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.utils import PcapNgWriter

HERE = Path(__file__).parent
BASE_TS = 1421920800.0  # 2015-01-22 10:00:00 UTC

CLIENT_MAC = "00:11:22:33:44:55"
SERVER_MAC = "66:77:88:99:aa:bb"


def _eth(src_mac: str, dst_mac: str):
    return Ether(src=src_mac, dst=dst_mac)


def tcp_session(t0: float, cli: str, srv: str, sport: int, dport: int, payload: bytes):
    """Полная TCP-сессия: рукопожатие, запрос, ответ, закрытие через FIN."""
    c2s = _eth(CLIENT_MAC, SERVER_MAC) / IP(src=cli, dst=srv)
    s2c = _eth(SERVER_MAC, CLIENT_MAC) / IP(src=srv, dst=cli)
    seq_c, seq_s = 1000, 5000
    pkts = [
        c2s / TCP(sport=sport, dport=dport, flags="S", seq=seq_c),
        s2c / TCP(sport=dport, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1),
        c2s / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1),
        c2s
        / TCP(sport=sport, dport=dport, flags="PA", seq=seq_c + 1, ack=seq_s + 1)
        / Raw(payload),
        s2c
        / TCP(sport=dport, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1 + len(payload))
        / Raw(b"HTTP/1.1 200 OK\r\n\r\nhello"),
        c2s
        / TCP(sport=sport, dport=dport, flags="FA", seq=seq_c + 1 + len(payload), ack=seq_s + 25),
        s2c
        / TCP(sport=dport, dport=sport, flags="FA", seq=seq_s + 25, ack=seq_c + 2 + len(payload)),
        c2s
        / TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 2 + len(payload), ack=seq_s + 26),
    ]
    # Разносим пакеты на 10 мс: так у потока есть длительность и межпакетные интервалы
    for i, p in enumerate(pkts):
        p.time = t0 + i * 0.01
    return pkts


def udp_dns(t0: float, cli: str, srv: str, sport: int, qname: str):
    q = (
        _eth(CLIENT_MAC, SERVER_MAC)
        / IP(src=cli, dst=srv)
        / UDP(sport=sport, dport=53)
        / DNS(id=sport, rd=1, qd=DNSQR(qname=qname))
    )
    r = (
        _eth(SERVER_MAC, CLIENT_MAC)
        / IP(src=srv, dst=cli)
        / UDP(sport=53, dport=sport)
        / DNS(id=sport, qr=1, qd=DNSQR(qname=qname))
    )
    q.time, r.time = t0, t0 + 0.02
    return [q, r]


def icmp_echo(t0: float, cli: str, srv: str, count: int = 3):
    pkts = []
    for i in range(count):
        req = _eth(CLIENT_MAC, SERVER_MAC) / IP(src=cli, dst=srv) / ICMP(type=8, id=1, seq=i)
        rep = _eth(SERVER_MAC, CLIENT_MAC) / IP(src=srv, dst=cli) / ICMP(type=0, id=1, seq=i)
        req.time, rep.time = t0 + i, t0 + i + 0.005
        pkts += [req, rep]
    return pkts


def build_packets():
    """Набор трафика: веб-сессии, «атакующая» сессия, DNS и ping.

    Две сессии специально стартуют в одну и ту же миллисекунду с одного клиента на разные
    порты — это проверяет, что сортировка стабильна не только по времени.
    """
    pkts = []
    pkts += tcp_session(
        BASE_TS + 0.0, "10.0.0.1", "10.0.0.100", 40001, 80, b"GET / HTTP/1.1\r\n\r\n"
    )
    pkts += tcp_session(
        BASE_TS + 0.0, "10.0.0.1", "10.0.0.100", 40002, 8080, b"GET /a HTTP/1.1\r\n\r\n"
    )
    pkts += udp_dns(BASE_TS + 1.0, "10.0.0.2", "10.0.0.53", 50001, "example.com")
    pkts += icmp_echo(BASE_TS + 2.0, "10.0.0.3", "10.0.0.100")
    # «Атака»: клиент 175.45.176.1 — адрес из подсети атакующих UNSW
    pkts += tcp_session(
        BASE_TS + 5.0, "175.45.176.1", "149.171.126.10", 1043, 21, b"USER anonymous\r\n"
    )
    pkts += udp_dns(BASE_TS + 6.0, "10.0.0.2", "10.0.0.53", 50002, "test.org")
    pkts += tcp_session(BASE_TS + 8.0, "10.0.0.4", "10.0.0.100", 40100, 443, b"\x16\x03\x01hello")
    pkts.sort(key=lambda p: float(p.time))
    return pkts


def main() -> None:
    pkts = build_packets()
    pcap = HERE / "synthetic.pcap"
    wrpcap(str(pcap), pkts)

    with PcapNgWriter(str(HERE / "synthetic.pcapng")) as w:
        for p in pkts:
            w.write(p)

    # Обрезанный файл: отрезаем хвост посреди последнего пакета — так выглядит PCAP,
    # который писали на диск и оборвали (закончилось место, упал tcpdump)
    data = pcap.read_bytes()
    (HERE / "truncated.pcap").write_bytes(data[: len(data) - 30])
    print(f"записано {len(pkts)} пакетов в {pcap.name}, .pcapng и truncated.pcap")


if __name__ == "__main__":
    main()
