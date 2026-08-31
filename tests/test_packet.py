from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

from netsentry.packet import (
    PacketCounters,
    iter_packet_records,
    parse_packet,
)


def test_parse_tcp_packet() -> None:
    packet = (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=49152, dport=443, flags="S")
    )
    packet.time = 1.25

    record = parse_packet(packet)

    assert record is not None
    assert record.timestamp == 1.25
    assert record.src_ip == "10.0.0.1"
    assert record.dst_ip == "10.0.0.2"
    assert record.src_port == 49152
    assert record.dst_port == 443
    assert record.protocol == "TCP"
    assert record.length == len(packet[IP])
    assert record.tcp_flags == 0x02


def test_unsupported_packets_are_skipped() -> None:
    packets = [
        Ether() / ARP(),
        Ether() / IP() / ICMP(),
        Ether() / IPv6() / UDP(sport=1000, dport=2000),
    ]

    for packet in packets:
        assert parse_packet(packet) is None


def test_iterator_filters_and_counts(tmp_path: Path) -> None:
    packets = [
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=50000, dport=443, flags="S"),
        Ether()
        / IP(src="10.0.0.3", dst="8.8.8.8")
        / UDP(sport=53000, dport=53),
        Ether() / IP() / ICMP(),
        Ether() / ARP(),
        Ether() / IPv6() / UDP(sport=1000, dport=2000),
    ]

    for index, packet in enumerate(packets):
        packet.time = float(index)

    capture = tmp_path / "mixed.pcap"
    wrpcap(str(capture), packets)

    counters = PacketCounters()
    records = list(iter_packet_records(capture, counters))

    assert [record.protocol for record in records] == ["TCP", "UDP"]
    assert counters.encountered == 5
    assert counters.supported == 2
    assert counters.unsupported == 3
    assert counters.tcp_packets == 1
    assert counters.udp_packets == 1
    assert counters.bytes_processed == sum(
        record.length for record in records
    )