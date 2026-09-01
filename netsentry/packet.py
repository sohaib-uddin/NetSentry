from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
from scapy.utils import PcapReader
from scapy.config import conf
from scapy.layers.l2 import Dot1Q
from contextlib import contextmanager


Protocol = Literal["TCP", "UDP"]


@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: Protocol
    length: int
    tcp_flags: int = 0


@dataclass(slots=True)
class PacketCounters:
    encountered: int = 0
    supported: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    bytes_processed: int = 0

    @property
    def unsupported(self) -> int:
        return self.encountered - self.supported

    def observe(self, record: PacketRecord) -> None:
        self.supported += 1
        self.bytes_processed += record.length

        if record.protocol == "TCP":
            self.tcp_packets += 1
        else:
            self.udp_packets += 1


class PcapReadError(Exception):
    """Raised when a capture cannot be decoded."""


def parse_packet(packet: Packet) -> PacketRecord | None:
    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    transport = ip.payload

    if isinstance(transport, TCP):
        protocol: Protocol = "TCP"
        tcp_flags = int(transport.flags)
    elif isinstance(transport, UDP):
        protocol = "UDP"
        tcp_flags = 0
    else:
        return None

    length = int(ip.len) if ip.len is not None else len(ip)

    return PacketRecord(
        timestamp=float(packet.time),
        src_ip=str(ip.src),
        dst_ip=str(ip.dst),
        src_port=int(transport.sport),
        dst_port=int(transport.dport),
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
    )


@contextmanager
def _filtered_reader(
    path: Path,
) -> Iterator[PcapReader]:
    with PcapReader(str(path)) as reader:
        conf.layers.filter(
            [
                reader.LLcls,
                Dot1Q,
                IP,
                TCP,
                UDP,
            ]
        )
        try:
            yield reader
        finally:
            conf.layers.unfilter()


def iter_packet_records(
    path: Path,
    counters: PacketCounters,
) -> Iterator[PacketRecord]:
    try:
        with _filtered_reader(path) as reader:
            for packet in reader:
                counters.encountered += 1
                record = parse_packet(packet)

                if record is None:
                    continue

                counters.observe(record)
                yield record
    except (OSError, EOFError, Scapy_Exception) as exc:
        raise PcapReadError(
            f"could not read PCAP '{path}': {exc}"
        ) from exc