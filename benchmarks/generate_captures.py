from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapWriter


CAPTURE_SIZES = (
    25_000,
    50_000,
    100_000,
    200_000,
)
FLOW_COUNT = 2_048
OUTPUT_DIRECTORY = Path(__file__).parent / "data"
BASE_TIMESTAMP = 1_700_000_000.0


def make_packet(index: int) -> Packet:
    pair_index = index // 2
    flow_id = pair_index % FLOW_COUNT
    forward = index % 2 == 0
    first_exchange = pair_index < FLOW_COUNT

    client_id = flow_id % 250
    server_id = (flow_id // 250) % 200

    client_ip = f"10.0.0.{client_id + 1}"
    server_ip = f"192.0.2.{server_id + 1}"
    client_port = 40_000 + flow_id
    server_port = (53, 80, 123, 443)[flow_id % 4]

    if forward:
        source_ip, destination_ip = client_ip, server_ip
        source_port, destination_port = (
            client_port,
            server_port,
        )
        source_mac = "02:00:00:00:00:01"
        destination_mac = "02:00:00:00:00:02"
    else:
        source_ip, destination_ip = server_ip, client_ip
        source_port, destination_port = (
            server_port,
            client_port,
        )
        source_mac = "02:00:00:00:00:02"
        destination_mac = "02:00:00:00:00:01"

    if server_port in (53, 123):
        transport = UDP(
            sport=source_port,
            dport=destination_port,
        )
    else:
        if first_exchange:
            flags = "S" if forward else "SA"
        else:
            flags = "A"

        transport = TCP(
            sport=source_port,
            dport=destination_port,
            flags=flags,
        )

    payload_size = 32 + index % 96
    packet = (
        Ether(src=source_mac, dst=destination_mac)
        / IP(src=source_ip, dst=destination_ip)
        / transport
        / Raw(load=b"x" * payload_size)
    )
    packet.time = BASE_TIMESTAMP + index * 0.001
    return packet


def main() -> None:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    writers: list[tuple[int, Path, PcapWriter]] = []
    for size in CAPTURE_SIZES:
        path = OUTPUT_DIRECTORY / f"synthetic-{size}.pcap"
        writers.append(
            (
                size,
                path,
                PcapWriter(str(path), sync=False),
            )
        )

    largest_size = max(CAPTURE_SIZES)

    try:
        for index in range(largest_size):
            packet = make_packet(index)

            for size, _, writer in writers:
                if index < size:
                    writer.write(packet)

            completed = index + 1
            if completed % 25_000 == 0:
                print(
                    f"Generated "
                    f"{completed:,}/{largest_size:,} packets"
                )
    finally:
        for _, _, writer in writers:
            writer.close()

    print("\nCreated benchmark captures:")
    for size, path, _ in writers:
        print(f"  {path} ({size:,} packets)")


if __name__ == "__main__":
    main()