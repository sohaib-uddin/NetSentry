from math import isclose

from netsentry.flow import (
    FlowTable,
    RunningStats,
    canonical_flow,
)
from netsentry.packet import PacketRecord, Protocol


def make_packet(
    timestamp: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: Protocol = "TCP",
    length: int = 60,
    tcp_flags: int = 0,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=length,
        tcp_flags=tcp_flags,
    )


def test_reversed_packets_share_canonical_key() -> None:
    forward = make_packet(
        1.0,
        "10.0.0.1",
        50000,
        "10.0.0.2",
        443,
    )
    reverse = make_packet(
        2.0,
        "10.0.0.2",
        443,
        "10.0.0.1",
        50000,
    )

    forward_key, forward_direction = canonical_flow(forward)
    reverse_key, reverse_direction = canonical_flow(reverse)

    assert forward_key == reverse_key
    assert forward_direction == "A_TO_B"
    assert reverse_direction == "B_TO_A"


def test_flow_table_tracks_both_directions() -> None:
    table = FlowTable()

    forward = make_packet(
        1.0,
        "10.0.0.1",
        50000,
        "10.0.0.2",
        443,
        length=60,
    )
    reverse = make_packet(
        2.0,
        "10.0.0.2",
        443,
        "10.0.0.1",
        50000,
        length=100,
    )

    flow, first_created = table.process(forward)
    same_flow, second_created = table.process(reverse)

    assert first_created is True
    assert second_created is False
    assert flow is same_flow
    assert table.flows_created == 1
    assert len(table.active) == 1

    assert flow.total_packets == 2
    assert flow.total_bytes == 160
    assert flow.packets_a_to_b == 1
    assert flow.packets_b_to_a == 1
    assert flow.bytes_a_to_b == 60
    assert flow.bytes_b_to_a == 100
    assert flow.start_timestamp == 1.0
    assert flow.last_timestamp == 2.0
    assert flow.duration == 1.0


def test_protocol_and_ports_separate_flows() -> None:
    table = FlowTable()

    table.process(
        make_packet(
            1.0,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
            protocol="TCP",
        )
    )
    table.process(
        make_packet(
            2.0,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
            protocol="UDP",
        )
    )
    table.process(
        make_packet(
            3.0,
            "10.0.0.1",
            50001,
            "10.0.0.2",
            443,
            protocol="TCP",
        )
    )

    assert table.flows_created == 3
    assert len(table.active) == 3

def test_running_statistics_match_known_values() -> None:
    statistics = RunningStats()

    for value in [2, 4, 4, 4, 5, 5, 7, 9]:
        statistics.update(float(value))

    assert statistics.count == 8
    assert isclose(statistics.mean, 5.0)
    assert isclose(statistics.variance, 4.0)
    assert isclose(statistics.standard_deviation, 2.0)


def test_completed_flow_contains_streaming_statistics() -> None:
    table = FlowTable()

    packets = [
        make_packet(
            1.0,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
            length=100,
            tcp_flags=0x02,
        ),
        make_packet(
            1.5,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
            length=200,
            tcp_flags=0x10,
        ),
        make_packet(
            2.5,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
            length=300,
            tcp_flags=0x05,
        ),
    ]

    flow = None
    for packet in packets:
        flow, _ = table.process(packet)

    assert flow is not None
    completed = flow.complete()

    assert completed.total_packets == 3
    assert completed.total_bytes == 600
    assert completed.minimum_packet_size == 100
    assert completed.maximum_packet_size == 300
    assert isclose(completed.mean_packet_size, 200.0)
    assert isclose(
        completed.packet_size_variance,
        20000.0 / 3.0,
    )
    assert isclose(
        completed.packet_size_standard_deviation,
        (20000.0 / 3.0) ** 0.5,
    )

    assert completed.inter_arrival_count == 2
    assert isclose(completed.mean_inter_arrival, 0.75)
    assert isclose(completed.inter_arrival_variance, 0.0625)
    assert isclose(
        completed.inter_arrival_standard_deviation,
        0.25,
    )

    assert completed.syn_count == 1
    assert completed.fin_count == 1
    assert completed.rst_count == 1
    assert completed.duration == 1.5
    assert completed.initiator.ip == "10.0.0.1"
    assert completed.responder.ip == "10.0.0.2"

def test_flow_expires_at_timeout_boundary() -> None:
    table = FlowTable(timeout=60.0)

    old_packet = make_packet(
        0.0,
        "10.0.0.1",
        50000,
        "10.0.0.2",
        443,
    )
    recent_packet = make_packet(
        30.0,
        "10.0.0.3",
        50001,
        "10.0.0.4",
        443,
    )

    table.process(old_packet)
    table.process(recent_packet)

    completed = table.expire(60.0)

    assert len(completed) == 1
    assert completed[0].key == canonical_flow(old_packet)[0]
    assert len(table.active) == 1
    assert table.flows_completed == 1

    _, created = table.process(
        make_packet(
            61.0,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
        )
    )

    assert created is True
    assert table.flows_created == 3


def test_recently_updated_flow_moves_to_end() -> None:
    table = FlowTable(timeout=60.0)

    first = make_packet(
        0.0,
        "10.0.0.1",
        50000,
        "10.0.0.2",
        443,
    )
    second = make_packet(
        10.0,
        "10.0.0.3",
        50001,
        "10.0.0.4",
        443,
    )
    first_reply = make_packet(
        20.0,
        "10.0.0.2",
        443,
        "10.0.0.1",
        50000,
    )

    table.process(first)
    table.process(second)
    table.process(first_reply)

    completed = table.expire(70.0)

    assert len(completed) == 1
    assert completed[0].key == canonical_flow(second)[0]
    assert canonical_flow(first)[0] in table.active


def test_flush_completes_every_active_flow() -> None:
    table = FlowTable()

    table.process(
        make_packet(
            1.0,
            "10.0.0.1",
            50000,
            "10.0.0.2",
            443,
        )
    )
    table.process(
        make_packet(
            2.0,
            "10.0.0.3",
            50001,
            "10.0.0.4",
            53,
            protocol="UDP",
        )
    )

    completed = table.flush()

    assert len(completed) == 2
    assert len(table.active) == 0
    assert table.flows_created == 2
    assert table.flows_completed == 2