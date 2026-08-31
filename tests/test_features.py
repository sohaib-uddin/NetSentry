from dataclasses import replace
from math import isclose, isfinite

import numpy as np

from netsentry.features import (
    FEATURE_NAMES,
    extract_flow_features,
    feature_matrix,
)
from netsentry.flow import CompletedFlow, FlowTable
from netsentry.packet import PacketRecord


def make_packet(
    timestamp: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    length: int,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
        length=length,
    )


def complete_flow(
    packets: list[PacketRecord],
) -> CompletedFlow:
    table = FlowTable()

    for packet in packets:
        table.process(packet)

    return table.flush()[0]


def test_zero_duration_flow_has_finite_features() -> None:
    completed = complete_flow(
        [
            make_packet(
                5.0,
                "10.0.0.1",
                50000,
                "10.0.0.2",
                443,
                100,
            )
        ]
    )

    features = extract_flow_features(completed)

    assert features.duration == 0.0
    assert features.packet_rate == 0.0
    assert features.byte_rate == 0.0
    assert all(
        isfinite(value)
        for value in features.vector()
    )


def test_rates_and_directional_ratios() -> None:
    completed = complete_flow(
        [
            make_packet(
                0.0,
                "10.0.0.1",
                50000,
                "10.0.0.2",
                443,
                100,
            ),
            make_packet(
                2.0,
                "10.0.0.2",
                443,
                "10.0.0.1",
                50000,
                300,
            ),
        ]
    )

    features = extract_flow_features(completed)

    assert features.duration == 2.0
    assert features.total_packets == 2
    assert features.total_bytes == 400
    assert features.packet_rate == 1.0
    assert features.byte_rate == 200.0
    assert features.directional_packet_ratio == 0.5
    assert features.directional_byte_ratio == 0.25
    assert isclose(features.mean_packet_size, 200.0)
    assert isclose(
        features.packet_size_standard_deviation,
        100.0,
    )
    assert features.mean_inter_arrival == 2.0
    assert (
        features.inter_arrival_standard_deviation
        == 0.0
    )


def test_feature_matrix_shape_and_finite_values() -> None:
    completed = complete_flow(
        [
            make_packet(
                0.0,
                "10.0.0.1",
                50000,
                "10.0.0.2",
                443,
                100,
            )
        ]
    )
    features = extract_flow_features(completed)
    corrupted = replace(
        features,
        byte_rate=float("inf"),
    )

    matrix = feature_matrix([features, corrupted])
    empty = feature_matrix([])

    assert matrix.shape == (2, len(FEATURE_NAMES))
    assert np.isfinite(matrix).all()
    assert (
        matrix[1, FEATURE_NAMES.index("byte_rate")]
        == 0.0
    )
    assert empty.shape == (0, len(FEATURE_NAMES))