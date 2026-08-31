from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite

import numpy as np
from numpy.typing import NDArray

from .flow import CompletedFlow, Endpoint, FlowKey


FEATURE_NAMES = (
    "duration",
    "total_packets",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "mean_packet_size",
    "packet_size_standard_deviation",
    "mean_inter_arrival",
    "inter_arrival_standard_deviation",
    "directional_packet_ratio",
    "directional_byte_ratio",
    "syn_count",
    "fin_count",
    "rst_count",
)


@dataclass(frozen=True, slots=True)
class FlowFeatures:
    key: FlowKey
    initiator: Endpoint
    duration: float
    total_packets: int
    total_bytes: int
    packet_rate: float
    byte_rate: float
    mean_packet_size: float
    packet_size_standard_deviation: float
    mean_inter_arrival: float
    inter_arrival_standard_deviation: float
    directional_packet_ratio: float
    directional_byte_ratio: float
    syn_count: int
    fin_count: int
    rst_count: int

    def vector(self) -> tuple[float, ...]:
        return (
            self.duration,
            float(self.total_packets),
            float(self.total_bytes),
            self.packet_rate,
            self.byte_rate,
            self.mean_packet_size,
            self.packet_size_standard_deviation,
            self.mean_inter_arrival,
            self.inter_arrival_standard_deviation,
            self.directional_packet_ratio,
            self.directional_byte_ratio,
            float(self.syn_count),
            float(self.fin_count),
            float(self.rst_count),
        )


def finite_or_zero(value: float) -> float:
    if isfinite(value):
        return value
    return 0.0


def safe_rate(value: int, duration: float) -> float:
    if duration <= 0.0:
        return 0.0
    return finite_or_zero(value / duration)


def safe_ratio(value: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return finite_or_zero(value / total)


def extract_flow_features(
    flow: CompletedFlow,
) -> FlowFeatures:
    duration = finite_or_zero(flow.duration)

    return FlowFeatures(
        key=flow.key,
        initiator=flow.initiator,
        duration=duration,
        total_packets=flow.total_packets,
        total_bytes=flow.total_bytes,
        packet_rate=safe_rate(
            flow.total_packets,
            duration,
        ),
        byte_rate=safe_rate(
            flow.total_bytes,
            duration,
        ),
        mean_packet_size=finite_or_zero(
            flow.mean_packet_size
        ),
        packet_size_standard_deviation=finite_or_zero(
            flow.packet_size_standard_deviation
        ),
        mean_inter_arrival=finite_or_zero(
            flow.mean_inter_arrival
        ),
        inter_arrival_standard_deviation=finite_or_zero(
            flow.inter_arrival_standard_deviation
        ),
        directional_packet_ratio=safe_ratio(
            flow.packets_a_to_b,
            flow.total_packets,
        ),
        directional_byte_ratio=safe_ratio(
            flow.bytes_a_to_b,
            flow.total_bytes,
        ),
        syn_count=flow.syn_count,
        fin_count=flow.fin_count,
        rst_count=flow.rst_count,
    )


def feature_matrix(
    records: Sequence[FlowFeatures],
) -> NDArray[np.float64]:
    if not records:
        return np.empty(
            (0, len(FEATURE_NAMES)),
            dtype=np.float64,
        )

    matrix = np.asarray(
        [record.vector() for record in records],
        dtype=np.float64,
    )
    return np.nan_to_num(
        matrix,
        copy=False,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )