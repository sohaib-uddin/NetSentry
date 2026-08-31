from dataclasses import dataclass
from pathlib import Path

from .features import FlowFeatures, extract_flow_features
from .flow import FlowTable
from .packet import PacketCounters, iter_packet_records
from .window import HostProfile, RollingHostTracker


@dataclass(slots=True)
class AnalysisResult:
    counters: PacketCounters
    flows: FlowTable
    flow_features: list[FlowFeatures]
    host_profiles: list[HostProfile]


def analyse_capture(
    path: Path,
    flow_timeout: float = 60.0,
    window_seconds: float = 30.0,
) -> AnalysisResult:
    counters = PacketCounters()
    flows = FlowTable(timeout=flow_timeout)
    hosts = RollingHostTracker(
        window_seconds=window_seconds
    )
    flow_features: list[FlowFeatures] = []

    for packet in iter_packet_records(path, counters):
        for completed in flows.expire(packet.timestamp):
            flow_features.append(
                extract_flow_features(completed)
            )

        _, new_connection = flows.process(packet)
        hosts.process(packet, new_connection)

    for completed in flows.flush():
        flow_features.append(
            extract_flow_features(completed)
        )

    return AnalysisResult(
        counters=counters,
        flows=flows,
        flow_features=flow_features,
        host_profiles=hosts.profiles(),
    )