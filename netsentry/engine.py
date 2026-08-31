from dataclasses import dataclass
from pathlib import Path

from .flow import CompletedFlow, FlowTable
from .packet import PacketCounters, iter_packet_records


@dataclass(slots=True)
class AnalysisResult:
    counters: PacketCounters
    flows: FlowTable
    completed_flows: list[CompletedFlow]


def analyse_capture(
    path: Path,
    flow_timeout: float = 60.0,
) -> AnalysisResult:
    counters = PacketCounters()
    flows = FlowTable(timeout=flow_timeout)
    completed_flows: list[CompletedFlow] = []

    for packet in iter_packet_records(path, counters):
        completed_flows.extend(
            flows.expire(packet.timestamp)
        )
        flows.process(packet)

    completed_flows.extend(flows.flush())

    return AnalysisResult(
        counters=counters,
        flows=flows,
        completed_flows=completed_flows,
    )