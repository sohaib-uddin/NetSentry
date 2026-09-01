import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter

from .detection import (
    DetectedAnomaly,
    DetectorName,
    run_detector,
)
from .explain import ExplainedAnomaly, explain_anomalies
from .features import FlowFeatures, extract_flow_features
from .flow import FlowTable
from .packet import PacketCounters, iter_packet_records
from .window import HostProfile, RollingHostTracker


@dataclass(frozen=True, slots=True)
class RunMetrics:
    processing_seconds: float
    packets_per_second: float
    peak_memory_bytes: int


@dataclass(slots=True)
class AnalysisResult:
    counters: PacketCounters
    flows: FlowTable
    flow_features: list[FlowFeatures]
    host_profiles: list[HostProfile]
    anomalies: list[DetectedAnomaly]
    alerts: list[ExplainedAnomaly]
    detector: DetectorName
    metrics: RunMetrics


def analyse_capture(
    path: Path,
    flow_timeout: float = 60.0,
    window_seconds: float = 30.0,
    z_threshold: float = 3.0,
    detector: DetectorName = "zscore",
) -> AnalysisResult:
    tracemalloc.start()
    started = perf_counter()

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

    host_profiles = hosts.profiles()
    anomalies = run_detector(
        detector,
        flow_features,
        host_profiles,
        threshold=z_threshold,
    )
    alerts = explain_anomalies(anomalies)

    processing_seconds = perf_counter() - started
    _, peak_memory_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    packets_per_second = (
        counters.encountered / processing_seconds
        if processing_seconds > 0.0
        else 0.0
    )
    metrics = RunMetrics(
        processing_seconds=processing_seconds,
        packets_per_second=packets_per_second,
        peak_memory_bytes=peak_memory_bytes,
    )

    return AnalysisResult(
        counters=counters,
        flows=flows,
        flow_features=flow_features,
        host_profiles=host_profiles,
        anomalies=anomalies,
        alerts=alerts,
        detector=detector,
        metrics=metrics,
    )