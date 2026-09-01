import json
from pathlib import Path
from typing import Any

from .engine import AnalysisResult
from .explain import ExplainedAnomaly
from .features import FlowFeatures


def format_bytes(value: int) -> str:
    size = float(value)

    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size) < 1024.0 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024.0

    return f"{size:.1f} TB"


def print_ranked_alerts(
    alerts: list[ExplainedAnomaly],
    top: int,
) -> None:
    print()
    print("Top anomalies")
    print("-" * 60)

    if not alerts:
        print("No anomalies exceeded the detector threshold.")
        return

    for position, alert in enumerate(
        alerts[:top],
        start=1,
    ):
        record = alert.record

        if isinstance(record, FlowFeatures):
            label = "Flow"
            identity = str(record.key)
        else:
            label = "Host"
            identity = record.source_ip

        print(f"{position}. Score: {alert.score:.3f}")
        print(f"   {label}: {identity}")
        print(f"   Type: {alert.category}")
        print(f"   Reason: {alert.reason}")

        if alert.important_values:
            values = ", ".join(
                (
                    f"{name}="
                    f"{_format_value(name, value)}"
                )
                for name, value in alert.important_values
            )
            print(f"   Values: {values}")

        print()


def build_payload(
    capture: Path,
    result: AnalysisResult,
    *,
    flow_timeout: float,
    window_seconds: float,
    z_threshold: float,
    top: int,
) -> dict[str, Any]:
    counters = result.counters

    return {
        "metadata": {
            "file": str(capture),
            "packets_encountered": counters.encountered,
            "supported_packets": counters.supported,
            "unsupported_packets": counters.unsupported,
            "tcp_packets": counters.tcp_packets,
            "udp_packets": counters.udp_packets,
            "supported_ipv4_bytes": (
                counters.bytes_processed
            ),
            "flows_reconstructed": (
                result.flows.flows_created
            ),
            "flows_completed": (
                result.flows.flows_completed
            ),
            "host_profiles": len(
                {
                    profile.source_ip
                    for profile in result.host_profiles
                }
            ),
            "processing_seconds": (
                result.metrics.processing_seconds
            ),
            "packets_per_second": (
                result.metrics.packets_per_second
            ),
            "peak_memory_bytes": (
                result.metrics.peak_memory_bytes
            ),
        },
        "configuration": {
            "detector": result.detector,
            "flow_timeout_seconds": flow_timeout,
            "window_seconds": window_seconds,
            "z_threshold": z_threshold,
            "top": top,
        },
        "anomalies": [
            _alert_payload(alert)
            for alert in result.alerts[:top]
        ],
    }


def write_json(
    path: Path,
    capture: Path,
    result: AnalysisResult,
    *,
    flow_timeout: float,
    window_seconds: float,
    z_threshold: float,
    top: int,
) -> None:
    payload = build_payload(
        capture,
        result,
        flow_timeout=flow_timeout,
        window_seconds=window_seconds,
        z_threshold=z_threshold,
        top=top,
    )

    with path.open("w", encoding="utf-8") as output:
        json.dump(payload, output, indent=2)
        output.write("\n")


def _alert_payload(
    alert: ExplainedAnomaly,
) -> dict[str, Any]:
    record = alert.record

    if isinstance(record, FlowFeatures):
        entity = {
            "kind": "flow",
            "identity": str(record.key),
            "initiator": str(record.initiator),
        }
    else:
        entity = {
            "kind": "host",
            "identity": record.source_ip,
            "window_timestamp": record.timestamp,
        }

    return {
        "score": alert.score,
        "max_zscore": alert.max_zscore,
        "category": alert.category,
        "reason": alert.reason,
        "entity": entity,
        "contributions": [
            {
                "feature": name,
                "zscore": zscore,
            }
            for name, zscore in alert.contributions
        ],
        "important_values": {
            name: value
            for name, value in alert.important_values
        },
    }


def _format_value(name: str, value: float) -> str:
    if name in {"bytes", "total_bytes"}:
        return format_bytes(int(value))
    if value.is_integer():
        return f"{int(value):,}"
    return f"{value:,.3f}"