import json
from pathlib import Path

from netsentry.engine import AnalysisResult, RunMetrics
from netsentry.explain import ExplainedAnomaly
from netsentry.flow import FlowTable
from netsentry.packet import PacketCounters
from netsentry.report import (
    build_payload,
    print_ranked_alerts,
    write_json,
)
from netsentry.window import HostProfile


def make_result() -> AnalysisResult:
    profile = HostProfile(
        source_ip="10.0.0.10",
        timestamp=30.0,
        window_seconds=30.0,
        connections=100,
        unique_destination_ips=2,
        unique_destination_ports=95,
        packets=120,
        bytes=12_000,
        syn_packets=90,
    )
    alert = ExplainedAnomaly(
        kind="host",
        record=profile,
        score=4.5,
        max_zscore=5.0,
        category="Possible port scan",
        reason="unusually high destination-port diversity",
        contributions=(
            ("unique_destination_ports", 5.0),
        ),
        important_values=(
            ("connections", 100.0),
            ("unique_destination_ports", 95.0),
        ),
    )
    flows = FlowTable()
    flows.flows_created = 10
    flows.flows_completed = 10

    return AnalysisResult(
        counters=PacketCounters(
            encountered=1_000,
            supported=900,
            tcp_packets=800,
            udp_packets=100,
            bytes_processed=100_000,
        ),
        flows=flows,
        flow_features=[],
        host_profiles=[profile],
        anomalies=[],
        alerts=[alert],
        detector="zscore",
        metrics=RunMetrics(
            processing_seconds=2.0,
            packets_per_second=500.0,
            peak_memory_bytes=1_024,
        ),
    )


def test_json_payload_and_export(tmp_path: Path) -> None:
    result = make_result()
    capture = Path("capture.pcap")

    payload = build_payload(
        capture,
        result,
        flow_timeout=60.0,
        window_seconds=30.0,
        z_threshold=3.0,
        top=10,
    )

    assert payload["metadata"]["packets_encountered"] == 1_000
    assert payload["metadata"]["flows_reconstructed"] == 10
    assert payload["configuration"]["detector"] == "zscore"
    assert payload["anomalies"][0]["category"] == (
        "Possible port scan"
    )

    output = tmp_path / "results.json"
    write_json(
        output,
        capture,
        result,
        flow_timeout=60.0,
        window_seconds=30.0,
        z_threshold=3.0,
        top=10,
    )

    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved == payload


def test_terminal_alert_output(capsys) -> None:
    result = make_result()

    print_ranked_alerts(result.alerts, top=10)
    output = capsys.readouterr().out

    assert "Top anomalies" in output
    assert "Possible port scan" in output
    assert "10.0.0.10" in output
    assert "Score: 4.500" in output