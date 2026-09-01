from netsentry.detection import DetectedAnomaly
from netsentry.explain import explain_anomaly
from netsentry.features import FlowFeatures
from netsentry.flow import Endpoint, FlowKey
from netsentry.window import HostProfile


def make_flow(
    *,
    total_bytes: int = 1_000,
    byte_rate: float = 100.0,
    packet_rate: float = 1.0,
    syn_count: int = 1,
) -> FlowFeatures:
    endpoint_a = Endpoint("10.0.0.1", 50000)
    endpoint_b = Endpoint("10.0.0.2", 443)

    return FlowFeatures(
        key=FlowKey(
            protocol="TCP",
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
        ),
        initiator=endpoint_a,
        duration=10.0,
        total_packets=10,
        total_bytes=total_bytes,
        packet_rate=packet_rate,
        byte_rate=byte_rate,
        mean_packet_size=100.0,
        packet_size_standard_deviation=5.0,
        mean_inter_arrival=1.0,
        inter_arrival_standard_deviation=0.1,
        directional_packet_ratio=0.5,
        directional_byte_ratio=0.5,
        syn_count=syn_count,
        fin_count=1,
        rst_count=0,
    )


def make_host(
    *,
    connections: int,
    unique_ips: int,
    unique_ports: int,
    packets: int,
    bytes_processed: int,
    syn_packets: int,
) -> HostProfile:
    return HostProfile(
        source_ip="10.0.0.10",
        timestamp=30.0,
        window_seconds=30.0,
        connections=connections,
        unique_destination_ips=unique_ips,
        unique_destination_ports=unique_ports,
        packets=packets,
        bytes=bytes_processed,
        syn_packets=syn_packets,
    )


def make_anomaly(
    record: FlowFeatures | HostProfile,
    contributions: tuple[tuple[str, float], ...],
) -> DetectedAnomaly:
    return DetectedAnomaly(
        kind=(
            "host"
            if isinstance(record, HostProfile)
            else "flow"
        ),
        record=record,
        score=4.0,
        max_zscore=5.0,
        contributions=contributions,
    )


def test_possible_port_scan_explanation() -> None:
    host = make_host(
        connections=100,
        unique_ips=2,
        unique_ports=95,
        packets=120,
        bytes_processed=12_000,
        syn_packets=90,
    )

    explained = explain_anomaly(
        make_anomaly(
            host,
            (("unique_destination_ports", 5.0),),
        )
    )

    assert explained.category == "Possible port scan"
    assert "destination-port diversity" in explained.reason


def test_possible_host_sweep_explanation() -> None:
    host = make_host(
        connections=60,
        unique_ips=55,
        unique_ports=1,
        packets=70,
        bytes_processed=7_000,
        syn_packets=40,
    )

    explained = explain_anomaly(
        make_anomaly(
            host,
            (("unique_destination_ips", 5.0),),
        )
    )

    assert explained.category == "Possible host sweep"
    assert "destination-host diversity" in explained.reason


def test_flow_volume_explanation() -> None:
    flow = make_flow(
        total_bytes=1_000_000,
        byte_rate=100_000.0,
        packet_rate=1_000.0,
    )

    explained = explain_anomaly(
        make_anomaly(
            flow,
            (
                ("byte_rate", 5.0),
                ("total_bytes", 4.0),
            ),
        )
    )

    assert explained.category == "Traffic-volume anomaly"
    assert "above baseline" in explained.reason


def test_syn_heavy_host_explanation() -> None:
    host = make_host(
        connections=20,
        unique_ips=1,
        unique_ports=1,
        packets=22,
        bytes_processed=2_200,
        syn_packets=19,
    )

    explained = explain_anomaly(
        make_anomaly(
            host,
            (("syn_packets", 4.0),),
        )
    )

    assert explained.category == "SYN-heavy activity"
    assert dict(explained.important_values)["syn_packets"] == 19


def test_unmatched_flow_uses_fallback() -> None:
    flow = make_flow()

    explained = explain_anomaly(
        make_anomaly(
            flow,
            (("directional_packet_ratio", -4.0),),
        )
    )

    assert explained.category == "Unusual flow"
    assert "differ significantly" in explained.reason