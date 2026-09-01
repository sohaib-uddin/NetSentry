from netsentry.detection import (
    detect_anomalies,
    detect_isolation_anomalies,
)
from netsentry.features import FlowFeatures
from netsentry.flow import Endpoint, FlowKey
from netsentry.window import HostProfile


def make_flow(
    index: int,
    total_bytes: int,
) -> FlowFeatures:
    endpoint_a = Endpoint(
        ip="10.0.0.1",
        port=50000 + index,
    )
    endpoint_b = Endpoint(
        ip="10.0.0.2",
        port=443,
    )

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
        packet_rate=1.0,
        byte_rate=total_bytes / 10.0,
        mean_packet_size=total_bytes / 10.0,
        packet_size_standard_deviation=5.0,
        mean_inter_arrival=1.0,
        inter_arrival_standard_deviation=0.1,
        directional_packet_ratio=0.5,
        directional_byte_ratio=0.5,
        syn_count=1,
        fin_count=1,
        rst_count=0,
    )


def make_host(
    index: int,
    connections: int,
    unique_ports: int,
    syn_packets: int,
) -> HostProfile:
    return HostProfile(
        source_ip=f"10.0.0.{index}",
        timestamp=30.0,
        window_seconds=30.0,
        connections=connections,
        unique_destination_ips=2,
        unique_destination_ports=unique_ports,
        packets=connections * 2,
        bytes=connections * 200,
        syn_packets=syn_packets,
    )


def test_obvious_flow_outlier_is_ranked() -> None:
    normal = [
        make_flow(index, total_bytes=1_000)
        for index in range(20)
    ]
    outlier = make_flow(100, total_bytes=100_000)

    anomalies = detect_anomalies(
        normal + [outlier],
        [],
        threshold=3.0,
    )

    assert len(anomalies) == 1
    assert anomalies[0].kind == "flow"
    assert anomalies[0].record is outlier
    assert anomalies[0].max_zscore >= 3.0
    assert anomalies[0].score > 0.0
    assert any(
        name == "total_bytes"
        for name, _ in anomalies[0].contributions
    )


def test_zero_variance_produces_no_anomalies() -> None:
    identical = [
        make_flow(index, total_bytes=1_000)
        for index in range(20)
    ]

    anomalies = detect_anomalies(
        identical,
        [],
        threshold=3.0,
    )

    assert anomalies == []


def test_host_outlier_uses_separate_baseline() -> None:
    normal_hosts = [
        make_host(
            index=index,
            connections=5,
            unique_ports=2,
            syn_packets=1,
        )
        for index in range(1, 21)
    ]
    outlier = make_host(
        index=100,
        connections=100,
        unique_ports=95,
        syn_packets=90,
    )

    anomalies = detect_anomalies(
        [],
        normal_hosts + [outlier],
        threshold=3.0,
    )

    assert len(anomalies) == 1
    assert anomalies[0].kind == "host"
    assert anomalies[0].record is outlier
    assert anomalies[0].max_zscore >= 3.0
    assert {
        name
        for name, _ in anomalies[0].contributions
    } & {
        "connections",
        "unique_destination_ports",
        "syn_packets",
    }

def test_isolation_forest_detects_obvious_outlier() -> None:
    normal = [
        make_flow(
            index,
            total_bytes=1_000 + (index % 5) * 10,
        )
        for index in range(40)
    ]
    outlier = make_flow(
        100,
        total_bytes=1_000_000,
    )

    anomalies = detect_isolation_anomalies(
        normal + [outlier],
        [],
    )

    assert any(
        anomaly.record is outlier
        for anomaly in anomalies
    )
    assert all(
        first.score >= second.score
        for first, second in zip(
            anomalies,
            anomalies[1:],
            strict=False,
        )
    )


def test_isolation_forest_skips_tiny_cohort() -> None:
    records = [
        make_flow(index, total_bytes=1_000)
        for index in range(4)
    ]

    anomalies = detect_isolation_anomalies(
        records,
        [],
    )

    assert anomalies == []