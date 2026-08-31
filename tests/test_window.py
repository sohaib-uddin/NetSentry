from netsentry.packet import PacketRecord
from netsentry.window import (
    HostWindowState,
    RollingHostTracker,
)


def make_packet(
    timestamp: float,
    source: str,
    destination: str,
    destination_port: int,
    length: int = 100,
    tcp_flags: int = 0,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=source,
        dst_ip=destination,
        src_port=50000,
        dst_port=destination_port,
        protocol="TCP",
        length=length,
        tcp_flags=tcp_flags,
    )


def test_events_expire_at_window_boundary() -> None:
    state = HostWindowState(
        source_ip="10.0.0.1",
        window_seconds=10.0,
    )

    state.add(
        make_packet(
            0.0,
            "10.0.0.1",
            "192.0.2.1",
            80,
            length=100,
            tcp_flags=0x02,
        ),
        new_connection=True,
    )
    state.add(
        make_packet(
            5.0,
            "10.0.0.1",
            "192.0.2.1",
            80,
            length=200,
        ),
        new_connection=False,
    )
    profile = state.add(
        make_packet(
            10.0,
            "10.0.0.1",
            "192.0.2.2",
            443,
            length=300,
        ),
        new_connection=True,
    )

    assert profile.connections == 1
    assert profile.packets == 2
    assert profile.bytes == 500
    assert profile.syn_packets == 0
    assert profile.unique_destination_ips == 2
    assert profile.unique_destination_ports == 2


def test_tracker_retains_peak_after_state_expires() -> None:
    tracker = RollingHostTracker(window_seconds=10.0)

    for offset, port in enumerate([80, 81, 82]):
        tracker.process(
            make_packet(
                float(offset),
                "10.0.0.1",
                "192.0.2.1",
                port,
                tcp_flags=0x02,
            ),
            new_connection=True,
        )

    tracker.process(
        make_packet(
            13.0,
            "10.0.0.2",
            "192.0.2.10",
            443,
        ),
        new_connection=True,
    )

    first_host_profiles = [
        profile
        for profile in tracker.profiles()
        if profile.source_ip == "10.0.0.1"
    ]

    assert "10.0.0.1" not in tracker.states
    assert "10.0.0.2" in tracker.states
    assert max(
        profile.unique_destination_ports
        for profile in first_host_profiles
    ) == 3
    assert max(
        profile.connections
        for profile in first_host_profiles
    ) == 3
    assert max(
        profile.syn_packets
        for profile in first_host_profiles
    ) == 3