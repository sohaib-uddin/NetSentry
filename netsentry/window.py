from collections import Counter, OrderedDict, deque
from dataclasses import dataclass, field
from math import isfinite

from .flow import TCP_SYN
from .packet import PacketRecord


HOST_FEATURE_NAMES = (
    "connections",
    "unique_destination_ips",
    "unique_destination_ports",
    "packets",
    "bytes",
    "syn_packets",
)


@dataclass(frozen=True, slots=True)
class HostEvent:
    timestamp: float
    destination_ip: str
    destination_port: int
    length: int
    syn: int
    new_connection: int


@dataclass(frozen=True, slots=True)
class HostProfile:
    source_ip: str
    timestamp: float
    window_seconds: float
    connections: int
    unique_destination_ips: int
    unique_destination_ports: int
    packets: int
    bytes: int
    syn_packets: int

    def vector(self) -> tuple[float, ...]:
        return (
            float(self.connections),
            float(self.unique_destination_ips),
            float(self.unique_destination_ports),
            float(self.packets),
            float(self.bytes),
            float(self.syn_packets),
        )


@dataclass(slots=True)
class HostWindowState:
    source_ip: str
    window_seconds: float
    events: deque[HostEvent] = field(
        default_factory=deque
    )
    destination_ips: Counter[str] = field(
        default_factory=Counter
    )
    destination_ports: Counter[int] = field(
        default_factory=Counter
    )
    connections: int = 0
    packets: int = 0
    bytes: int = 0
    syn_packets: int = 0

    @property
    def last_timestamp(self) -> float:
        if not self.events:
            return 0.0
        return self.events[-1].timestamp

    def add(
        self,
        packet: PacketRecord,
        new_connection: bool,
    ) -> HostProfile:
        self._expire(packet.timestamp)

        syn = int(
            packet.protocol == "TCP"
            and bool(packet.tcp_flags & TCP_SYN)
        )
        event = HostEvent(
            timestamp=packet.timestamp,
            destination_ip=packet.dst_ip,
            destination_port=packet.dst_port,
            length=packet.length,
            syn=syn,
            new_connection=int(new_connection),
        )

        self.events.append(event)
        self.destination_ips[event.destination_ip] += 1
        self.destination_ports[event.destination_port] += 1
        self.connections += event.new_connection
        self.packets += 1
        self.bytes += event.length
        self.syn_packets += event.syn

        return self.profile(packet.timestamp)

    def profile(self, timestamp: float) -> HostProfile:
        return HostProfile(
            source_ip=self.source_ip,
            timestamp=timestamp,
            window_seconds=self.window_seconds,
            connections=self.connections,
            unique_destination_ips=len(
                self.destination_ips
            ),
            unique_destination_ports=len(
                self.destination_ports
            ),
            packets=self.packets,
            bytes=self.bytes,
            syn_packets=self.syn_packets,
        )

    def _expire(self, timestamp: float) -> None:
        cutoff = timestamp - self.window_seconds

        while (
            self.events
            and self.events[0].timestamp <= cutoff
        ):
            event = self.events.popleft()
            self.connections -= event.new_connection
            self.packets -= 1
            self.bytes -= event.length
            self.syn_packets -= event.syn

            self._decrement(
                self.destination_ips,
                event.destination_ip,
            )
            self._decrement(
                self.destination_ports,
                event.destination_port,
            )

    @staticmethod
    def _decrement(
        counter: Counter,
        key: str | int,
    ) -> None:
        counter[key] -= 1
        if counter[key] <= 0:
            del counter[key]


@dataclass(slots=True)
class RollingHostTracker:
    window_seconds: float = 30.0
    states: OrderedDict[str, HostWindowState] = field(
        default_factory=OrderedDict
    )
    peaks: dict[str, dict[str, HostProfile]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        if (
            not isfinite(self.window_seconds)
            or self.window_seconds <= 0.0
        ):
            raise ValueError(
                "host window must be positive and finite"
            )

    def process(
        self,
        packet: PacketRecord,
        new_connection: bool,
    ) -> HostProfile:
        self._drop_inactive(packet.timestamp)

        state = self.states.get(packet.src_ip)
        if state is None:
            state = HostWindowState(
                source_ip=packet.src_ip,
                window_seconds=self.window_seconds,
            )
            self.states[packet.src_ip] = state

        profile = state.add(packet, new_connection)
        self.states.move_to_end(packet.src_ip)
        self._record_peaks(profile)
        return profile

    def profiles(self) -> list[HostProfile]:
        profiles: list[HostProfile] = []
        seen: set[tuple] = set()

        for host_peaks in self.peaks.values():
            for profile in host_peaks.values():
                identity = (
                    profile.source_ip,
                    profile.connections,
                    profile.unique_destination_ips,
                    profile.unique_destination_ports,
                    profile.packets,
                    profile.bytes,
                    profile.syn_packets,
                )
                if identity not in seen:
                    seen.add(identity)
                    profiles.append(profile)

        profiles.sort(
            key=lambda profile: (
                profile.source_ip,
                profile.timestamp,
            )
        )
        return profiles

    def _drop_inactive(self, timestamp: float) -> None:
        cutoff = timestamp - self.window_seconds

        while self.states:
            oldest = next(iter(self.states.values()))
            if oldest.last_timestamp > cutoff:
                break
            self.states.popitem(last=False)

    def _record_peaks(self, profile: HostProfile) -> None:
        host_peaks = self.peaks.setdefault(
            profile.source_ip,
            {}
        )

        for name in ("ports", "hosts", "volume", "syn"):
            current = host_peaks.get(name)
            if (
                current is None
                or self._rank(name, profile)
                > self._rank(name, current)
            ):
                host_peaks[name] = profile

    @staticmethod
    def _rank(
        name: str,
        profile: HostProfile,
    ) -> tuple[int, int, int]:
        if name == "ports":
            return (
                profile.unique_destination_ports,
                profile.connections,
                profile.syn_packets,
            )
        if name == "hosts":
            return (
                profile.unique_destination_ips,
                profile.connections,
                profile.packets,
            )
        if name == "volume":
            return (
                profile.bytes,
                profile.packets,
                profile.connections,
            )
        return (
            profile.syn_packets,
            profile.connections,
            profile.unique_destination_ports,
        )