from collections import OrderedDict
from dataclasses import dataclass, field
from math import isfinite, sqrt
from typing import Literal

from .packet import PacketRecord, Protocol


Direction = Literal["A_TO_B", "B_TO_A"]

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04


@dataclass(slots=True)
class RunningStats:
    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta_from_new_mean = value - self.mean
        self.m2 += delta * delta_from_new_mean

    @property
    def variance(self) -> float:
        if self.count == 0:
            return 0.0
        return self.m2 / self.count

    @property
    def standard_deviation(self) -> float:
        return sqrt(self.variance)


@dataclass(frozen=True, order=True, slots=True)
class Endpoint:
    ip: str
    port: int

    def __str__(self) -> str:
        return f"{self.ip}:{self.port}"


@dataclass(frozen=True, slots=True)
class FlowKey:
    protocol: Protocol
    endpoint_a: Endpoint
    endpoint_b: Endpoint

    def __str__(self) -> str:
        return (
            f"{self.endpoint_a} <-> {self.endpoint_b} "
            f"({self.protocol})"
        )


def canonical_flow(
    packet: PacketRecord,
) -> tuple[FlowKey, Direction]:
    source = Endpoint(packet.src_ip, packet.src_port)
    destination = Endpoint(packet.dst_ip, packet.dst_port)

    if source <= destination:
        key = FlowKey(packet.protocol, source, destination)
        return key, "A_TO_B"

    key = FlowKey(packet.protocol, destination, source)
    return key, "B_TO_A"


@dataclass(frozen=True, slots=True)
class CompletedFlow:
    key: FlowKey
    initiator: Endpoint
    start_timestamp: float
    last_timestamp: float
    total_packets: int
    total_bytes: int
    packets_a_to_b: int
    packets_b_to_a: int
    bytes_a_to_b: int
    bytes_b_to_a: int
    minimum_packet_size: int
    maximum_packet_size: int
    mean_packet_size: float
    packet_size_variance: float
    inter_arrival_count: int
    mean_inter_arrival: float
    inter_arrival_variance: float
    syn_count: int
    fin_count: int
    rst_count: int

    @property
    def duration(self) -> float:
        return max(0.0, self.last_timestamp - self.start_timestamp)

    @property
    def packet_size_standard_deviation(self) -> float:
        return sqrt(self.packet_size_variance)

    @property
    def inter_arrival_standard_deviation(self) -> float:
        return sqrt(self.inter_arrival_variance)

    @property
    def responder(self) -> Endpoint:
        if self.initiator == self.key.endpoint_a:
            return self.key.endpoint_b
        return self.key.endpoint_a


@dataclass(slots=True)
class FlowState:
    key: FlowKey
    initiator: Endpoint
    start_timestamp: float
    last_timestamp: float
    total_packets: int = 0
    total_bytes: int = 0
    packets_a_to_b: int = 0
    packets_b_to_a: int = 0
    bytes_a_to_b: int = 0
    bytes_b_to_a: int = 0
    minimum_packet_size: int | None = None
    maximum_packet_size: int | None = None
    packet_sizes: RunningStats = field(
        default_factory=RunningStats
    )
    inter_arrivals: RunningStats = field(
        default_factory=RunningStats
    )
    syn_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_timestamp - self.start_timestamp)

    def update(
        self,
        packet: PacketRecord,
        direction: Direction,
    ) -> None:
        if self.total_packets:
            interval = packet.timestamp - self.last_timestamp
            if interval >= 0.0:
                self.inter_arrivals.update(interval)

        self.start_timestamp = min(
            self.start_timestamp,
            packet.timestamp,
        )
        self.last_timestamp = max(
            self.last_timestamp,
            packet.timestamp,
        )
        self.total_packets += 1
        self.total_bytes += packet.length
        self.packet_sizes.update(float(packet.length))

        if (
            self.minimum_packet_size is None
            or packet.length < self.minimum_packet_size
        ):
            self.minimum_packet_size = packet.length

        if (
            self.maximum_packet_size is None
            or packet.length > self.maximum_packet_size
        ):
            self.maximum_packet_size = packet.length

        if direction == "A_TO_B":
            self.packets_a_to_b += 1
            self.bytes_a_to_b += packet.length
        else:
            self.packets_b_to_a += 1
            self.bytes_b_to_a += packet.length

        if packet.protocol == "TCP":
            self._update_tcp_flags(packet.tcp_flags)

    def _update_tcp_flags(self, flags: int) -> None:
        if flags & TCP_SYN:
            self.syn_count += 1
        if flags & TCP_FIN:
            self.fin_count += 1
        if flags & TCP_RST:
            self.rst_count += 1

    def complete(self) -> CompletedFlow:
        return CompletedFlow(
            key=self.key,
            initiator=self.initiator,
            start_timestamp=self.start_timestamp,
            last_timestamp=self.last_timestamp,
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            packets_a_to_b=self.packets_a_to_b,
            packets_b_to_a=self.packets_b_to_a,
            bytes_a_to_b=self.bytes_a_to_b,
            bytes_b_to_a=self.bytes_b_to_a,
            minimum_packet_size=(
                self.minimum_packet_size
                if self.minimum_packet_size is not None
                else 0
            ),
            maximum_packet_size=(
                self.maximum_packet_size
                if self.maximum_packet_size is not None
                else 0
            ),
            mean_packet_size=self.packet_sizes.mean,
            packet_size_variance=self.packet_sizes.variance,
            inter_arrival_count=self.inter_arrivals.count,
            mean_inter_arrival=self.inter_arrivals.mean,
            inter_arrival_variance=(
                self.inter_arrivals.variance
            ),
            syn_count=self.syn_count,
            fin_count=self.fin_count,
            rst_count=self.rst_count,
        )


@dataclass(slots=True)
class FlowTable:
    timeout: float = 60.0
    active: OrderedDict[FlowKey, FlowState] = field(
        default_factory=OrderedDict
    )
    flows_created: int = 0
    flows_completed: int = 0

    def __post_init__(self) -> None:
        if not isfinite(self.timeout) or self.timeout <= 0.0:
            raise ValueError("flow timeout must be positive and finite")

    def process(
        self,
        packet: PacketRecord,
    ) -> tuple[FlowState, bool]:
        key, direction = canonical_flow(packet)
        flow = self.active.get(key)
        created = flow is None

        if flow is None:
            initiator = (
                key.endpoint_a
                if direction == "A_TO_B"
                else key.endpoint_b
            )
            flow = FlowState(
                key=key,
                initiator=initiator,
                start_timestamp=packet.timestamp,
                last_timestamp=packet.timestamp,
            )
            self.active[key] = flow
            self.flows_created += 1

        flow.update(packet, direction)
        self.active.move_to_end(key)
        return flow, created

    def expire(self, timestamp: float) -> list[CompletedFlow]:
        completed: list[CompletedFlow] = []

        while self.active:
            oldest = next(iter(self.active.values()))
            inactivity = timestamp - oldest.last_timestamp

            if inactivity < self.timeout:
                break

            _, flow = self.active.popitem(last=False)
            completed.append(flow.complete())
            self.flows_completed += 1

        return completed

    def flush(self) -> list[CompletedFlow]:
        completed = [
            flow.complete()
            for flow in self.active.values()
        ]
        self.flows_completed += len(completed)
        self.active.clear()
        return completed