from collections.abc import Sequence
from dataclasses import dataclass

from .detection import (
    DetectedAnomaly,
    EntityKind,
    FeatureRecord,
)
from .features import FEATURE_NAMES, FlowFeatures
from .window import HOST_FEATURE_NAMES, HostProfile


@dataclass(frozen=True, slots=True)
class ExplainedAnomaly:
    kind: EntityKind
    record: FeatureRecord
    score: float
    max_zscore: float
    category: str
    reason: str
    contributions: tuple[tuple[str, float], ...]
    important_values: tuple[tuple[str, float], ...]


def explain_anomalies(
    anomalies: Sequence[DetectedAnomaly],
) -> list[ExplainedAnomaly]:
    return [
        explain_anomaly(anomaly)
        for anomaly in anomalies
    ]


def explain_anomaly(
    anomaly: DetectedAnomaly,
) -> ExplainedAnomaly:
    if isinstance(anomaly.record, HostProfile):
        category, reason, values = _explain_host(
            anomaly,
            anomaly.record,
        )
    else:
        category, reason, values = _explain_flow(
            anomaly,
            anomaly.record,
        )

    return ExplainedAnomaly(
        kind=anomaly.kind,
        record=anomaly.record,
        score=anomaly.score,
        max_zscore=anomaly.max_zscore,
        category=category,
        reason=reason,
        contributions=anomaly.contributions,
        important_values=values,
    )


def _explain_host(
    anomaly: DetectedAnomaly,
    profile: HostProfile,
) -> tuple[str, str, tuple[tuple[str, float], ...]]:
    connections = max(profile.connections, 1)
    port_ratio = (
        profile.unique_destination_ports
        / connections
    )
    host_ratio = (
        profile.unique_destination_ips
        / connections
    )
    syn_ratio = profile.syn_packets / connections

    if (
        profile.connections >= 10
        and profile.unique_destination_ports >= 10
        and port_ratio >= 0.7
    ):
        return (
            "Possible port scan",
            (
                "unusually high destination-port diversity "
                "across recent connections"
            ),
            (
                ("connections", float(profile.connections)),
                (
                    "unique_destination_ports",
                    float(profile.unique_destination_ports),
                ),
                ("syn_packets", float(profile.syn_packets)),
            ),
        )

    if (
        profile.connections >= 10
        and profile.unique_destination_ips >= 10
        and host_ratio >= 0.7
    ):
        return (
            "Possible host sweep",
            (
                "unusually high destination-host diversity "
                "across recent connections"
            ),
            (
                ("connections", float(profile.connections)),
                (
                    "unique_destination_ips",
                    float(profile.unique_destination_ips),
                ),
                ("syn_packets", float(profile.syn_packets)),
            ),
        )

    if _has_positive_contribution(
        anomaly,
        {"bytes", "packets"},
    ):
        return (
            "Traffic-volume anomaly",
            "recent traffic volume is significantly above its baseline",
            (
                ("bytes", float(profile.bytes)),
                ("packets", float(profile.packets)),
                ("connections", float(profile.connections)),
            ),
        )

    if (
        profile.syn_packets >= 5
        and syn_ratio >= 0.8
    ):
        return (
            "SYN-heavy activity",
            "a high proportion of recent connections contain SYN packets",
            (
                ("syn_packets", float(profile.syn_packets)),
                ("connections", float(profile.connections)),
                ("syn_ratio", syn_ratio),
            ),
        )

    return (
        "Unusual host behaviour",
        "recent host behaviour differs significantly from its baseline",
        _contributor_values(anomaly),
    )


def _explain_flow(
    anomaly: DetectedAnomaly,
    flow: FlowFeatures,
) -> tuple[str, str, tuple[tuple[str, float], ...]]:
    if _has_positive_contribution(
        anomaly,
        {
            "total_packets",
            "total_bytes",
            "packet_rate",
            "byte_rate",
        },
    ):
        return (
            "Traffic-volume anomaly",
            "flow volume or transfer rate is significantly above baseline",
            (
                ("total_bytes", float(flow.total_bytes)),
                ("byte_rate", flow.byte_rate),
                ("packet_rate", flow.packet_rate),
            ),
        )

    if (
        flow.syn_count >= 3
        and _has_positive_contribution(
            anomaly,
            {"syn_count"},
        )
    ):
        return (
            "SYN-heavy activity",
            "the flow contains unusually high SYN activity",
            (
                ("syn_count", float(flow.syn_count)),
                (
                    "total_packets",
                    float(flow.total_packets),
                ),
            ),
        )

    return (
        "Unusual flow",
        "flow characteristics differ significantly from their baseline",
        _contributor_values(anomaly),
    )


def _has_positive_contribution(
    anomaly: DetectedAnomaly,
    names: set[str],
    minimum_zscore: float = 2.0,
) -> bool:
    return any(
        name in names and zscore >= minimum_zscore
        for name, zscore in anomaly.contributions
    )


def _contributor_values(
    anomaly: DetectedAnomaly,
) -> tuple[tuple[str, float], ...]:
    feature_names = (
        HOST_FEATURE_NAMES
        if isinstance(anomaly.record, HostProfile)
        else FEATURE_NAMES
    )
    values = dict(
        zip(
            feature_names,
            anomaly.record.vector(),
            strict=True,
        )
    )

    return tuple(
        (name, float(values[name]))
        for name, _ in anomaly.contributions[:3]
    )