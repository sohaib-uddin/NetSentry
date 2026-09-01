from collections.abc import Sequence
from dataclasses import dataclass
from math import isfinite, sqrt
from typing import Literal

import numpy as np
from numpy.typing import NDArray

from .features import FEATURE_NAMES, FlowFeatures
from .flow import RunningStats
from .window import HOST_FEATURE_NAMES, HostProfile


EntityKind = Literal["flow", "host"]
DetectorName = Literal["zscore", "isolation"]
FeatureRecord = FlowFeatures | HostProfile


@dataclass(frozen=True, slots=True)
class DetectedAnomaly:
    kind: EntityKind
    record: FeatureRecord
    score: float
    max_zscore: float
    contributions: tuple[tuple[str, float], ...]


def run_detector(
    detector: DetectorName,
    flow_records: Sequence[FlowFeatures],
    host_records: Sequence[HostProfile],
    threshold: float = 3.0,
) -> list[DetectedAnomaly]:
    if detector == "zscore":
        return detect_anomalies(
            flow_records,
            host_records,
            threshold=threshold,
        )
    if detector == "isolation":
        return detect_isolation_anomalies(
            flow_records,
            host_records,
        )
    raise ValueError(f"unknown detector: {detector}")


def detect_anomalies(
    flow_records: Sequence[FlowFeatures],
    host_records: Sequence[HostProfile],
    threshold: float = 3.0,
) -> list[DetectedAnomaly]:
    if not isfinite(threshold) or threshold <= 0.0:
        raise ValueError(
            "z-score threshold must be positive and finite"
        )

    anomalies = _detect_zscore_group(
        flow_records,
        FEATURE_NAMES,
        "flow",
        threshold,
    )
    anomalies.extend(
        _detect_zscore_group(
            host_records,
            HOST_FEATURE_NAMES,
            "host",
            threshold,
        )
    )
    anomalies.sort(
        key=lambda anomaly: anomaly.score,
        reverse=True,
    )
    return anomalies


def detect_isolation_anomalies(
    flow_records: Sequence[FlowFeatures],
    host_records: Sequence[HostProfile],
) -> list[DetectedAnomaly]:
    anomalies = _detect_isolation_group(
        flow_records,
        FEATURE_NAMES,
        "flow",
    )
    anomalies.extend(
        _detect_isolation_group(
            host_records,
            HOST_FEATURE_NAMES,
            "host",
        )
    )
    anomalies.sort(
        key=lambda anomaly: anomaly.score,
        reverse=True,
    )
    return anomalies


def _detect_zscore_group(
    records: Sequence[FeatureRecord],
    feature_names: Sequence[str],
    kind: EntityKind,
    threshold: float,
) -> list[DetectedAnomaly]:
    if len(records) < 2:
        return []

    matrix = _finite_matrix(records)
    baselines = _fit_baselines(matrix)
    anomalies: list[DetectedAnomaly] = []

    for record, row in zip(records, matrix, strict=True):
        zscores = _calculate_zscores(row, baselines)
        score, maximum, contributions = _summarize_zscores(
            zscores,
            feature_names,
        )

        if maximum < threshold:
            continue

        anomalies.append(
            DetectedAnomaly(
                kind=kind,
                record=record,
                score=score,
                max_zscore=maximum,
                contributions=contributions,
            )
        )

    return anomalies


def _detect_isolation_group(
    records: Sequence[FeatureRecord],
    feature_names: Sequence[str],
    kind: EntityKind,
) -> list[DetectedAnomaly]:
    if len(records) < 8:
        return []

    from sklearn.ensemble import IsolationForest

    matrix = _finite_matrix(records)
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
    )
    labels = model.fit_predict(matrix)
    anomaly_scores = -model.decision_function(matrix)
    baselines = _fit_baselines(matrix)
    anomalies: list[DetectedAnomaly] = []

    for record, row, label, anomaly_score in zip(
        records,
        matrix,
        labels,
        anomaly_scores,
        strict=True,
    ):
        if label != -1:
            continue

        zscores = _calculate_zscores(row, baselines)
        _, maximum, contributions = _summarize_zscores(
            zscores,
            feature_names,
        )
        anomalies.append(
            DetectedAnomaly(
                kind=kind,
                record=record,
                score=float(anomaly_score),
                max_zscore=maximum,
                contributions=contributions,
            )
        )

    return anomalies


def _finite_matrix(
    records: Sequence[FeatureRecord],
) -> NDArray[np.float64]:
    matrix = np.asarray(
        [record.vector() for record in records],
        dtype=np.float64,
    )
    return np.nan_to_num(
        matrix,
        copy=False,
        nan=0.0,
        posinf=0.0,
        neginf=0.0,
    )


def _fit_baselines(
    matrix: NDArray[np.float64],
) -> list[RunningStats]:
    baselines = [
        RunningStats()
        for _ in range(matrix.shape[1])
    ]

    for row in matrix:
        for baseline, value in zip(
            baselines,
            row,
            strict=True,
        ):
            baseline.update(float(value))

    return baselines


def _calculate_zscores(
    row: NDArray[np.float64],
    baselines: Sequence[RunningStats],
) -> NDArray[np.float64]:
    zscores = np.zeros(len(baselines), dtype=np.float64)

    for index, (value, baseline) in enumerate(
        zip(row, baselines, strict=True)
    ):
        deviation = baseline.standard_deviation
        if deviation > 0.0:
            zscores[index] = (
                float(value) - baseline.mean
            ) / deviation

    return zscores


def _summarize_zscores(
    zscores: NDArray[np.float64],
    feature_names: Sequence[str],
) -> tuple[
    float,
    float,
    tuple[tuple[str, float], ...],
]:
    absolute = np.abs(zscores)
    maximum = float(np.max(absolute))
    strongest = np.argsort(absolute)[::-1][:3]

    score = sqrt(
        sum(
            float(zscores[index]) ** 2
            for index in strongest
        )
        / len(strongest)
    )
    contributions = tuple(
        (
            feature_names[int(index)],
            float(zscores[index]),
        )
        for index in strongest
        if zscores[index] != 0.0
    )
    return score, maximum, contributions