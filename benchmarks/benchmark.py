import argparse
import platform
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Sequence

from netsentry.engine import analyse_capture


@dataclass(frozen=True, slots=True)
class BenchmarkRow:
    path: Path
    packets: int
    supported_packets: int
    flows: int
    bytes_processed: int
    median_seconds: float
    packets_per_second: float
    median_peak_bytes: int


def positive_integer(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(
            "value must be greater than zero"
        )
    return number


def non_negative_integer(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError(
            "value cannot be negative"
        )
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Benchmark NetSentry against PCAP files."
    )
    parser.add_argument(
        "captures",
        nargs="+",
        type=Path,
        help="one or more PCAP files to benchmark",
    )
    parser.add_argument(
        "--runs",
        type=positive_integer,
        default=5,
        help="number of measured runs per capture",
    )
    parser.add_argument(
        "--warmups",
        type=non_negative_integer,
        default=1,
        help="number of unmeasured warm-up runs",
    )
    parser.add_argument(
        "--detector",
        choices=("zscore", "isolation"),
        default="zscore",
    )
    parser.add_argument(
        "--flow-timeout",
        type=float,
        default=60.0,
    )
    parser.add_argument(
        "--window",
        type=float,
        default=30.0,
    )
    parser.add_argument(
        "--z-threshold",
        type=float,
        default=3.0,
    )
    return parser


def run_analysis(
    path: Path,
    args: argparse.Namespace,
):
    return analyse_capture(
        path=path,
        flow_timeout=args.flow_timeout,
        window_seconds=args.window,
        z_threshold=args.z_threshold,
        detector=args.detector,
    )


def benchmark_capture(
    path: Path,
    args: argparse.Namespace,
) -> BenchmarkRow:
    print(f"\nCapture: {path.resolve()}")

    for warmup in range(1, args.warmups + 1):
        print(f"  Warm-up {warmup}/{args.warmups}")
        run_analysis(path, args)

    runtimes: list[float] = []
    peak_memory: list[int] = []
    expected_counts: tuple[int, int, int, int] | None = None

    for run_number in range(1, args.runs + 1):
        result = run_analysis(path, args)

        supported_packets = sum(
            flow.total_packets
            for flow in result.flow_features
        )
        counts = (
            result.counters.encountered,
            supported_packets,
            len(result.flow_features),
            result.counters.bytes_processed,
        )

        if expected_counts is None:
            expected_counts = counts
        elif counts != expected_counts:
            raise RuntimeError(
                "analysis counts changed between benchmark runs"
            )

        runtimes.append(result.metrics.processing_seconds)
        peak_memory.append(result.metrics.peak_memory_bytes)

        print(
            f"  Measured {run_number}/{args.runs}: "
            f"{result.metrics.processing_seconds:.4f} seconds"
        )

    assert expected_counts is not None
    packets, supported, flows, byte_count = expected_counts
    median_seconds = median(runtimes)

    return BenchmarkRow(
        path=path,
        packets=packets,
        supported_packets=supported,
        flows=flows,
        bytes_processed=byte_count,
        median_seconds=median_seconds,
        packets_per_second=(
            packets / median_seconds
            if median_seconds > 0.0
            else 0.0
        ),
        median_peak_bytes=int(median(peak_memory)),
    )


def print_results(
    rows: Sequence[BenchmarkRow],
    args: argparse.Namespace,
) -> None:
    print("\nNetSentry benchmark results")
    print(f"Python:   {platform.python_version()}")
    print(f"Platform: {platform.platform()}")
    print(
        f"Method:   {args.warmups} warm-up, "
        f"{args.runs} measured runs, median reported"
    )
    print(f"Detector: {args.detector}\n")

    header = (
        f"{'Capture':<26}"
        f"{'Packets':>12}"
        f"{'Supported':>12}"
        f"{'Flows':>10}"
        f"{'Data MiB':>11}"
        f"{'Time (s)':>11}"
        f"{'Packets/s':>13}"
        f"{'Peak MiB':>11}"
    )
    print(header)
    print("-" * len(header))

    for row in rows:
        name = row.path.name
        if len(name) > 25:
            name = f"{name[:22]}..."

        print(
            f"{name:<26}"
            f"{row.packets:>12,}"
            f"{row.supported_packets:>12,}"
            f"{row.flows:>10,}"
            f"{row.bytes_processed / (1024 ** 2):>11.2f}"
            f"{row.median_seconds:>11.4f}"
            f"{row.packets_per_second:>13,.0f}"
            f"{row.median_peak_bytes / (1024 ** 2):>11.2f}"
        )


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    missing = [
        path
        for path in args.captures
        if not path.is_file()
    ]
    if missing:
        parser.error(
            "capture not found: "
            + ", ".join(str(path) for path in missing)
        )

    rows = [
        benchmark_capture(path, args)
        for path in args.captures
    ]
    print_results(rows, args)


if __name__ == "__main__":
    main()