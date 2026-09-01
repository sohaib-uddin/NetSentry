import argparse
from math import isfinite
from pathlib import Path
from typing import Sequence

from .engine import AnalysisResult, analyse_capture
from .packet import PcapReadError
from .report import (
    format_bytes,
    print_ranked_alerts,
    write_json,
)


def positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"expected a number, received: {value}"
        ) from exc

    if not isfinite(number) or number <= 0.0:
        raise argparse.ArgumentTypeError(
            "value must be positive and finite"
        )

    return number


def positive_integer(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"expected an integer, received: {value}"
        ) from exc

    if number <= 0:
        raise argparse.ArgumentTypeError(
            "value must be a positive integer"
        )

    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netsentry",
        description="Offline network-traffic analysis.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    analyse = subparsers.add_parser(
        "analyse",
        help="analyse an offline PCAP file",
    )
    analyse.add_argument(
        "capture",
        type=Path,
        help="path to the PCAP file",
    )
    analyse.add_argument(
        "--flow-timeout",
        type=positive_float,
        default=60.0,
        metavar="SECONDS",
        help="flow inactivity timeout (default: 60)",
    )
    analyse.add_argument(
        "--window",
        type=positive_float,
        default=30.0,
        metavar="SECONDS",
        help="rolling host window (default: 30)",
    )
    analyse.add_argument(
        "--detector",
        choices=("zscore", "isolation"),
        default="zscore",
        help="anomaly detector (default: zscore)",
    )
    analyse.add_argument(
        "--z-threshold",
        type=positive_float,
        default=3.0,
        metavar="VALUE",
        help="anomaly z-score threshold (default: 3.0)",
    )
    analyse.add_argument(
        "--top",
        type=positive_integer,
        default=10,
        metavar="COUNT",
        help="maximum anomalies to display (default: 10)",
    )
    analyse.add_argument(
        "--json",
        type=Path,
        dest="json_path",
        metavar="PATH",
        help="write results to a JSON file",
    )

    return parser


def print_summary(
    capture: Path,
    result: AnalysisResult,
) -> None:
    counters = result.counters

    print("-" * 60)
    print("NetSentry Network Traffic Analysis")
    print("-" * 60)
    print(f"Capture:              {capture}")
    print(f"Packets encountered:  {counters.encountered:,}")
    print(f"Supported packets:    {counters.supported:,}")
    print(f"Unsupported packets:  {counters.unsupported:,}")
    print(f"TCP packets:          {counters.tcp_packets:,}")
    print(f"UDP packets:          {counters.udp_packets:,}")
    print(f"IPv4 bytes processed: {counters.bytes_processed:,}")
    print(f"Flows reconstructed:  {result.flows.flows_created:,}")
    print(f"Flows completed:      {result.flows.flows_completed:,}")

    host_count = len(
        {
            profile.source_ip
            for profile in result.host_profiles
        }
    )
    print(f"Hosts profiled:       {host_count:,}")
    print(f"Detector:             {result.detector}")
    print(f"Anomalies detected:   {len(result.alerts):,}")
    print(
        f"Processing time:      "
        f"{result.metrics.processing_seconds:.3f} s"
    )
    print(
        f"Throughput:           "
        f"{result.metrics.packets_per_second:,.0f} packets/s"
    )
    print(
        f"Peak Python memory:   "
        f"{format_bytes(result.metrics.peak_memory_bytes)}"
    )


def run_analyse(
    capture: Path,
    flow_timeout: float,
    window_seconds: float,
    parser: argparse.ArgumentParser,
    z_threshold: float = 3.0,
    detector: str = "zscore",
    top: int = 10,
    json_path: Path | None = None,
) -> int:
    capture = capture.expanduser()

    if not capture.is_file():
        parser.error(f"capture file does not exist: {capture}")

    try:
        result = analyse_capture(
            capture,
            flow_timeout=flow_timeout,
            window_seconds=window_seconds,
            z_threshold=z_threshold,
            detector=detector,
        )
    except PcapReadError as exc:
        parser.error(str(exc))

    if json_path is not None:
        json_path = json_path.expanduser()
        try:
            write_json(
                json_path,
                capture,
                result,
                flow_timeout=flow_timeout,
                window_seconds=window_seconds,
                z_threshold=z_threshold,
                top=top,
            )
        except OSError as exc:
            parser.error(
                f"could not write JSON '{json_path}': {exc}"
            )

    print_summary(capture, result)
    print_ranked_alerts(result.alerts, top)

    if json_path is not None:
        print(f"JSON written to:      {json_path}")

    return 0


def main(arguments: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(arguments)

    if args.command == "analyse":
        return run_analyse(
            args.capture,
            args.flow_timeout,
            args.window,
            parser,
            z_threshold=args.z_threshold,
            detector=args.detector,
            top=args.top,
            json_path=args.json_path,
        )

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())