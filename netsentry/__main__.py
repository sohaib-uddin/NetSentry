import argparse
from math import isfinite
from pathlib import Path
from typing import Sequence

from .engine import AnalysisResult, analyse_capture
from .packet import PcapReadError


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

    return parser


def print_summary(
    capture: Path,
    result: AnalysisResult,
) -> None:
    counters = result.counters

    print("-" * 60)
    print("NetSentry packet scan")
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


def run_analyse(
    capture: Path,
    flow_timeout: float,
    window_seconds: float,
    parser: argparse.ArgumentParser,
) -> int:
    capture = capture.expanduser()

    if not capture.is_file():
        parser.error(f"capture file does not exist: {capture}")

    try:
        result = analyse_capture(
            capture,
            flow_timeout=flow_timeout,
            window_seconds=window_seconds,
        )
    except PcapReadError as exc:
        parser.error(str(exc))

    print_summary(capture, result)
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
        )
    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())