# NetSentry

A compact, streaming network-traffic analysis engine for offline PCAP files.

NetSentry processes IPv4 TCP and UDP packets incrementally, reconstructs
bidirectional flows, calculates online statistics, tracks rolling host
behaviour, and ranks unusual activity using statistical or Isolation Forest
detection.

The project is deliberately CLI-first and focuses on networking, algorithms,
statistics, explainability, and measurable performance rather than frontend
scope.

## Features

- Incremental PCAP processing with Scapy
- IPv4 TCP and UDP packet filtering
- Canonical bidirectional flow reconstruction
- Expected O(1) active-flow lookup
- Welford online mean and variance
- Heap-based inactivity expiration
- Flow-level feature engineering
- Deque-based rolling host windows
- Transparent z-score anomaly detection
- Optional Isolation Forest detection
- Explainable heuristic classifications
- Ranked terminal reports
- Structured JSON export
- Runtime, throughput, and peak-memory instrumentation
- Reproducible synthetic benchmarks
- Deterministic unit tests

## Architecture

```text
                           PCAP capture
                                |
                                v
                  Scapy streaming packet reader
                                |
                                v
                         PacketRecord
                         /          \
                        /            \
                       v              v
              Active FlowTable   RollingHostTracker
              dictionary + heap   deque-based windows
                       |              |
                       v              v
              Completed flows     Host profiles
                       |
                       v
                Feature extraction
                       \              /
                        \            /
                         v          v
                    Anomaly detector
                   /                \
             z-score          Isolation Forest
                   \                /
                    v              v
                  Explanation heuristics
                           |
                     +-----+------+
                     |            |
                     v            v
              Terminal report   JSON export
```

The packet reader yields lightweight metadata records rather than retaining
Scapy packet objects. Each record updates flow and host state, after which the
original decoded packet can be released.

## Processing pipeline

1. Read one packet from the PCAP.
2. Ignore packets that are not IPv4 TCP or UDP.
3. Convert supported packets into a lightweight `PacketRecord`.
4. Canonicalize the two endpoints into a bidirectional flow key.
5. Expire flows whose inactivity deadlines have passed.
6. Update packet, byte, flag, size, and inter-arrival statistics.
7. Update the source host's rolling behaviour window.
8. Convert completed flows into finite numerical features.
9. Build statistical or Isolation Forest anomaly scores.
10. Apply transparent explanation rules.
11. Rank alerts and render terminal or JSON output.

## Core algorithms

### Canonical flow keys

Endpoints are ordered deterministically before constructing a flow key.
Packets travelling in either direction therefore map to the same dictionary
entry while retaining their A-to-B or B-to-A direction.

Active-flow lookup is expected O(1) through a hash map.

### Online statistics

Packet sizes and inter-arrival times use Welford's algorithm. Each observation
updates a count, mean, and accumulated squared deviation without retaining all
previous values.

Each update requires O(1) time and O(1) additional storage.

### Flow expiration

Active flows are stored in a dictionary, while expiry deadlines are recorded
in a minimum heap. Newer deadlines make older heap entries stale; stale
entries are ignored when removed.

This avoids scanning every active flow for every packet.

### Rolling host windows

Timestamped host events are stored in deques. Events leave from the front when
they fall outside the configured time window.

Rolling counters track:

- Connections
- Destination IP diversity
- Destination port diversity
- Packets
- Bytes
- SYN activity

Deque expiration is amortized O(1) per event.

### Detection

The default detector calculates per-feature baselines and standardized
deviations. Large absolute z-scores indicate values far from their cohort's
mean, but do not prove malicious activity.

The optional Isolation Forest uses deterministic random state and 5%
contamination. Its score direction is normalized so that higher values always
mean more anomalous.

### Explanations

Anomalies are assigned concise heuristic descriptions such as:

- Possible port scan
- Possible host sweep
- Traffic-volume anomaly
- SYN-heavy activity
- Unusual flow
- Unusual host behaviour

These labels describe unusual patterns, not confirmed attacks.

## Installation

NetSentry requires Python 3.12 or newer.

```powershell
git clone https://github.com/sohaib-uddin/NetSentry.git
cd NetSentry
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Dependencies:

- Scapy
- NumPy
- scikit-learn
- pytest

## Usage

Analyse a capture with the default z-score detector:

```powershell
python -m netsentry analyse ".\capture.pcap"
```

Use Isolation Forest:

```powershell
python -m netsentry analyse ".\capture.pcap" --detector isolation
```

Show the five highest-ranked alerts:

```powershell
python -m netsentry analyse ".\capture.pcap" --top 5
```

Adjust flow and host-window timing:

```powershell
python -m netsentry analyse ".\capture.pcap" --flow-timeout 60 --window 30
```

Change the statistical threshold:

```powershell
python -m netsentry analyse ".\capture.pcap" --z-threshold 3.5
```

Export JSON:

```powershell
python -m netsentry analyse ".\capture.pcap" --json ".\results.json"
```

Display every option:

```powershell
python -m netsentry analyse --help
```

## Example output

Abridged output from the generated 25,000-packet capture using Isolation
Forest:

```text
NetSentry Network Traffic Analysis

Capture:              benchmarks\data\synthetic-25000.pcap
Packets encountered:  25,000
Supported packets:    25,000
TCP packets:          12,500
UDP packets:          12,500
Flows reconstructed:  2,048
Hosts profiled:       259
Detector:             isolation
Anomalies detected:   125
Processing time:      27.013 s
Throughput:           925 packets/s
Peak Python memory:   66.0 MB

Top anomalies

1. Score: 0.215
   Host: 192.0.2.1
   Type: Traffic-volume anomaly
   Reason: recent traffic volume is significantly above its baseline
```

Runtime and memory figures depend on the machine, capture, detector, and
Python/library versions.

## JSON output

JSON reports include:

- Capture metadata
- Packet and byte counts
- Flow and host counts
- Detector configuration
- Processing time
- Throughput
- Peak Python memory
- Ranked anomaly scores
- Classifications and reasons
- Important contributing values

## Benchmarking

Generate deterministic benchmark captures:

```powershell
python -m benchmarks.generate_captures
```

Run the benchmark suite:

```powershell
python -m benchmarks.benchmark ".\benchmarks\data\synthetic-25000.pcap" ".\benchmarks\data\synthetic-50000.pcap" ".\benchmarks\data\synthetic-100000.pcap" ".\benchmarks\data\synthetic-200000.pcap" --runs 5 --warmups 1
```

Generated captures are ignored by Git and can be recreated locally.

### Methodology

- Machine: AMD Ryzen 5 220 w/ Radeon 740M Graphics
- Memory: 15.3 GB RAM
- Operating system: Windows 11, build 26200
- Python: 3.14.7
- Detector: z-score
- Warm-up runs: 1 per capture
- Measured runs: 5 per capture
- Reported runtime: median
- Peak memory: median measured Python allocation peak
- Instrumentation: `time.perf_counter` and `tracemalloc`

The captures are deterministic prefixes of the same generated traffic stream.
They contain 2,048 recurring bidirectional flows, allowing packet count to
increase while flow cardinality remains controlled.

### Baseline scaling results

These measurements were recorded before the packet-dissection optimization:

| Packets | Supported | Flows | Data | Median time | Throughput | Peak memory |
|---:|---:|---:|---:|---:|---:|---:|
| 25,000 | 25,000 | 2,048 | 2.70 MiB | 20.5736 s | 1,215 pkt/s | 7.39 MiB |
| 50,000 | 50,000 | 2,048 | 5.41 MiB | 41.9165 s | 1,193 pkt/s | 8.84 MiB |
| 100,000 | 100,000 | 2,048 | 10.82 MiB | 84.2378 s | 1,187 pkt/s | 8.87 MiB |
| 200,000 | 200,000 | 2,048 | 21.65 MiB | 172.2643 s | 1,161 pkt/s | 8.87 MiB |

An eightfold packet increase produced an approximately 8.37-fold runtime
increase. Throughput remained within 1,161–1,215 packets per second, supporting
approximately linear packet-processing behaviour for this controlled workload.

Peak memory stabilized near 8.87 MiB because raw packets were released and
flow cardinality remained fixed. This does not imply constant memory for
captures whose active or completed-flow counts continually increase.

One 50,000-packet run took 56.5632 seconds, substantially longer than the
others. Using the median prevented that outlier from distorting the reported
result.

### Optimization experiment

Profiling the 25,000-packet capture recorded approximately 88% of cumulative
runtime in packet iteration and approximately 80% in Scapy reading and
dissection.

NetSentry was changed to ask Scapy to dissect only the capture's link layer,
optional VLAN headers, IPv4, TCP, and UDP. Correctness was rechecked using the
complete test suite and known packet counts.

| Metric | Before | After | Difference |
|---|---:|---:|---:|
| Median runtime | 20.5736 s | 19.7364 s | 0.8372 s faster |
| Throughput | 1,215 pkt/s | 1,267 pkt/s | 52 pkt/s higher |
| Peak memory | 7.39 MiB | 7.31 MiB | 0.08 MiB lower |

The measured runtime improvement was 4.1%.

The optimization is deliberately modest: Scapy's general packet-object
construction remains the principal cost, while NetSentry retains Scapy's
well-tested decoding rather than introducing a narrow custom binary parser.

## Complexity

Let:

- `n` be the number of packets
- `a` be the number of active flows
- `f` be the number of completed flow records
- `e` be the number of rolling host events
- `d` be the number of detection features

| Operation | Expected complexity |
|---|---:|
| Packet ingestion | O(n) |
| Active-flow lookup/update | O(1) per packet |
| Streaming-statistic update | O(1) per observation |
| Heap expiry insertion/removal | O(log a) |
| Deque event insertion/expiration | Amortized O(1) |
| Z-score feature processing | O(f × d) |
| Final ranking | O(f log f) |
| Isolation Forest fitting | Library/model dependent |

## Memory behaviour

NetSentry does not retain raw packet objects after their metadata has updated
the relevant state.

Memory primarily depends on:

- Active flows
- Heap expiry entries
- Events still inside rolling host windows
- Completed flow features retained for detection
- Host profiles
- Isolation Forest matrices and model state

A very large PCAP is therefore streamed rather than loaded wholesale, but
memory is not strictly constant. A capture containing continually increasing
flow cardinality can require increasing feature and flow storage.

## Testing

Run the complete suite:

```powershell
python -m pytest -q
```

Current result:

```text
28 passed
```

Focused tests cover:

- IPv4 TCP/UDP parsing and filtering
- Reversed-packet flow canonicalization
- Directional flow counters
- Welford mean and variance
- Inter-arrival statistics
- Flow timeout and EOF flushing
- Zero-duration and finite feature handling
- Sliding-window expiration boundaries
- Z-score anomaly ranking
- Isolation Forest score direction
- Explanation classifications
- Terminal and JSON reporting

The production package contains 1,600 physical Python lines, conservatively
counted including blank lines and comments:

```powershell
$productionFiles = Get-ChildItem .\netsentry -Filter *.py -File
($productionFiles | Get-Content | Measure-Object -Line).Lines
```

## Engineering decisions

| Decision | Reason |
|---|---|
| Stream PCAP packets | Avoid retaining the complete capture |
| Canonical endpoint ordering | Reconstruct both packet directions as one flow |
| Dictionary-backed active flows | Expected O(1) lookup and update |
| Heap-backed expiration | Avoid scanning every flow per packet |
| Welford statistics | Constant-storage, numerically stable updates |
| Deques for host events | Efficient expiration from the oldest end |
| Z-score detector by default | Transparent and independently implemented |
| Isolation Forest as optional | Provides a second unsupervised approach without replacing explainability |
| Separate explanations | Keep anomaly scoring distinct from heuristic interpretation |
| CLI and JSON interface | Preserve focus on the engine and support automation without frontend coupling |
| Conservative feature scope | Keep the project technically dense and maintainable |

## Interface choice

NetSentry intentionally remains CLI-first.

A dashboard would make the same results more visual but would not strengthen
the networking, streaming, statistical, or performance-engineering core.
Because a separate portfolio project already demonstrates frontend work,
NetSentry provides a more distinct technical signal as a compact engine.

JSON export provides a stable boundary for adding a dashboard later without
coupling presentation code to packet processing.

## Limitations

- Offline analysis only
- IPv4 TCP and UDP only
- No live capture or traffic blocking
- No payload decryption or deep content inspection
- No IPv6
- Detection quality depends on the capture's baseline population
- Z-scores can be distorted by skewed distributions and outliers
- Isolation Forest identifies statistical isolation, not malicious intent
- Explanation categories are transparent heuristics, not attack confirmation
- Completed feature records are retained until detection
- Packet timestamps are expected to be reasonably ordered
- Scapy layer filtering changes global Scapy configuration and is intended for
  NetSentry's single-threaded CLI
- Synthetic benchmark traffic controls flow cardinality and is not a substitute
  for evaluation on diverse real-world sanitized captures
- Throughput figures include Python allocation tracing and are machine-specific

## Potential future work

Reasonable extensions, if scope were expanded, include:

- IPv6 flow support
- More robust statistical baselines such as median absolute deviation
- Detection over bounded batches to reduce completed-feature retention
- Evaluation against diverse sanitized public datasets
- Explicit support and testing for additional capture link types
- An optional visualization layer consuming exported JSON

These are intentionally outside the current compact project scope.

## Defensive-use scope

NetSentry is an offline defensive analysis tool. It does not intercept live
traffic, inject or modify packets, decrypt payloads, exploit systems, or
automate attacks.