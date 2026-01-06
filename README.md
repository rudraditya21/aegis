# Aegis

High-performance Rust firewall/IDS workspace with persistent configuration under `/etc/aegis`.

## Workspace Map

| Crate | Purpose |
| --- | --- |
| `packet-parser` | Bounds-checked Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP parsing + TCP reassembly helpers |
| `config` | Persistent config root manager (versioning, integrity, rollback) |
| `aegis-core` | Stateless/stateful engine (L3/L4 rules, flow tracker, TCP FSM, LRU, attack protection, DPI hooks, threat intel, HA hooks) |
| `aegis-utils` | Shared helpers (config root resolution, hex parsing) |
| `aegis` | CLI and runtime wrapper (rules/policies, capture, eval, metrics, failover controls) |

## Quick Start

- Config root: defaults to `/etc/aegis` (override with `AEGIS_CONFIG_ROOT`). Layout:
  - `aegis.yaml` (runtime config, optional), `rules/l3l4.rules`, `rules/dpi.rules`, `rules/policies.rules`
  - `intel/ip_blocklist.txt`, `intel/domain_blocklist.txt`
  - `state/flows.snapshot`, `state/counters.bin`, `state/versions/` (backups)
  - `logs/alerts.log`, `logs/dpi.log`, `logs/audit.log`
- Run tests: `cargo test`
- Add rule: `cargo run -p aegis -- add-rule --rules /etc/aegis/rules/l3l4.rules --rule "allow cidr 10.0.0.0/8 ingress"`
- List rules: `cargo run -p aegis -- list-rules --rules /etc/aegis/rules/l3l4.rules`
- Evaluate hex packet: `cargo run -p aegis -- eval --rules /etc/aegis/rules/l3l4.rules --direction ingress --hex "<hex bytes>"`
- Capture (pcap): `cargo run -p aegis -- capture --rules /etc/aegis/rules/l3l4.rules --iface eth0 --count 10`
- Fail mode: default fail-closed when no rules loaded; set `AEGIS_FAIL_OPEN=1` to start in fail-open.
- Docker: `docker build -t aegis . && docker run --rm aegis`

### Runtime Config (aegis.yaml)

Example:
```yaml
dataplane:
  backend: pcap
  pcap:
    snaplen: 65535
    promisc: true
    timeout-ms: 1000
    filter: "tcp and port 443"
  rss:
    enabled: true
    symmetric: true
    hash-fields: ["ipv4", "ipv6", "tcp", "udp"]
    queues: [0, 1]
    cpu-affinity: [2, 3]
    seed: 42
```

AF_XDP example (Linux only, feature-gated):
```yaml
dataplane:
  backend: af-xdp
  af-xdp:
    queue: 0
    umem-frames: 4096
    frame-size: 2048
    headroom: 256
    use-need-wakeup: false
    numa-node: 0
    use-hugepages: true
    hugepage-size-kb: 2048
    hugepage-fallback: true
    numa-fallback: true
    pin-dir: "/sys/fs/bpf/aegis"
    program-name: "xdp_prog_eth0"
    map-name: "xsk_map_eth0"
    xsk-map-entries: 1
    xsk-map-pin: "/sys/fs/bpf/aegis/xsk_map_eth0"
    xdp-program-pin: "/sys/fs/bpf/aegis/xdp_prog_eth0"
    attach: true
    mode: auto
    update-if-noexist: true
```

DPDK example (Linux only, feature-gated):
```yaml
dataplane:
  backend: dpdk
  dpdk:
    port-id: 0
    rx-queue: 0
    tx-queue: 0
    rx-queues: 1
    tx-queues: 1
    mbuf-count: 8192
    mbuf-cache: 256
    socket-id: 0
    queue-sockets: [0]
    mem-channels: 4
    no-huge: false
    hugepage-fallback: true
    core-mask: "0"
    rx-desc: 1024
    tx-desc: 1024
    rx-burst: 32
    tx-burst: 32
    promisc: true
    eal-args: []
```

Supported backends: `pcap` (default). `af-xdp` and `dpdk` require compiled backends (feature flags) and Linux support.
When `rss.enabled` is true, aegis uses RSS hashing for flow sharding. On RSS-capable backends it
spawns queue-affine workers; for pcap it uses software hashing to shard flows across workers.

### Performance & Diagnostics

- Perf/stress harness: `bash scripts/run_perf_stress.sh`
- RSS balance benchmark: `bash scripts/run_rss_balance.sh`
- Full regression battery: `bash scripts/run_all_tests.sh`
- Dataplane readiness: `cargo run -p aegis -- dataplane-diag`
- Metrics (include dataplane stats with `--iface`): `cargo run -p aegis -- metrics --rules /etc/aegis/rules/l3l4.rules --iface eth0`
- Per-core worker balance (live traffic): `cargo run -p aegis -- capture --rules /etc/aegis/rules/l3l4.rules --iface eth0 --count 10000 --worker-stats`
- CI workflows: `.github/workflows/ci-pcap.yml`, `.github/workflows/ci-af-xdp.yml`, and `.github/workflows/ci-dpdk.yml`.

### Docker Test Runs

CI container (AF_XDP/DPDK feature tests):
```bash
docker build -f docker/Dockerfile.ci -t aegis-ci .
docker run --rm -v "$PWD:/workspace" -w /workspace aegis-ci bash docker/run_ci_tests.sh af-xdp
docker run --rm -v "$PWD:/workspace" -w /workspace aegis-ci bash docker/run_ci_tests.sh dpdk
```

Runtime images (multi-distro Linux):
```bash
bash docker/build-matrix.sh
docker run --rm -it aegis:debian --help
```

PCAP-only tests (host):
```bash
cargo test -p aegis-core
cargo test -p aegis-dataplane --features pcap
cargo test -p aegis --features pcap
```

### Rule File Format

One rule per line (`#` for comments):
- `allow cidr 10.0.0.0/8 ingress`
- `deny port tcp 22 ingress`
- `allow port udp 1000-2000 ingress`
- `deny proto icmpv6 egress`
- `default deny ingress`

Evaluation order: LPM CIDR → port range/exact → protocol → default (directional) → implicit deny.

### Backend Requirements & Tuning

AF_XDP (Linux only):
- Kernel/XDP-capable NIC + driver, bpffs mounted at `/sys/fs/bpf`.
- Optional bundled XDP program pinning uses `pin-dir`, `program-name`, and `map-name`.
- UMEM tuning: `umem-frames`, `frame-size`, `headroom`.
- Hugepages/NUMA: `use-hugepages`, `hugepage-size-kb`, `numa-node`, and `*-fallback` flags.

DPDK (Linux only):
- Requires DPDK userspace drivers (vfio/uio), hugepages (or `no-huge=true`), and port binding.
- Queue/core mapping: `core-mask`, `rx-queues`, `tx-queues`, `queue-sockets`.
- Memory tuning: `mbuf-count`, `mbuf-cache`, `rx-desc`, `tx-desc`, `rx-burst`, `tx-burst`.

Operational tuning:
- `rss.*` aligns flow distribution with RX queues and CPU affinity.
- `flow-shards` should match worker count for per-core isolation.
- Use `dataplane-diag` and `metrics --iface` to verify hugepage/NUMA readiness and zero-copy support.
- For zero-copy TX, lease buffers via the dataplane `lease_tx` API; `send_frame` remains a safe copy-based fallback.

## Implemented Features

| Area | Highlights |
| --- | --- |
| Packet parsing | Bounds-checked Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP; fragment rejection; VLAN stacking; TCP overlap-aware reassembly |
| Stateless L3/L4 | CIDR allow/deny (LPM), port/proto rules, per-direction defaults, conflict resolution (deny > allow; redirect wins) |
| Stateful flows | 5-tuple flow table; TCP state machine; handshake/established/closed timeouts; LRU eviction; per-CPU stats; flow snapshot/sync hooks |
| DPI / App ID | HTTP/DNS/TLS/file heuristics; TLS ClientHello metadata (SNI, ciphers) including reassembled payloads; signature engine (SQLi/XSS/path traversal); normalization (double percent-decode, BOM strip); tail-aware scanning |
| Policy engine | Priority if/then policies; geo/time/user/app match; conflict resolution; hit counters; versioned apply |
| Threat intel | IP/domain blocklists with timestamps; geo/user enrichment hooks; dynamic block support |
| Attack protection | SYN/ICMP/UDP rate limiting; invalid ACK drop; behavior detector (rate + beaconing); signature blocking (optional); C2 beacon alerts; protector counters decay |
| TLS/IPS controls | TLS policy on SNI/cipher; IDS/IPS toggles; DPI logging toggle; geo/time toggles; failover flags; flow capacity controls |
| HA/failover | Flow state export/import; failover enable/disable; flow capacity setter |
| CLI | Rule/policy add/remove/list; eval/eval-batch; replay files; capture/capture-async; metrics; audit-status; show-config-root; failover controls; behavior/signature blocking toggles; Rayon batch eval |
| PCAP shim | Safe wrapper for open/live/next/drop; build.rs generates libpcap bindings; unsafe confined to FFI boundary |

## Test & Validation Matrix

| Suite | What it covers | How to run |
| --- | --- | --- |
| Unit tests | Parsing, TCP FSM, LRU, policies, threat intel, TLS parsing, signatures, behavior detector | `cargo test` |
| Attack simulations | SYN/ACK/UDP/ICMP floods, DNS amplification, HTTP flood/Slowloris, obfuscation/double-encoding, TLS handshake flood, fragmented TLS ClientHello, TCP segmentation evasion, fragmentation, protocol confusion, exploit signatures, C2 beaconing | `bash scripts/run_regressions.sh` (runs all) or individual `scripts/attack_*.sh` |
| Policy correctness | LPM precedence, port deny precedence, default deny | `bash scripts/run_policy_correctness.sh` |
| Performance & stress | Throughput/latency/flow-scale/rule-scale, eval-batch (Rayon), optional iperf3/tcpreplay/hping3/wrk/dnsperf hooks | `bash scripts/run_perf_stress.sh` |
| Stability/soak | Mixed traffic/attacks over time (configurable; smoke with SOAK_DURATION=300) | `SOAK_DURATION=300 bash scripts/run_long_soak.sh` |
| Chaos | Fail-open/closed kill test, reload storm, memory/fd pressure | `bash scripts/chaos_userspace_crash.sh`, `bash scripts/chaos_config_reload_storm.sh`, `bash scripts/chaos_resource_exhaustion.sh` |
| Feature matrix | End-to-end sample flows across rule/policy features | `bash scripts/run_feature_matrix.sh` |

## Shortcuts

- Full regressions: `bash scripts/run_regressions.sh`
- Perf (synthetic): `bash scripts/run_perf_stress.sh`
- Stability smoke (5m): `SOAK_DURATION=300 bash scripts/run_long_soak.sh`
- Everything (tests + attacks + feature matrix): `bash scripts/run_all_tests.sh`
