#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

CONFIG_ROOT="$(mktemp -d)"
if command -v realpath >/dev/null 2>&1; then
  export AEGIS_CONFIG_ROOT="$(realpath "$CONFIG_ROOT")"
  export FIREWALL_CONFIG_ROOT="$AEGIS_CONFIG_ROOT"
else
  export AEGIS_CONFIG_ROOT="$(cd "$CONFIG_ROOT" && pwd)"
  export FIREWALL_CONFIG_ROOT="$AEGIS_CONFIG_ROOT"
fi
unset AEGIS_CONFIG_READONLY
unset FIREWALL_CONFIG_READONLY
RULES_FILE="$FIREWALL_CONFIG_ROOT/rules.conf"
POLICY_FILE="$FIREWALL_CONFIG_ROOT/policies.conf"
trap 'rm -rf "$CONFIG_ROOT"' EXIT

cat >"$RULES_FILE" <<'RULES'
allow cidr 0.0.0.0/0 ingress
default deny ingress
RULES
echo >"$POLICY_FILE"

PKT_FILE="$FIREWALL_CONFIG_ROOT/frag_tls.hex"
rm -f "$PKT_FILE"

# Build a minimal TLS ClientHello and split it across two TCP segments so SNI spans packets.
python3 - <<'PY' >"$PKT_FILE"
import struct

def build_client_hello(sni: bytes) -> bytes:
    random_bytes = bytes(range(32))
    session_id = b""
    cipher_suites = b"\x00\x2f"  # TLS_RSA_WITH_AES_128_CBC_SHA
    comp_methods = b"\x01\x00"
    # SNI extension
    sni_ext = b"\x00" + struct.pack("!H", len(sni)) + sni
    sni_list = struct.pack("!H", len(sni_ext)) + sni_ext
    ext = b"\x00\x00" + struct.pack("!H", len(sni_list)) + sni_list
    extensions = struct.pack("!H", len(ext)) + ext
    body = (
        b"\x03\x03" + random_bytes +
        struct.pack("!B", len(session_id)) + session_id +
        struct.pack("!H", len(cipher_suites)) + cipher_suites +
        comp_methods +
        extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record

def tcp_pkt(seq, payload=b"", flags=0x18):
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBHII",
        ver_ihl, 0, total_len, 0x9999, 0x4000, 64, 6, 0, 0x0a0000f5, 0x0a000002)
    offset_flags = (5 << 12) | flags
    tcp = struct.pack("!HHIIHHHH", 45000, 443, seq, 1, offset_flags, 0x7210, 0, 0)
    frame = eth + ip + tcp + payload
    print(" ".join(f"{b:02x}" for b in frame))

hello = build_client_hello(b"frag.example.com")
# Split into two segments with SNI crossing boundary.
mid = len(hello) // 2
part1 = hello[:mid]
part2 = hello[mid:]

tcp_pkt(1, b"", flags=0x02)
tcp_pkt(2, b"", flags=0x10)
tcp_pkt(3, part1)
tcp_pkt(3 + len(part1), part2)
PY

echo "[attack] Replaying fragmented TLS ClientHello..."
OUTPUT=$(cargo run -p aegis --quiet -- replay --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --file "$PKT_FILE" --no-logs 2>&1 || true)
echo "$OUTPUT"

allowed=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^allowed/){split($i,a,"=");print a[2]}}}')
alerts=$(echo "$OUTPUT" | awk '/Replay done/ {for(i=1;i<=NF;i++){if($i~/^alerts/){split($i,a,"=");print a[2]}}}')

if [ -z "$alerts" ] || [ "$alerts" -lt 1 ]; then
  echo "TLS metadata or detection failed on fragmented ClientHello" >&2
  exit 1
fi

echo "[attack] Fragmented TLS ClientHello simulation passed (allowed=${allowed:-0} alerts=${alerts:-0})"
