#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname "$0")/.."

echo "[1/5] Running full test suite..."
cargo test --all

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
allow cidr 10.0.0.0/8 ingress
deny port tcp 22 ingress
default deny ingress
RULES

cat >"$POLICY_FILE" <<'POLICY'
priority 10 action allow src 10.0.0.0/8 user alice geo US time 9-17
priority 5 action deny src 192.168.10.0/24
POLICY

hex_base="$(
  python3 - <<'PY'
import struct, binascii

def pkt(src_ip, dst_ip, src_port, dst_port, payload):
    # Ethernet (dummy)
    eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H", 0x0800)
    # IPv4 header
    ver_ihl = (4 << 4) | 5
    total_len = 20 + 20 + len(payload)
    ip = struct.pack("!BBHHHBBHII", ver_ihl, 0, total_len, 1, 0x4000, 64, 6, 0, src_ip, dst_ip)
    tcp = struct.pack("!HHIIHHHH", src_port, dst_port, 1, 0, (5<<12)|0x18, 29200, 0, 0)
    frame = eth + ip + tcp + payload
    print(" ".join(f"{b:02x}" for b in frame))
pkt(0x0a000001, 0x0a000002, 8080, 80, b"GET / HTTP/1.1\r\n")
PY
)"
if [ -z "$hex_base" ]; then
  echo "Failed to generate base packet hex" >&2
  exit 1
fi

echo "[2/5] Base allow/deny paths..."
cargo run -p aegis -- eval --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --hex "$hex_base"

hex_time="$(
  python3 - <<'PY'
import struct
eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H",0x0800)
ip = struct.pack("!BBHHHBBHII",(4<<4)|5,0,40,2,0x4000,64,6,0,0x0a000001,0x0a000002)
tcp = struct.pack("!HHIIHHHH",1234,80,1,0,(5<<12)|0x10,65535,0,0)
frame = eth+ip+tcp
print(" ".join(f"{b:02x}" for b in frame))
PY
)"
if [ -z "$hex_time" ]; then
  echo "Failed to generate time-window packet hex" >&2
  exit 1
fi

echo "[3/5] Policy time window (override to 22h -> denied unless disabled)..."
cargo run -p aegis -- eval --rules "$RULES_FILE" --policies "$POLICY_FILE" --direction ingress --hex "$hex_time" --disable-time

hex_tls="$(
  python3 - <<'PY'
import struct
def tls_client_hello(sni: str):
    random = bytes(range(32))
    session = b""
    cipher = b"\x13\x01"  # TLS_AES_128_GCM_SHA256
    comp = b"\x00"
    host = sni.encode()
    sni_list = b"\x00" + len(host).to_bytes(2,"big") + host
    sni_ext = len(sni_list).to_bytes(2,"big") + sni_list
    exts = b"\x00\x00" + len(sni_ext).to_bytes(2,"big") + sni_ext
    hello = b"\x03\x03" + random + bytes([len(session)]) + session + len(cipher).to_bytes(2,"big") + cipher + bytes([len(comp)]) + comp + len(exts).to_bytes(2,"big") + exts
    hs = b"\x01" + len(hello).to_bytes(3,"big") + hello
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2,"big") + hs
    return rec

payload = tls_client_hello("blocked.test")
eth = bytes.fromhex("ffe1e2e3e4e5001122334455") + struct.pack("!H",0x0800)
total_len = 20+20+len(payload)
ip = struct.pack("!BBHHHBBHII",(4<<4)|5,0,total_len,3,0x4000,64,6,0,0x0a000005,0x0a000006)
tcp = struct.pack("!HHIIHHHH",44444,443,1,0,(5<<12)|0x18,65535,0,0)
frame = eth+ip+tcp+payload
print(" ".join("{:02x}".format(b) for b in frame))
PY
)"
if [ -z "$hex_tls" ]; then
  echo "Failed to generate TLS ClientHello packet hex" >&2
  exit 1
fi

echo "[4/5] TLS/SNI parsing and alert output..."
cargo run -p aegis -- eval --rules "$RULES_FILE" --direction ingress --hex "$hex_tls"

echo "[5/5] List rules and policies after actions..."
cargo run -p aegis -- list-rules --rules "$RULES_FILE"
cargo run -p aegis -- list-policies --policies "$POLICY_FILE"

echo "[diag] Dataplane diagnostics..."
cargo run -p aegis -- dataplane-diag

echo "Feature matrix run complete."
