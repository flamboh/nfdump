#!/bin/sh
# Exercise the Atlantis output through nfdump's process-output seam.

set -eu

ROOT=$(pwd)
NFDUMP="$ROOT/../nfdump/nfdump -G none"
WORK="$ROOT/atlantis-test.$$"
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir "$WORK"
cd "$WORK"

"$ROOT/../test/nfgen" --atlantis-tunnel >/dev/null

# Empty and no-match output must contain only the binary header and terminator,
# even without quiet mode.
$NFDUMP -r dummy_flows.nf -o atlantis 'bytes < 0' >"$WORK/empty.atl" 2>"$WORK/empty.err"
test ! -s "$WORK/empty.err"
python3 - "$WORK/empty.atl" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
expected = b"ATLNFLOW" + (1).to_bytes(2, "little") + (72).to_bytes(2, "little") + (0).to_bytes(4, "little")
assert data == expected, data.hex()
PY

# Hostname lookup is a filter diagnostic and must stay off the binary stream.
$NFDUMP -r dummy_flows.nf -q -o atlantis 'host localhost' >"$WORK/hostname.atl" 2>"$WORK/hostname.err"
grep -q '^Resolving localhost' "$WORK/hostname.err"
python3 - "$WORK/hostname.atl" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
expected = b"ATLNFLOW" + (1).to_bytes(2, "little") + (72).to_bytes(2, "little") + (0).to_bytes(4, "little")
assert data == expected, data.hex()
PY

$NFDUMP -r dummy_flows.nf -q -o atlantis >"$WORK/flows.atl" 2>"$WORK/flows.err"
test ! -s "$WORK/flows.err"
python3 - "$WORK/flows.atl" <<'PY'
import pathlib
import sys

data = pathlib.Path(sys.argv[1]).read_bytes()
assert data[:8] == b"ATLNFLOW"
assert int.from_bytes(data[8:10], "little") == 1
assert int.from_bytes(data[10:12], "little") == 72

offset = 12
records = []
while True:
    assert offset + 4 <= len(data), "missing block header"
    count = int.from_bytes(data[offset:offset + 4], "little")
    offset += 4
    assert count <= 2048
    if count == 0:
        break
    end = offset + count * 72
    assert end <= len(data), "short block"
    records.extend(data[offset:end][i:i + 72] for i in range(0, count * 72, 72))
    offset = end
assert offset == len(data), "trailing bytes"
assert records, "generated fixture unexpectedly had no records"

def u64(record, start):
    return int.from_bytes(record[start:start + 8], "little")

def v4(src, dst):
    return bytes(src) + b"\0" * 12, bytes(dst) + b"\0" * 12

src, dst = v4((172, 16, 1, 68), (192, 168, 170, 104))
addressed = [record for record in records if record[:16] == src and record[16:32] == dst]
assert addressed, "asymmetric IPv4 record missing"
assert addressed[0][68] == 6 and addressed[0][69] == 6
assert [u64(addressed[0], start) for start in (32, 40, 48, 56)] == [25, 33445566, 1, 2801]
assert int.from_bytes(addressed[0][64:66], "little") == 12345
assert int.from_bytes(addressed[0][66:68], "little") == 433

v6_src = bytes.fromhex("fe800000000000002110abcd12340000")
v6_dst = bytes.fromhex("fe800000000000002110abcd12354321")
assert any(record[:16] == v6_src and record[16:32] == v6_dst and record[69] & 1 for record in records), "IPv6 record missing"

icmp = [record for record in records if record[68] == 1]
assert icmp and all(int.from_bytes(record[66:68], "little") == 0 for record in icmp)

counted = [record for record in records if u64(record, 48) == 7]
assert counted, "EXcntFlow flow count missing"

with_ttl = [record for record in records if record[70:72] == bytes((40, 255))]
assert with_ttl, "TTL extension missing"

tunnel_src, tunnel_dst = v4((10, 0, 0, 1), (10, 0, 0, 2))
tunnel = [record for record in records if record[:16] == tunnel_src and record[16:32] == tunnel_dst and record[68] == 4]
assert tunnel, "synthetic tunnel record missing"
assert u64(tunnel[0], 48) == 1 and tunnel[0][70:72] == b"\0\0"
outer = [record for record in records if record[:16] == bytes.fromhex("488aaa65000000000000000000000000") and u64(record, 48) == 7]
assert outer and outer[-1][70:72] == bytes((40, 255))
assert records.index(tunnel[0]) < records.index(outer[-1]), "tunnel record must precede outer record"
assert tunnel[0][32:48] == outer[-1][32:48]
assert tunnel[0][56:68] == outer[-1][56:68]
PY

# Atlantis is a record stream, so aggregation, statistics, sorting, and file
# output must be rejected before anything is written to stdout.
for mode in aggregate stats sort write; do
    case "$mode" in
        aggregate) args="-a" ;;
        stats) args="-s record" ;;
        sort) args="-O bytes" ;;
        write) args="-w $WORK/output.nf" ;;
    esac
    if $NFDUMP -r dummy_flows.nf -q -o atlantis $args >"$WORK/$mode.out" 2>"$WORK/$mode.err"; then
        echo "Atlantis unexpectedly accepted $mode mode" >&2
        exit 1
    fi
    test ! -s "$WORK/$mode.out"
    test -s "$WORK/$mode.err"
done
