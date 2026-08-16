# Atlantis Flow Stream

`nfdump -o atlantis` writes a private, versioned flow stream for ATLANTIS.
Diagnostics remain on standard error. The mode only supports direct record
output; aggregation, statistics, sorting, and `-w` output are rejected before
any stream bytes are written.

## Version 1 framing

All integers are unsigned little-endian. IP address bytes are in network order.

- The 12-byte header is `ATLNFLOW`, a `u16` version (`1`), and a `u16` record
  length (`72`).
- Each data block starts with a `u32` record count from 1 through 2,048,
  followed by exactly `count * 72` record bytes.
- A zero `u32` count terminates every successful stream, including an empty
  stream. Physical EOF must immediately follow it.

Each 72-byte record contains:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 16 | source address |
| 16 | 16 | destination address |
| 32 | 8 | packets |
| 40 | 8 | bytes |
| 48 | 8 | flow count |
| 56 | 8 | duration in milliseconds |
| 64 | 2 | source port |
| 66 | 2 | destination port |
| 68 | 1 | IP protocol |
| 69 | 1 | tag |
| 70 | 1 | minimum TTL |
| 71 | 1 | maximum TTL |

Tag bit 0 selects IPv6. Bits 1 and 2 mark source and destination
anonymization. Higher bits are reserved and zero. IPv4 addresses occupy their
first four bytes; the remaining 12 bytes are zero.

Duration is `msecLast - msecFirst`. Missing flow-count data maps to one;
missing generic counters map to zero. ICMP and ICMPv6 destination ports are
zero. Each TTL byte uses zero independently as the missing sentinel, so a
record such as `min=64, max=0` is valid. Tunnel extensions produce a synthetic
tunnel record immediately before the outer record, matching CSV expansion;
the synthetic record has flow count one and missing TTL values.
