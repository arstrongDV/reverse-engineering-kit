# Message Dictionary: rekit session protocol (TCP 7500)

## Framing (big-endian)
| Offset | Size | Field | Meaning | Finding |
| --- | --- | --- | --- | --- |
| 0 | 2 | magic | B1 7E | F-001 |
| 2 | 1 | type | see below | F-002 |
| 3 | 1 | flags | 0 in analysis; bit0 seen set in holdout (meaning unknown) | F-004 |
| 4 | 2 | seq | client counts 1..n; server replies echo the request seq (CHALLENGE echoes HELLO) | F-002 |
| 6 | 2 | length | payload bytes | F-001 |
| 8 | n | payload | | |
| 8+n | 2 | crc | CRC-16/CCITT-FALSE over bytes 0..8+n-1 | F-001 |

## Messages
| Type | Dir | Payload | Purpose |
| --- | --- | --- | --- |
| 1 HELLO | C→S | ASCII client id ("rekit-client/1.0") | open session |
| 2 CHALLENGE | S→C | 8 bytes | auth nonce |
| 3 AUTH_RESPONSE | C→S | 8 bytes = challenge XOR 0x5C | auth (F-003) |
| 4 GET_PARAM | C→S | u16 param id | read parameter |
| 5 PARAM_VALUE | S→C | u16 id, i32 signed value | reply |
| 6 ERROR | S→C | u8 code (2 seen, after GET_PARAM 99) | failure; holdout only |
| 7 BYE | C→S | empty | close; no reply |

## State machine
HELLO → CHALLENGE → AUTH_RESPONSE → (GET_PARAM → PARAM_VALUE|ERROR)* → BYE. No server reply to AUTH_RESPONSE was captured.
Params seen: 1=2150, 2=-40 (units unknown), 7=123456.
