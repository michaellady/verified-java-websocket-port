# Handshake discrimination — raising the projection ceiling

STATUS: IN PROGRESS. Analysis complete, implementation under way. Nothing below
that is labelled MEASURED was asserted; nothing labelled OPEN is claimed.

## Baseline, reproduced (MEASURED)

`go run ./cmd/normcollidectl report --harness ./rust/target/release/ws-oracle-harness`
exit 0, and its census line reads:

    corpora/handshake/cases.jsonl (driven through the harness):
      49 rows -> 26 distinct scored observations; 27 rows share one; largest class 11

Same numbers as the committed `evidence/normalization-collisions/audit.json`.

## Where the 26 comes from (MEASURED)

Driving the 49 committed cases through the harness and grouping by canonical
JSON with the three identity fields stripped gives exactly four classes of
size > 1 and 22 singletons:

| size | observation | cases |
|---|---|---|
| 22 | `accept` + a distinct `sec_websocket_accept` | 22 server-side accepts |
| 11 | `reject` / `invalid_handshake` / `close_code 1002` | 0009 0010 0011 0012 0018 0031 0032 0033 0035 0036 0037 |
| 9 | `reject` / `not_matched` / `close_code 1002` | 0023 0024 0025 0026 0028 0038 0039 0040 0041 |
| 4 | `incomplete` | 0042 0043 0044 0045 |
| 3 | `accept` with NO `sec_websocket_accept` | 0006 0007 0008 |

22 + 4 = **26**. Every bit of discriminating power the exam has beyond four
buckets is carried by one key, `sec_websocket_accept`, and only on the server
side.

## What the 11-case class actually differs in (MEASURED from the case bytes)

Seven distinct corpus families and BOTH directions collapse into one row:

| case | direction | family | corpus reject_code |
|---|---|---|---|
| 0009 | client_request | method-not-get | HS_METHOD_NOT_GET (`POST`) |
| 0010 | client_request | method-not-get | HS_METHOD_NOT_GET (`PATCH`) |
| 0011 | client_request | http-version | HS_HTTP_VERSION (`HTTP/1.0`) |
| 0012 | client_request | http-version | HS_HTTP_VERSION (`HTTP/0.9`) |
| 0018 | client_request | missing-key | HS_MISSING_KEY |
| 0031 | client_request | malformed-request-line | no SP in the request line |
| 0032 | client_request | malformed-request-line | trailing ` EXTRA` token |
| 0033 | client_request | obs-fold | folded continuation line |
| 0035 | server_response | status-not-101 | `HTTP/1.1 200 OK` |
| 0036 | server_response | status-not-101 | `HTTP/1.1 404 Not Found` |
| 0037 | server_response | status-not-101 | `HTTP/1.1 301 Moved Permanently` |

(remaining sections filled in as the work lands)
