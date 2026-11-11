---
title: "ADR-0003 — Module protocol secmonk-wire/1: length-framed JSON, JSON Schema as IDL"
summary: "secmonk-wire/1: 4-byte length-framed JSON over stdio, JSON Schema as IDL, symmetric requests, streaming, cancel and notify; NDJSON, gRPC and CBOR rejected for now."
read_when: you implement the module protocol, consider another encoding (gRPC, CBOR, NDJSON), or add a method
type: decision
context: decisions
status: accepted
tags: [protocol, modules, contracts, decision]
updated: 2026-11-11
verified: 2026-11-11
related: [tech/contracts.md, decisions/0002-rust-core-python-modules.md]
---

# ADR-0003 — Module protocol secmonk-wire/1

## Context

The proposal (§4.2–4.3) compared gRPC, Connect, Cap'n Proto and a JSON envelope over framed streams and recommended the
latter: the UI, CLI, mocks and fixtures already consume JSON; the probe must work over non-HTTP streams (SSH stdio);
calls must flow both ways. The prototype needs it for Python child processes first.

## Decision

- Frame = 4-byte big-endian length + one UTF-8 JSON object; hard cap 64 MiB, default `max_frame` 16 MiB announced
  in `hello`; bulk data streamed in chunks. The W1.2 spike (2026-11-11) ran this framing between Rust and a
  uv-launched Python worker: spawn to first reply 65 ms, warm calls in microseconds.
- Messages `hello`, `req`, `res`, `err`, `event`, `end`, `progress`, `cancel`, `notify` with the fields of
  [contracts (a)](../tech/contracts.md#a-module-protocol-secmonk-wire1); errors reuse the `{error, hint, code}` shape.
- Version `secmonk-wire/1.0`: major must match, minors additive; codec negotiated in `hello` (`json` only now).
- IDL = JSON Schema (draft 2020-12) in `rust/contracts/schemas/` + the method and route catalogs; Rust types are checked
  against them in tests (`schemars` export compared to the files **(verify)**).
- On stdio: stdout carries frames only (the Python server dups fd 1 to a private descriptor and re-points fd 1 and
  `sys.stdout` to stderr; proven by the spike), stderr carries logs forwarded line by line, EOF on stdin ends the module.
- The server lives in `rust/python` (`secmonk_modules`); a `secmonk.rpc` module inside the Python package is a later
  option (the spike suggested it; `src/` stays untouched for now).

Rejected now: NDJSON (fragile against stray output, no size limit before parse), gRPC as IDL (remodels payloads, needs
HTTP/2 over stdio), CBOR/protobuf (no measured need).

## Consequences

- A small session layer (~1–1.5k lines) on each side; the same one serves SSH/TLS transports later.
- Payloads stay identical to the CLI/web JSON, so goldens and the design mock are reusable as test data.
- Throughput of the mirror row stream through JSON must be measured on a full OSV sync **(verify)**; a compressed codec
  is the planned answer if needed.

## Implementation notes (2026-11-11, W2.1)

- `secmonk-proto`: `Message` enum (tag `type`, unknown fields ignored), `ErrorCode` (19 codes + `Other` for codes of
  a newer peer), `WireError` (80 bytes: `data` boxed, below `clippy::result_large_err`), manifest types, and the codec
  as `tokio_util::codec` Decoder/Encoder (`FrameCodec`, `MessageCodec`). The codec makes `secmonk-proto` depend on
  `tokio-util` + `bytes` behind the default feature `codec` (byte buffers only, no runtime, no I/O); the
  architecture rule "no tokio in proto" holds with `--no-default-features`.
- An oversized length is refused from the 4-byte header (the body is never buffered); a stream that ends inside a
  frame is `Truncated`; invalid UTF-8, JSON, type, id or method name are `protocol-error`. Fuzz-style tests: random
  chunking, every truncation point, 2000 random byte strings.
- Every contract example round-trips through the Rust types. The `schemars` export comparison of the IDL is not
  done **(verify)**.

## Implementation notes (2026-11-11, W3.4: review fixes)

- `hello.provides` accepts unknown keys, like `hello` itself: minors are additive. `Provides` is no longer
  `deny_unknown_fields`, the envelope schema no longer closes `hello.provides`, and `Message::from_slice` logs the
  unknown keys at debug (`secmonk_proto::message::unknown_fields`). A manifest's `provides` stays closed: a typo in a
  local file is an error (`manifest.schema.json`, `Manifest` deserializes it strictly).
- Python server: the in-flight slot is freed **before** the final `res` / `end` / `err` frame is written, so a host
  that sends its next call on reading the answer never gets `busy` with `max_inflight = 1`.

## Implementation notes (2026-11-11, W4.2)

- Still open: the throughput measurement of the row stream on a full OSV sync and the `schemars` comparison
  ([backlog](../plans/backlog.md)).
- `hello.session.grants` stays strict (unknown keys refused, `Grants` in `secmonk-proto`), unlike the rest of `hello`;
  relax it with the first second grant (backlog).
