# visage

A **compact email alias & forwarding server** written in C11 — give out disposable
`alias@domain` addresses that forward to your real inbox, and reply through them too. The whole
service — daemon *and* alias store — fits in a single small, portable [APE](https://github.com/jart/cosmopolitan)
binary, configured in [typechecked Dhall](https://dhall-lang.org/). The same C core also builds to
**WebAssembly** and runs fully client-side in your browser.

> ▶ **Try it live — https://jmars.github.io/visage/** (edit a Dhall config and resolve aliases in the
> browser, powered by the real C pipeline compiled to wasm)

## What it is

A single self-contained SMTP daemon that accepts mail for the domains it serves, resolves each
recipient against a **DAFSA alias store**, and forwards accepted mail to your mailbox provider. You
never give out your real address — only disposable aliases, and replies are routed back through a
`reply+<token>@yourdomain` reverse alias.

## Compact by design

Two things stay small as you grow.

**The server.** One C codebase → one `visage.com` APE binary (≈2.6&nbsp;MB) that runs on many OSes
with no VM, runtime, or database process. No framework, no interpreter for the hot path — just the
mail router and its store.

**The data store.** Aliases live in a [datalog-dafsa](https://github.com/jmars/datalog-dafsa) store
built on a *minimal acyclic DAFSA* — a graph that shares common prefixes **and** suffixes across every
key, so the store stays tiny even as you add thousands of aliases. Strings are interned to 32-bit
symbol ids; each relation is one on-disk DAFSA that is mmap'd for read-only serving and durably
WAL'd (single-writer, `flock`).

**Measured** (`dhake bench`): on-disk store size is ~480 B/alias at 1,000 aliases and ~542 B/alias at
1,000,000 — roughly **constant across three decades**, with no per-alias index bloat. The footprint
is dominated by the string interner (every distinct address stored once), not per-alias metadata.
See `docs/bench-size.svg`.

## Prefix search, not indexes

Email routing needs exactly two lookups, and both are native DAFSA primitives — so visage carries
**no separate index**, and lookup cost scales with the address length, not the alias count:

- Every fact is one fixed-width big-endian key; *bind the leading columns to constants and enumerate
  the rest* is exactly a byte-prefix walk on the DAFSA.
- **Forward routing** — resolving `alias@domain` → its destinations is a prefix walk binding the
  `(domain, local)` columns of the `alias` relation.
- **Reverse reply routing** — `reply+<token>@domain` → (original sender, alias) is a prefix walk
  binding the `token` column of the `revmap` relation.

Prefix enumeration is the DAFSA's second-strongest primitive (after exact-key lookup), so alias
resolution and reply-token routing are O(prefix length) regardless of how many aliases exist.

**Measured** (`dhake bench`): warm `store_resolve`/`store_revmap_resolve` latency is ~0.6 µs at 1,000
aliases and ~3 µs at 1,000,000 — **sub-linear** (≈5× over three decades of scale), i.e. the cost
tracks address length, not alias count. See `docs/bench-latency.svg`.

## Security posture

The wire path is hand-rolled C11, so the hardening is explicit. visage was given a deep
wire-path security review before public launch (3 HIGH + 4 MEDIUM findings, all fixed, no
CRITICAL). Where it stands:

- **Wire memory safety** — bounded per-connection buffers on the SMTP and admin paths; a
  reply-backlog cap (`SMTP_IN_MAX_OUT` 256&nbsp;KB) + TCP backpressure so a never-reading client
  can't exhaust memory; hard command-length limits.
- **Reply tokens** — 32 hex chars from `/dev/urandom`, **no weak fallback** (fail-closed), expiring
  after 30 days. Tokens are the reply feature's only credential.
- **Admin API** — constant-time bearer-token comparison; `config-check` rejects tokens that can
  never authenticate (>500 chars) and warns on weak defaults.
- **Anti-injection** — MAIL FROM and RCPT are validated (printable ASCII, no quote/angle chars) so
  forwarded headers can't be broken; no SMTP-envelope CRLF injection to the relay; mail containing
  NUL/control bytes is rejected (`554`) rather than silently forwarded.
- **Relay integrity** — `starttls-verify` does mandatory STARTTLS with CA + hostname verification
  and never falls back to plaintext or sends AUTH over it; `starttls` is documented as
  anti-passive-snooping only.
- **Availability** — inbound SMTP is rate-bounded (512 conns global / 16 per-IP, `421` on excess);
  queue-driven relay sends are batched (8/tick) so a slow relay can't stall the event loop; null
  reverse-path mail is preserved end-to-end (`MAIL FROM:<>`) so DSN bounce loops can't ping-pong.
- **Browser demo** — remote `http://` Dhall imports are **compiled out** of the wasm build, so a
  pasted config can't make your browser probe URLs.

## Stack

| Piece | Role |
| --- | --- |
| [cosmocc](https://github.com/jart/cosmopolitan) | one small `visage.com` APE binary, many OSes |
| [dhall-c](https://github.com/jmars/dhall-c) | **typechecked** Dhall config, evaluated at startup (vendored submodule) |
| [datalog-dafsa](https://github.com/jmars/datalog-dafsa) | compact minimal-DAFSA store: prefix-search lookups, WAL/flock + mmap reads (vendored submodule) |
| SMTP-in-C (`src/smtp_in.c`, `src/smtp_out.c`) | RFC 5321 state machine, receiver + relay |
| STARTTLS / STARTTLS-verify (`vendor/mbedtls`) | relay to your mailbox provider, optionally cert-verified |
| DKIM (`src/dkim.c`) | sign outbound mail from C |
| durable outbound retry queue | spooled to disk, bounded retries, no lost mail |
| emscripten | the same C core → `docs/visage.wasm` (client-side demo) |

## Build

Requires `cosmocc`. `dhall-c`, `datalog-dafsa`, `dhake`, `design` and `mfe-framework` are
vendored as git submodules; mbedTLS is vendored under `vendor/`. Every build target is driven
by **dhake** (no Make), with **hash-verified builds** — each output pins its expected sha256
(`hash`) and every input source pins its sha256 (`depsHash`), so a tampered or drifted artifact
fails the build.

```sh
git submodule update --init --recursive   # first checkout: fetch all vendored submodules
./vendor/dhake/dhake.com                  # default target `all`: visage.com + all *_check tools + tests + wasm
./vendor/dhake/dhake.com visage.com       # build one binary
./vendor/dhake/dhake.com e2e              # host integration tests (tests/run.sh)
./vendor/dhake/dhake.com bench            # store benchmark + docs/bench-*.svg
./vendor/dhake/dhake.com dist/index.html  # the Elm MFE docs site
./vendor/dhake/dhake.com --verify         # CI pre-flight: check pinned hashes + up-to-dateness
./vendor/dhake/dhake.com --list           # list all targets
```

To use sibling `dhall-c`/`datalog-dafsa` checkouts instead of the submodules, point
`scripts/build-wasm.sh` at them with `DHALL_C` (the C build reads them from `vendor/`).

For the browser build (needs `emscripten clang lld llvm nodejs`):

```sh
./vendor/dhake/dhake.com wasm             # → docs/visage.js + docs/visage.wasm, then runs the wasm smoke test
```

When a pinned hash goes stale (source or toolchain changed), rebuild with
`./vendor/dhake/dhake.com --warn-hash-mismatch TARGET` to print the new hashes, then regenerate
`Dhakefile.dhall` with `python3 tools/gen_dhakefile.py` (committed generator that recomputes all
pins from the built artifacts) and commit.

## Usage

```sh
./visage.com daemon -c config.example.dhall

./visage.com config-check -c FILE          # validate config and exit
./visage.com add-alias -c FILE --alias A@D --dest X@Y
./visage.com rm-alias  -c FILE --alias A@D --dest X@Y
./visage.com log -c FILE [-n N]            # recent log entries via the daemon
```

## Config format

The config is a Dhall record — aliases, domains, relay, limits, storage, DKIM keys — typechecked
against its schema before the daemon binds a port. See `config.example.dhall` for a complete example.

```dhall
{ hostname = "mx.example.com"
, domains = [ "example.com" ]
, listen = { address = "0.0.0.0", port = 2525 }
, relay = { host = "127.0.0.1", port = 2526, tls = "starttls-verify", … }
, catch_all = ""
, aliases = [ { alias = "jane@example.com",     destinations = [ "jane@realmail.example" ] }
            , { alias = "shopping@example.com", destinations = [ "jane@realmail.example", "bob@realmail.example" ] }
            ]
, …
} : Config
```

`relay.tls` is `none`, `starttls`, or `starttls-verify` (an empty `tls_ca` uses the embedded Mozilla
CA bundle).
