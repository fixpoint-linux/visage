# visage

A **SimpleLogin-style email alias & forwarding service** written in C11 — give out disposable
`alias@domain` addresses that forward to your real inbox, and reply through them too. Configured in
[typechecked Dhall](https://dhall-lang.org/), compiled with [cosmocc](https://github.com/jart/cosmopolitan)
into a single portable APE binary. The same core also builds to **WebAssembly** and runs fully
client-side in your browser.

> ▶ **Try it live — https://jmars.github.io/visage/** (edit a Dhall config and resolve aliases in the
> browser, powered by the real C pipeline compiled to wasm)

## What it is

A single self-contained SMTP daemon that accepts mail for the domains it serves, resolves each
recipient against an alias store, and forwards accepted mail to your mailbox provider. You never give
out your real address — only disposable aliases, and replies are routed back through a
`reply+<token>@yourdomain` reverse alias.

## Stack

| Piece | Role |
| --- | --- |
| [cosmocc](https://github.com/jart/cosmopolitan) | one `visage.com` APE binary, many OSes |
| [dhall-c](https://github.com/jmars/dhall-c) | **typechecked** Dhall config, evaluated at startup |
| [datalog-dafsa](https://github.com/jmars/datalog-dafsa) | persistent, fast-lookup DAFSA alias store (WAL/flock) |
| SMTP-in-C (`src/smtp_in.c`, `src/smtp_out.c`) | RFC 5321 state machine, receiver + relay |
| STARTTLS / STARTTLS-verify (`vendor/mbedtls`) | relay to your mailbox provider, optionally cert-verified |
| DKIM (`src/dkim.c`) | sign outbound mail from C |
| durable outbound retry queue | spooled to disk, bounded retries, no lost mail |
| emscripten | the same C core → `docs/visage.wasm` (client-side demo) |

## Build

Requires `cosmocc`. The `dhall-c` interpreter core and `datalog-dafsa` store are siblings at
`../dhall-c` and `../datalog-dafsa`; mbedTLS is vendored under `vendor/`.

```sh
make            # builds visage.com (APE) + visage.com.dbg (ELF) + all *_check tools
```

For the browser build (needs `emscripten clang lld llvm nodejs`):

```sh
make wasm                # → docs/visage.js + docs/visage.wasm
node tests/wasm-smoke.js # headless smoke test of the wasm module
```

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
, relay = { host = "127.0.0.1", port = 2526, tls = "none", … }
, catch_all = ""
, aliases = [ { alias = "jane@example.com",     destinations = [ "jane@realmail.example" ] }
            , { alias = "shopping@example.com", destinations = [ "jane@realmail.example", "bob@realmail.example" ] }
            ]
, …
} : Config
```

`relay.tls` is `none`, `starttls`, or `starttls-verify` (an empty `tls_ca` uses the embedded Mozilla
CA bundle).
