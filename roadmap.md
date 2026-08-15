# visage roadmap

Deferred items and follow-ups beyond the initial MVP. Ordered roughly by
value-to-effort. MVP = engine + mail loop + reverse-alias reply routing,
SMTP in C, CLI + minimal HTTP admin, single cosmocc APE.

Legend: **P** = privacy/security, **R** = reliability, **F** = feature/interop, **A** = architecture.

---

## Next up

- **[R] Durable outbound retry queue.** The relay client retries in-memory only;
  a crash during a 4xx/relay outage loses the message. Queue spooled
  messages to disk (the `log`/spool layer already writes `<msgid>.eml`) and
  re-drive them on restart with bounded retries + backoff.
- **[P] STARTTLS on the outbound relay.** `relay.tls` is currently
  `"none"`-only; `tls != "none"` returns a hard "tls not supported" error.
  Implement STARTTLS (opportunistic) so the relay leg isn't plaintext when
  the relay supports it. Requires a TLS client in the cosmocc build.

## Security / correctness hardening

- **[F] Validate the MAIL FROM reverse-path as an addr-spec** (currently only
  `path_clean`'d). An embedded `"` breaks out of the quoted display-name into a
  malformed `From:`. No CR/LF injection today, but reject `"` `<` `>` (or run
  it through `mail_addr_parse`) so the header is always well-formed.
- **[F] Hard-enforce the command-line length cap.** The line limit is soft:
  a newline-terminated command can reach ~`SMTP_MAX_LINE + recv_chunk`
  (~5 KB) instead of the documented 1000. Bounded (not a DoS), but enforce
  the documented cap for newline-terminated lines.
- **[P] Two-step `AUTH PLAIN` (334 challenge) on the relay.** Currently only the
  single-line `AUTH PLAIN <b64>` form is sent; some relays use the
  challenge/response path. Handle both.

## Non-blocking admin HTTP

- **[A] Replace the blocking admin HTTP serving.** `http_on_readable` now
  bounds to 4 connections per poll wakeup (MVP mitigation) but still serves
  each synchronously with up-to-5 s blocking reads inside the shared SMTP
  poll loop. A trickling admin client can still stall SMTP delivery. Proper
  fix: a per-connection non-blocking HTTP state machine (mirroring
  `smtp_in.c`), so admin I/O and SMTP I/O share the loop fairly.

## Storage / scale

- **[R] Message-id wrap.** `meta.next_msgid` is a u32 counter that wraps to 0 at
  2³². Acceptable at MVP scale; move to a wider counter or a msgid
  table before that limit is reachable.
- **[A] Case-insensitive alias/domain matching.** Alias resolution is
  byte-exact; only the RCPT domain gate is case-insensitive. Lowercase on
  the way in (or an aliasing layer) so `Jane@Example.com` behaves like
  `jane@example.com`.
- **[A] Direct-writer CLI admin.** The daemon owns the store (single-writer
  `flock`); CLI admin subcommands are HTTP clients to the daemon. If a
  non-daemon batch tool is ever wanted, it needs a second writer path or a
  request channel through the daemon.

## SMTP / email features

- **[F] Broader address parsing.** `mail_addr_parse` rejects quoted-string
  local parts and domain literals (stricter than RFC 5321). Fine while
  aliases/reverse-aliases are dot-atom only; revisit if arbitrary mailbox
  addresses are routed.
- **[F] MIME awareness.** Forwarding is MIME-safe (body preserved verbatim) but
  not MIME-aware (no re-encoding, no DKIM/SPF signing, no attachment
  handling). Sign forwarded mail (DKIM) if deliverability matters.
- **[F] RFC 5322 groups in To/Cc stripping.** `reply_strip_reverse` is a
  best-effort address-list splitter (no group syntax / encoded-word display
  names). Sufficient for reverse-alias replies; extend if group recipients
  appear.

## Out of scope / long-term

- **[A] Multi-writer / multi-threaded store.** Deliberately single-threaded
  (datalog single-writer `flock`). A real multi-tenant deploy needs a
  different concurrency model.
- **[A] Web UI / full admin panel.** The HTTP admin is a minimal JSON API for
  alias management; a management UI is a separate surface.
- **[A] Durable spool + replay beyond retries.** Spooled messages are written
  but only used for immediate forwarding; a general journal/replay design is
  larger than the retry-queue item above.
