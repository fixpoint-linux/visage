# visage roadmap

Deferred items and follow-ups beyond the initial MVP. Ordered roughly by
value-to-effort. MVP = engine + mail loop + reverse-alias reply routing,
SMTP in C, CLI + minimal HTTP admin, single cosmocc APE.

Legend: **P** = privacy/security, **R** = reliability, **F** = feature/interop, **A** = architecture.

> Status (2026-08-16): **all actionable roadmap items are now DONE.** The two
> original "## Next up" items (durable outbound retry queue + STARTTLS relay)
> shipped in 5963187; `starttls-verify` in the S-B4 commit; then the remaining
> hardening/arch/storage/feature items each landed in their own commit
> (4f192c5, 495bad4, 3fa75af, 0ee6fe3, 3fc72b6, 60c8a76, 437c35a, 484d9d7,
> d8ffaed). Only the "Out of scope / long-term" items remain, which are
> deliberate architectural deferrals (see below).

---

## Next up

- ~~**[R] Durable outbound retry queue.**~~ **DONE (2026-08-16, commit 5963187).**
  At-least-once durable queue: sanitize-once + spool `<msgid>.<k>.out.eml`
  (fsync) before `store_queue_add`; re-drive at startup + in-loop poll
  deadline; backoff 1s..1h, `relay.max_attempts`; crash-safe add-first
  transitions (no loss window); `250 OK: queued` on durable accept, `451`
  on enqueue failure. Host e2e covers outage→re-drive + restart persistence.
- ~~**[P] STARTTLS on the outbound relay.**~~ **DONE (2026-08-16, commit 5963187).**
  Vendored mbedTLS 3.6.7 (`vendor/mbedtls`, custom
  `src/mbedtls_visage_config.h`, TLS1.2 subset); `relay.tls` in
  `{none, starttls}`; opportunistic `VERIFY_NONE` + SNI; never sends AUTH
  over plaintext (D2 rule); `tests/tls_selfcheck.com` in-sandbox gate.
  Follow-up: `starttls-verify` (real CA verification) = S-B4 below.

## Security / correctness hardening

- ~~**[P] `starttls-verify` (real relay cert verification).**~~ **DONE
  (2026-08-16).** `relay.tls = "starttls-verify"` = mandatory STARTTLS +
  `VERIFY_REQUIRED` + hostname check (SAN/CN), trust anchors from an embedded
  Mozilla CA bundle (default) or a `relay.tls_ca` PEM file. Fail-closed: a bad
  cert → `SMTP_PERMFAIL` (never plaintext fallback, never AUTH-over-plaintext,
  never retried); transport errors → `SMTP_TEMPFAIL` (queue re-drives).
  Embedded bundle refreshed via `tools/gen_cacert.sh` + `src/data/cacert.pem`
  (quarterly policy). `tests/verify_selfcheck.com` is the in-sandbox gate
  (good/hostname-mismatch/wrong-CA/embedded-bundle).
- ~~**[F] Validate the MAIL FROM reverse-path as an addr-spec**~~ **DONE (4f192c5).**
  Reject `"` `<` `>` in the reverse-path so `reply_from_rewrite`'s quoted
  display-name can't be broken into a malformed `From:`.
- ~~**[F] Hard-enforce the command-line length cap.**~~ **DONE (495bad4).**
  Enforce `max_line` in the newline-terminated branch too (was only checked
  when no `\n` was buffered), so every command line is hard-capped.
- ~~**[P] Two-step `AUTH PLAIN` (334 challenge) on the relay.**~~ **DONE (3fa75af).**
  On a `334` reply send the base64 blob standalone; extracted `smtp_auth_class`.
- ~~**[P] Pre-launch deep security review + fixes.**~~ **DONE (2026-08-16, commits
  c11ea7b + 9865d0d).** A deep wire-path review before public launch returned 3 HIGH +
  4 MEDIUM (no CRITICAL); all fixed across two commits:
  - **c11ea7b** — per-conn reply-backlog cap (`SMTP_IN_MAX_OUT` 256&nbsp;KB) + `POLLIN`
    backpressure (unauthenticated memory-exhaustion DoS); one-shot `relay.retries=0` +
    redrive batch of 8 for queue sends (single-thread event-loop freeze during a relay
    outage); deleted the `prng16` fallback so reply tokens fail-closed from `/dev/urandom`
    (predictable/colliding tokens were the reply feature's only credential); `path_clean`
    on RCPT (header-injection surface via quoted-string local parts); constant-time admin
    bearer comparison; post-`DATA` pipelined bytes routed to the DATA buffer (silent mail
    loss).
  - **9865d0d** — reply-token TTL (30&nbsp;days, hourly sweep) + expired-row rejection in
    resolve; inbound conn caps (512 global / 16 per-IP, `421` on excess); admin-token
    `config-check` fails tokens >500 chars / warns on weak defaults; wasm demo remote
    `http://` imports disabled (stub, so no SSRF from visitor browsers); NUL/control-byte
    rejection (`554`, 8-bit preserved); null reverse-path preserved end-to-end
    (`MAIL FROM:<>`) to break DSN bounce loops.

## Non-blocking admin HTTP

- ~~**[A] Replace the blocking admin HTTP serving.**~~ **DONE (0ee6fe3).**
  Per-connection non-blocking HTTP state machine multiplexed into the shared
  SMTP poll loop; a trickling admin client can no longer stall SMTP delivery.

## Storage / scale

- ~~**[R] Message-id wrap.**~~ **DONE (3fc72b6).** Fail closed with `451` on
  msgid allocation failure (instead of proceeding with a colliding msgid 0).
  A wider counter is a DAFSA u32-BE schema change, deferred; the S3 monotonic
  fix already prevents reuse below 2³².
- ~~**[A] Case-insensitive alias/domain matching.**~~ **DONE (60c8a76).**
  `split_addr` lowercases local+domain on the way in; destination unchanged.
- ~~**[A] Direct-writer CLI admin.**~~ **WON'T DO (by design).** The daemon owns
  the store (single-writer `flock`); CLI admin subcommands are HTTP clients to
  the daemon. A non-daemon batch tool would need a second writer path — not
  needed for the MVP, documented here.

## SMTP / email features

- ~~**[F] Broader address parsing.**~~ **DONE (437c35a).** `mail_addr_parse`
  accepts quoted-string local parts and domain literals per RFC 5321/5322;
  quoted-local aliases round-trip through the store.
- ~~**[F] MIME awareness / DKIM signing.**~~ **DONE (d8ffaed).** Forwards are
  now DKIM-signed (`a=rsa-sha256`, `c=relaxed/relaxed`, per-domain
  `{domain,selector,private_key}` config, default off) so they pass
  destination deliverability checks. Full MIME re-encoding/attachments
  remain out of scope (body is preserved verbatim).
- ~~**[F] RFC 5322 groups in To/Cc stripping.**~~ **DONE (484d9d7).**
  `addr_list_strip` is group-aware (recursive, arbitrary nesting), so the
  reverse-alias is stripped from group members while the group syntax is
  preserved.

## JMAP server (`jmapd`)

- ~~**[F] A JMAP (RFC 8620/8621) front end on the same maildir store.**~~
  **DONE (2026-10-22, milestones M1–M5).** `jmapd.com` is a single-process
  `poll()` daemon in the imapd shape: same maildir root, same `imapd.passwd`,
  HTTPS from the first byte (imapd's mbedTLS wrappers, plaintext only on a
  loopback bind), bounded JSON/HTTP parsers, and no link against the datalog
  store or Dhall. It answers `Mailbox/get`, `Identity/get`, `Email/query`,
  `Email/get` (bodies, bodyStructure, attachments, decoded blob download),
  `Email/set` (keywords, mailboxIds, create/destroy, `ifInState`), `Thread/get`
  and `EmailSubmission/set` (relayed to the outbox, which owns DKIM/DMARC).
  Accepted end to end by the real `mail-hub` client (`tests/jmapd_hub.sh`).
  Docs: `docs/jmapd.md`; deployment: `deploy/` (systemd unit, submission
  credential env file, Caddy snippet) and the jmapd stanza in
  `config.example.dhall`. Deferred, each named with its consequence in the docs:

  - **[F] Real `changes` / `queryChanges` diffs.** Today they answer the
    RFC-legal `cannotCalculateChanges`, so the client full-refreshes (a
    `Mailbox/get` + `Email/query` + `Email/get` **with bodies**) every 60 s.
    The per-mailbox fingerprint the state counters already compute is the
    natural basis for a real diff.
  - **[F] Push.** No EventSource `StateChange`; `eventSourceUrl` is advertised
    and `501`s, so the 60 s poll is the whole notification story.
  - **[F] Blob upload / attachments on compose.** `uploadUrl` is advertised and
    `501`s; `maxSizeAttachmentsPerEmail` is honestly `0`, and the MIME builder
    refuses attachments rather than dropping them.
  - **[F] `Mailbox/set`.** Mailboxes are the maildir folders imapd already
    uses; JMAP can read them but not create, rename or delete them.
  - **[F] Submission history.** No `EmailSubmission/get`/`changes`/`query` and
    no `undoStatus` cancellation; submissions are final when the worker starts,
    at-most-once, capped at 16 recipients, with a bounded 4096-entry ledger
    refusing a duplicate send of the same Email.
  - **[F] Broader `Email/query`.** Only `inMailbox`/`text`/`from`/`to`/`subject`
    filters and the `receivedAt` sort exist; anything else answers
    `unsupportedFilter`/`unsupportedSort` rather than returning a wrong set.
  - **[A] Trusted-proxy support (`X-Forwarded-For`).** Behind Caddy every client
    looks like `127.0.0.1`, so the per-IP lockout becomes one shared bucket.
    Fine on a single-user box; a real defect on a shared one.
  - **[A] A deferred (non-blocking) submission response.** `EmailSubmission/set`
    waits up to `--submit-wait` (5 s) for the relay's verdict so the answer is
    authoritative; that is the one place the poll loop can block, and a
    resumable method loop with a replay log is what would remove it.
  - **[R] Concurrent uidlist rewrites** by imapd and jmapd can lose the other's
    freshly registered uids. Uid churn only — JMAP ids never contain a uid — but
    an IMAP client can see uids move after a JMAP-side change.
  - **[F] RFC 2047 outside the display fields.** Subject and the display names
    of from/to/cc/bcc are decoded; attachment filenames, mailbox names and the
    preview keep their raw bytes.

## Out of scope / long-term

- **[A] Multi-writer / multi-threaded store.** Deliberately single-threaded
  (datalog single-writer `flock`). A real multi-tenant deploy needs a
  different concurrency model.
- **[A] Web UI / full admin panel.** The HTTP admin is a minimal JSON API for
  alias management; a management UI is a separate surface.
- **[A] Durable spool + replay beyond retries.** Spooled messages are written
  but only used for immediate forwarding; a general journal/replay design is
  larger than the retry-queue item above.
