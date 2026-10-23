# jmapd — the JMAP server

`jmapd` is the JMAP front end for the visage mail stack: one single-process,
`poll()`-driven C11 daemon, in the same shape as `imapd` and `pop3d`. It serves
**the same maildir root and the same `imapd.passwd` file as `imapd`** — it is a
second protocol on one store, never a second store.

Built by dhake as `jmapd.com` (and its unit checks as `jmap_check.com`).

It exists because there is already a client: **mail-hub**, the Zig + Elm JMAP
client in the sibling checkout (`../email`; on this box
`/home/jaye/email`). That client is the acceptance surface — every method in
the list below is there because the client calls it, in the order and with the
back-references it uses. `tests/jmapd_hub.sh` builds that client and drives its
own HTTP API at `jmapd` end to end (read, flag, move, send, sync), so a
regression that only the real client would notice fails the gate.

- Source: `src/jmapd.c` (listener + poll loop), `src/jmapd_http.c` (HTTP/1.1
  state machine), `src/jmap_json.c` (bounded JSON parser), `src/jmap_core.c`
  (session document, auth, method-call loop), `src/jmap_mail.c` (Mailbox,
  Identity, Email/get, Thread), `src/jmap_query.c` (Email/query),
  `src/jmap_mime.c` (MIME walk, transfer decoding, blob download),
  `src/jmap_set.c` (Email/set), `src/jmap_state.c` (state counters + /changes),
  `src/jmapd_submit.c` (EmailSubmission/set + the outbox worker).

## What it implements

Three capabilities, advertised in the session document and required in
`using`: `urn:ietf:params:jmap:core`, `:mail`, `:submission`.

| Method | Status |
| --- | --- |
| `Mailbox/get` | yes (no `Mailbox/set`) |
| `Identity/get` | yes (no `Identity/set`) |
| `Email/query` | yes — filters `inMailbox`, `text`, `from`, `to`, `subject`; sort `receivedAt` asc/desc (the only advertised sort option); exact `total`, paged `ids` (`position` + `limit`, window capped at 8192). Any other filter condition answers the RFC-legal `unsupportedFilter` method error rather than being silently ignored, and any other sort property answers `unsupportedSort` |
| `Email/get` | yes — full property set, `bodyValues` with `fetchTextBodyValues` / `fetchHTMLBodyValues` / `maxBodyValueBytes`, `bodyStructure`, `attachments`, `preview` |
| `Email/set` | yes — `create` (drafts), `update` (RFC 8620 3.3 patch objects: `keywords/$x`, `mailboxIds/<id>`, null-deletes), `destroy`; `ifInState` enforced |
| `Thread/get` | yes |
| `Email/changes`, `Mailbox/changes`, `Thread/changes`, `Email/queryChanges` | RFC-legal `cannotCalculateChanges` — see [v1 limitations](#v1-limitations) |
| `EmailSubmission/set` | yes — `create`, `onSuccessUpdateEmail`, `onSuccessDestroyEmail` |
| `EmailSubmission/get` / `/changes` / `/query` | no (the client never calls them) |
| `Blob/upload`, EventSource push | advertised, then `501` |

Endpoints: `GET /.well-known/jmap` (also `/jmap/session`) returns the session
document; `POST /api` is the method-call loop; `GET
/download/{accountId}/{blobId}/{name}` streams one **decoded** message part;
`/upload/{accountId}/` and `/event/` answer `501`.

### Scope cut for v1

Deliberately not implemented, and each omission's consequence for the client:

- **No `Blob/upload`.** `uploadUrl` is advertised (the client parses it) and the
  endpoint answers `501`. The client sends no attachments, so this is inert
  today; `maxSizeAttachmentsPerEmail` is advertised as `0` rather than lying
  with a non-zero number the server would refuse.
- **No EventSource push.** `eventSourceUrl` is advertised and `501`s. The client
  polls `/api/sync` every 60 s instead.
- **No `Mailbox/set`.** The client never creates or renames a mailbox. The role
  mailboxes `Inbox`, `Sent`, `Drafts`, `Trash`, `Junk` exist as the maildir
  folders imapd already uses, and any other dot-folder is listed as an ordinary
  mailbox.
- **No real `changes` / `queryChanges`.** `cannotCalculateChanges` — see below.
- **No Vacation/sieve, no quota, no `SearchSnippet`.**
- **One account per credential.** A passwd line is an account; there is no
  shared account and no account without a passwd line.
- **No attachments on compose.** The MIME builder refuses them rather than
  silently dropping them.

## Ids and state

Every id is a prefix plus base64url (unpadded), and every decoder is strict:
the wrong prefix, a non-base64url byte, a decoded `/`, `\`, NUL, control byte,
`.`, `..`, an oversized decode or an out-of-range part path is **rejected
before anything is opened**. An id is never a path.

| Type | Shape | What it encodes |
| --- | --- | --- |
| `accountId` | the passwd username | `alice` |
| Mailbox | `m` + b64url(name) | the maildir folder name (`Inbox`, `.Sent` → `Sent`) |
| Email | `e` + b64url(base) | the maildir **base name** — stable across flag renames, across moves (a rename keeps the base) and across uidlist rebuilds (uids never appear in an id) |
| Email (duplicate) | `f` + b64url(mbox NUL base) | the second and later copies of one base name, which only an IMAP `COPY` can create; such a copy's id changes if it is moved (the client cannot create one) |
| Thread | `t` + b64url(root Message-ID) | resolved by walking `In-Reply-To`/`References` through the uidlist's persisted Message-IDs, depth-capped, falling back to the message's own id |
| Blob | `g` + b64(email id) + `.` + b64(part path) | one part of one message; the part path is dotted decimal (`1`, `2.1`) |
| Identity | `i` + b64url(user) | the account's own identity |

**State strings are opaque**, so what they mean is this server's business: one
monotone counter per type, persisted in `<root>/<user>/jmapd-state`
(tmp + rename). `e<n>`, `m<n>`, `t<n>`, `i0`, `s<n>`. A counter is bumped by
(a) a commit `jmapd` itself makes and (b) **a request that observes the maildir
has moved under it** — per mailbox, the `new/`+`cur/` entry counts plus the
uidlist sidecar's `(mtime, size)`. That fingerprint is what makes the state
honest in a tree two daemons write: an `imapd` delivery, another client's flag
change or a delete moves the fingerprint, so `ifInState` cannot silently
succeed against a stale view. Cost is one `readdir` + two `stat`s per mailbox,
which is less than the per-mailbox scan the read methods already do.

`ifInState` mismatch answers the RFC-legal `stateMismatch` error inside that
method's response (`Email/set`, `EmailSubmission/set`), and `Email/set` answers
`oldState`/`newState` so a client can tell what moved.

## Auth model

- **Basic** carries the user and password, checked against
  `<root>/imapd.passwd` (the same file `imapd passwd USER PASS --root <root>`
  writes; the same credential as IMAP, on purpose — one password per person).
- **Bearer** carries only a token; the account is whichever passwd entry the
  token matches, compared in constant time per candidate. That is what the
  mail-hub client uses when it stores a password as a token.
- Failed attempts charge the per-IP lockout shared with imapd's table:
  **5 failures in 60 s → 300 s locked out**, cleared on success. Every request
  is authenticated on its own; there are no cookies and no session tokens.
- `accountId` in a method call must name this credential's account, or the call
  is refused — one credential cannot address another account.

## Security posture

- **HTTPS from the first byte.** `jmapd` does implicit TLS (never STARTTLS), so
  the `Authorization` header is inside the TLS session from the first request.
  It reuses `imapd_tls.c` — the same mbedTLS server wrappers and the same
  certificate pair as `imapd`.
- **Plaintext only on loopback, and refused otherwise.** A non-loopback bind
  without `--cert`/`--key` exits 1 at startup: JMAP carries the password in a
  header, so serving it in clear over a network is not a supported mode. The
  loopback plaintext mode is the dev mode (and what `tests/jmapd_*.sh` use); the
  mail-hub client's own URL policy accepts `http://` only for loopback hosts, so
  the two agree by construction.
- **A cert without a key, or a pair mbedTLS cannot parse, fails closed** at
  startup rather than degrading to plaintext.
- **No path from an id to the filesystem without revalidation.** Ids decode to a
  single maildir component and are re-checked as components; a blob id's email
  half is re-parsed before the part path is used; part paths are strict dotted
  decimal with no leading zeros, bounded depth and bounded value. Traversal
  payloads (`g` + b64(`../../etc/passwd`) + …) answer `404`, and
  `tests/jmapd_read.sh` sends exactly that.
- **Bounded everything.** 4 MiB request cap (`--max-request`), 16 MiB response
  cap, 256 KiB per-connection output backlog with `POLLIN` backpressure, 512
  connections / 16 per IP, 100 requests per keep-alive connection, JSON depth
  cap 32, 32 calls and 256 objects per request, 16 recipients and an 8-job /
  8 MiB submission queue (the 8 MiB is the send limit for ONE message — the
  whole message is resident while the worker runs, so anything larger is
  refused `tooLarge`, not "queue full"), 4096-entry submitted ledger, 64 MiB
  per streamed blob.
- **No datalog store, no Dhall.** `jmapd` links the maildir store, the TLS
  wrappers, the JSON writer and the SMTP client — never `store.c`. The single
  writer of the datalog store is untouched, so adding JMAP cannot corrupt the
  alias store.
- **Submission is delegated, not duplicated.** `jmapd` hands each submission to
  the outbox over authenticated SMTP; DKIM signing and DMARC/DNS policy live
  there, so there is one signing path in the stack, not two. The cost is
  at-most-once: an accepted submission is not re-driven by `jmapd` (the outbox
  owns retries), and a submission whose relay verdict misses the `--submit-wait`
  window is reported `created` with the failure logged — "accepted is not
  delivered", RFC 8621 7.5.
- **Four submission outcomes, each logged distinctly.** `delivered` (the relay
  accepted: `created`, filed in Sent with `$seen`, ledgered), `refused` (a
  refusal inside the window: `notCreated`, nothing sent, the draft stays in
  Drafts and is resubmittable), `accepted-without-verdict` (`--submit-wait`
  elapsed: `created`, filed in Sent with `$seen` **and** ledgered while
  delivery is still unknown), and `duplicate-refused` (already in the ledger:
  `notCreated`/`forbidden`, nothing sent). `--submit-wait 0` means wait for
  nothing: the response is `created` at once and the verdict is only logged.
  The consequence of `accepted-without-verdict` is named rather than hidden: a
  verdict that arrives late is logged as "late worker verdict lost", and if it
  is a **refusal** the message is marked sent, was never delivered, and is
  refused on any resubmission until 4096 newer ids evict the ledger entry.
  That is the price of at-most-once — deferring the Sent filing until the
  verdict would leave a delivered message looking like a draft, and ledgering
  only on a confirmed acceptance would allow a duplicate send after a
  timeout-then-success.

## Running it

```
jmapd [options]
  --root DIR           maildir root (JMAPD_ROOT, default ./var/mail; use imapd's)
  --addr ADDR          bind address (JMAPD_ADDR, default 127.0.0.1)
  --port N             bind port (JMAPD_PORT, default 8081)
  --cert/--key PATH    PEM pair: enables HTTPS from the first byte
  --hostname H         host used in the advertised URLs (JMAPD_HOSTNAME)
  --public-url URL     base URL advertised verbatim in the session document
                       (JMAPD_PUBLIC_URL, e.g. https://jmap.jaye.ch); empty =
                       derive from --cert/--hostname/--port
  --identity ADDRESS   the account's own address (JMAPD_IDENTITY,
                       default <user>@<hostname>)
  --max-request BYTES  request cap (JMAPD_MAX_REQ, default 4 MiB)
  --timeout SECONDS    idle timeout (JMAPD_TMO, default 300)
  --outbox-host/--outbox-port   submission relay (default 127.0.0.1:465)
  --outbox-user/--outbox-pass   submission AUTH PLAIN credential
  --outbox-tls MODE    implicit (default), starttls, starttls-verify, none
  --submit-wait MS     how long a submission waits for the verdict (5000;
                       0 = answer created at once and only log the verdict)
```

Deployment artifacts live in `deploy/`:

- `deploy/jmapd.service` — systemd unit: `User=imapd`, `ProtectSystem=strict`
  with `ReadWritePaths=/opt/imapd/var/mail` as the only writable path,
  `NoNewPrivileges`, `ProtectHome`, `PrivateTmp`/`PrivateDevices`, `UMask=0077`,
  `MemoryHigh`/`MemoryMax`, `Restart=on-failure`, journal output. It binds
  `127.0.0.1:8788` and passes `--root /opt/imapd/var/mail` (the same maildir as
  imapd), `--public-url https://jmap.jaye.ch` (see the reverse-proxy section),
  `--identity <user>@mail.jaye.ch`, and `--outbox-host 127.0.0.1
  --outbox-port 465`.
- `deploy/jmapd-outbox.env.example` — the submission credential as an
  `EnvironmentFile` (`/etc/jmapd/outbox.env`, 0600): a unit file is
  world-readable, so the password does not live in it.
- `deploy/Caddyfile.jmap` — `https://jmap.jaye.ch` → `127.0.0.1:8788`, with the
  note that `jmapd` can also terminate TLS itself with `--cert`/`--key` (the
  imapd certificate) instead, and that the proxied unit must set
  `--public-url`.

### Behind a TLS-terminating reverse proxy

`jmapd` derives the four URLs in the session document from the listener it is
bound to: `https` when `--cert`/`--key` are set, else `http`, plus `--hostname`
and `--port`. That is the right answer when `jmapd` itself terminates TLS, and
the wrong one when a proxy does: the listener is plaintext on
`127.0.0.1:8788`, which no client can reach, so the document would advertise
`http://127.0.0.1:8788/api` and every method call after the session fetch would
go nowhere.

`--public-url` (or `JMAPD_PUBLIC_URL`) replaces that derivation: the value is
advertised **verbatim** as the base of `apiUrl`, `uploadUrl`, `downloadUrl` and
`eventSourceUrl`, and the download template keeps its
`{accountId}/{blobId}/{name}` placeholders.

```
--addr 127.0.0.1 --port 8788 --public-url https://jmap.jaye.ch
```

Validation is at startup and fails closed, naming the flag:

- the scheme must be `http` or `https`, and a host must be present;
- no userinfo (`user@host`), no query string, no fragment; printable ASCII
  without spaces only; the value is capped at 384 bytes;
- a trailing `/` is stripped (so the joined suffixes never double up); a path
  suffix is allowed and preserved — `https://host/jmap` advertises
  `https://host/jmap/api` and `https://host/jmap/download/{...}`;
- an **`http://` value is refused unless the bind address is loopback** — the
  same rule the plaintext listener is held to, and the same reason: the client
  would be told to send the password in clear across a network.

An empty value means "no override", which is the pre-existing behaviour.

**Two deployment caveats worth knowing before you point Caddy at it.** Both are
consequences of the design, not defects, and neither is fixed in v1:

1. Behind a reverse proxy `jmapd` sees every client as `127.0.0.1`, and its
   per-IP lockout is keyed on the TCP peer address (it reads no
   `X-Forwarded-For`, and has no trusted-proxy setting). All clients then share
   one lockout bucket: five bad passwords from anyone lock everybody out for
   five minutes. On a single-user box that is a non-issue; on a shared one,
   terminate TLS in `jmapd` itself.
2. `imapd` and `jmapd` both write the maildir tree. `jmapd` caches nothing
   across requests, so it never serves a stale mailbox, but concurrent uidlist
   sidecar rewrites can lose the other daemon's freshly registered uids. That
   costs uid churn only — JMAP ids never contain a uid — but an IMAP client may
   see `UIDVALIDITY`/uid numbers move after a JMAP-side change.

## v1 limitations

Named, because a client acts on them:

- **`cannotCalculateChanges`** on `Email/changes`, `Mailbox/changes`,
  `Thread/changes` and `Email/queryChanges`: there is no per-object change log
  to diff against, and an invented diff is worse than an honest refusal. The
  mail-hub client's response is a **full refresh**, and since it polls
  `/api/sync` every 60 s, that means a `Mailbox/get` + `Email/query` +
  `Email/get` **with bodies** every 60 s. Fine for a personal mailbox on a LAN,
  wasteful on a large one; real diffs are the natural v1.1.
- **No push.** No EventSource, no `StateChange` — the 60 s poll is the whole
  notification story.
- **No upload**, so no attachments on compose.
- **One mailbox per Email.** The store is a maildir with a single folder per
  message, so `mailboxIds` replace is a move, and a patch that removes the
  mailbox a message is in while adding another is applied as a move.
- **No `Mailbox/set`, no `Identity/set`.** Identities come from the passwd file
  and cannot be deleted or edited over JMAP.
- **Submission is at-most-once and bounded.** 16 recipients per submission, a
  message over the 8 MiB send limit is refused `tooLarge` before it is queued, a
  second submission of the same Email is refused (`notCreated`, `forbidden`) —
  the ledger that makes that true is bounded to 4096 ids, oldest dropped. A
  partial RCPT acceptance is reported `created` (it cannot be un-sent) with each
  refusal logged.
- **No submission history.** `EmailSubmission/get` and friends are absent, and
  `undoStatus` cancellation is not supported: every submission is final the
  moment the worker starts.
- **No RFC 2047 decoding outside the display fields.** `Subject` and the display
  names of `from`/`to`/`cc`/`bcc` are decoded; attachment filenames, mailbox
  names and the preview keep their raw bytes.
- **No re-encoding on send.** The submitted copy is the maildir bytes with
  `Bcc` removed — no `Date`/`Message-ID` fixup, no charset conversion.
- **Charset passthrough.** `bodyValues` are transfer-decoded but not
  transcoded, and an unknown `Content-Transfer-Encoding` sets
  `isEncodingProblem` rather than being guessed at.

## Gates

Unit checks (pure, no sockets) and five host end-to-end scripts. The end-to-end
scripts need live sockets; run them on the host, not in a sandbox.

```sh
# build (a stale pin only warns locally; see the regen flow below)
./vendor/dhake/dhake.com --warn-hash-mismatch jmapd.com
./vendor/dhake/dhake.com --warn-hash-mismatch jmap_check.com

./jmap_check.com                # JSON battery, id codec, MIME, patch, state, session

./tests/jmapd_basic.sh          # session doc, Mailbox/get, Identity/get, auth,
                                # lockout, keep-alive, 413/404/405/501
./tests/jmapd_read.sh           # Email/query + Email/get bodies, blob download
                                # (decoded part, not the raw multipart), traversal 404
./tests/jmapd_write.sh          # flag/move/destroy, id stability, ifInState,
                                # Thread/get
./tests/jmapd_submit.sh         # EmailSubmission/set against a recording SMTP sink
./tests/jmapd_hub.sh            # THE ACCEPTANCE TEST: builds the real mail-hub
                                # client (MAIL_HUB_DIR, default /home/jaye/email)
                                # and drives its own API at jmapd: list, fetch
                                # bodies, flag, move, send, sync
```

Each script exits non-zero on the first failed assertion and prints
`<name>: all checks passed` on success; `jmap_check.com` prints
`N checks, 0 failed`. `dhake e2e` runs all five along with the rest of the host
suite.

Pins: after changing a source file, rebuild with
`./vendor/dhake/dhake.com --warn-hash-mismatch <target>` to see the new hashes,
then regenerate `Dhakefile.dhall` with `python3 tools/gen_dhakefile.py` **as a
deliberate step** and check the diff — the generator writes a zero placeholder
for any output that is not built on this machine, so a blind regen silently
drops the pins of artifacts you did not build.

## See also

- `README.md` — the stack, the build, the client acceptance path.
- `roadmap.md` — what JMAP shipped with and what was deferred.
- `deploy/` — unit, environment file, Caddy snippet.
- `config.example.dhall` — the jmapd stanza comment (it takes no Dhall).
