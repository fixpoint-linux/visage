#!/usr/bin/env bash
# uidlist_race.sh — the maildir uidlist sidecar with TWO daemons on one root.
#
# imapd and jmapd share one maildir tree.  imapd keeps its uidlist snapshot for
# a whole SELECTed session and saves at close; jmapd scans and saves per
# request; deliveries land in new/ behind both of them.  This script runs that
# traffic for real (plaintext loopback, throwaway root) and then asserts, from
# the sidecar files themselves:
#
#   * every uid in a sidecar is UNIQUE within its mailbox,
#   * uidnext > max(uid) in that mailbox,
#   * every base name present in new/ + cur/ has a row,
#   * uidnext never went backwards, and a row that existed mid-run is still
#     there after a stale snapshot is written at session close,
#   * a message expunged by ONE daemon while the other's session holds it in
#     its snapshot does not come back for good: the transient row that the
#     stale save can union back (tombstones are session-local — see
#     uidlist_merge's header comment) is pruned by the next scan,
#   * a second pass of the same workload leaves all of it intact.
#
# It is the measurement the locked read-merge-write in src/imap_maildir.c
# exists for: against the pre-fix code (a blind fopen("wb") of the caller's
# snapshot) the "rows registered while a session was open survive" and
# "uidnext did not rewind" checks fail, and the mailbox is left with a UID
# handed out twice.
#
# Binaries are overridable (IMAPD_BIN/JMAPD_BIN) so a pre-fix build can be
# measured against the same assertions.  Ports are picked free; no fixed ports.
set -euo pipefail

cd "$(dirname "$0")/.."

IMAPD_BIN="${IMAPD_BIN:-./imapd.com}"
JMAPD_BIN="${JMAPD_BIN:-./jmapd.com}"
for b in "$IMAPD_BIN" "$JMAPD_BIN"; do
    if [ ! -x "$b" ]; then
        echo "FAIL $b is not built (run: dhake imapd.com jmapd.com)" >&2
        exit 1
    fi
done

free_port() {
    python3 -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()'
}

IMAP_PORT="$(free_port)";   INGEST_PORT="$(free_port)"
POP3_PORT="$(free_port)";   JMAP_PORT="$(free_port)"

TMP="$(mktemp -d /tmp/uidlist_race_XXXXXX)"
ROOT="$TMP/root"
mkdir -p "$ROOT"
printf 'alice:waldorf\n' > "$ROOT/imapd.passwd"
chmod 600 "$ROOT/imapd.passwd"
for d in Inbox .Drafts .Sent; do
    mkdir -p "$ROOT/alice/$d/tmp" "$ROOT/alice/$d/new" "$ROOT/alice/$d/cur"
done
for n in 1 2 3; do
    printf 'From: bob@example.com\r\nTo: alice@example.com\r\nSubject: seed %s\r\nMessage-ID: <seed%s@example.com>\r\nDate: Mon, 1 Jan 2024 0%s:00:00 +0000\r\nContent-Type: text/plain\r\n\r\nseed body %s\r\n' \
        "$n" "$n" "$n" "$n" > "$ROOT/alice/Inbox/cur/170000010$n.SEED$n.host:2,S"
done

DAEMONS=()
cleanup() {
    for pid in "${DAEMONS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$TMP"
}
trap cleanup EXIT

FAILS=0
pass()  { printf 'ok   %s\n' "$1"; }
fail()  { printf 'FAIL %s\n' "$1"; FAILS=$((FAILS + 1)); }

wait_port() {   # wait_port PORT LABEL
    local i=0
    until (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; do
        i=$((i + 1))
        if [ "$i" -gt 100 ]; then echo "FAIL $2 did not come up" >&2; exit 1; fi
        sleep 0.1
    done
}

"$IMAPD_BIN" --root "$ROOT" --hostname localhost \
    --imap-port "$IMAP_PORT" --ingest-port "$INGEST_PORT" \
    --pop3-port "$POP3_PORT" >"$TMP/imapd.log" 2>&1 &
DAEMONS+=("$!")
"$JMAPD_BIN" --root "$ROOT" --addr 127.0.0.1 --port "$JMAP_PORT" \
    --hostname localhost >"$TMP/jmapd.log" 2>&1 &
DAEMONS+=("$!")

wait_port "$IMAP_PORT" "imapd"
wait_port "$JMAP_PORT" "jmapd"

if python3 - "$ROOT" "$IMAP_PORT" "$JMAP_PORT" <<'PYEOF'
import base64, json, os, re, socket, sys, threading, time
import urllib.request

root, imap_port, jmap_port = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
MBOXES = ("Inbox", ".Drafts", ".Sent")
JMAP_BASE = "http://127.0.0.1:%d" % jmap_port
AUTH = "Basic " + base64.b64encode(b"alice:waldorf").decode()
CORE = "urn:ietf:params:jmap:core"
MAIL = "urn:ietf:params:jmap:mail"
fails = []


def ok(what):
    print("ok   %s" % what)


def fail(what, detail=""):
    print("FAIL %s%s" % (what, " — %s" % detail if detail else ""))
    fails.append(what)


def check(cond, what, detail=""):
    (ok if cond else fail)(what) if cond else fail(what, detail)


# ---------------------------------------------------------------- sidecar
def sidecar(mbx):
    """(uidvalidity, uidnext, [(uid, base), ...]) read the way a reader does."""
    path = os.path.join(root, "alice", mbx, "imapd-uidlist")
    rows = []
    if not os.path.exists(path):
        return 0, 0, rows
    with open(path) as f:
        head = f.readline().split()
        if len(head) != 2:
            raise SystemExit("FAIL %s: malformed uidlist header" % path)
        uv, uidnext = int(head[0]), int(head[1])
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                rows.append((int(parts[0]), parts[1]))
    return uv, uidnext, rows


def maildir_bases(mbx):
    """Base names present in new/ + cur/ (tmp/ is in flight, not mail)."""
    d = os.path.join(root, "alice", mbx)
    bases = set()
    for sub in ("new", "cur"):
        p = os.path.join(d, sub)
        if not os.path.isdir(p):
            continue
        for name in os.listdir(p):
            bases.add(name.split(":2,")[0])
    return bases


def seed_base(mbx, n):
    """The maildir base of seed message n (its filename carries SEED<n>)."""
    for b in maildir_bases(mbx):
        if ("SEED%d." % n) in b:
            return b
    return None


def jmap_destroy_base(base):
    """Expunge one message through the OTHER daemon: unlink + tombstoned save.
    The id is "e" + b64url(base), the form jmapd itself emits for a message in
    one mailbox.  Returns True when jmapd reported it destroyed."""
    eid = "e" + base64.urlsafe_b64encode(base.encode()).decode().rstrip("=")
    res = one("Email/set", {"accountId": "alice", "destroy": [eid]})
    return eid in (res.get("destroyed") or [])


def structural(pass_no):
    """The three invariants that must hold of every sidecar, at any time."""
    for mbx in MBOXES:
        uv, uidnext, rows = sidecar(mbx)
        if uv == 0 and uidnext == 0 and not rows:
            ok("pass%d %s: no sidecar yet (empty mailbox)" % (pass_no, mbx))
            continue
        uids = [u for u, _ in rows]
        bases = [b for _, b in rows]
        check(len(set(uids)) == len(uids),
              "pass%d %s: uids unique in the sidecar" % (pass_no, mbx),
              "duplicate uid in %s: %s" % (mbx, sorted(uids)))
        check(len(set(bases)) == len(bases),
              "pass%d %s: bases unique in the sidecar" % (pass_no, mbx),
              "duplicate base in %s" % mbx)
        check(uidnext > max(uids) if uids else uidnext >= 1,
              "pass%d %s: uidnext > max(uid)" % (pass_no, mbx),
              "uidnext=%d max(uid)=%s" % (uidnext, max(uids) if uids else None))


def coverage(pass_no):
    """After everyone has settled: the sidecar mirrors new/ + cur/."""
    for mbx in MBOXES:
        uv, uidnext, rows = sidecar(mbx)
        have = set(b for _, b in rows)
        files = maildir_bases(mbx)
        check(not (files - have),
              "pass%d %s: every base in new/+cur/ has a uidlist row"
              % (pass_no, mbx),
              "unregistered: %s" % sorted(files - have)[:5])
        check(not (have - files),
              "pass%d %s: no uidlist row without a file" % (pass_no, mbx),
              "orphan rows: %s" % sorted(have - files)[:5])


# ------------------------------------------------------------------ IMAP
class Imap:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", imap_port), timeout=30)
        self.f = self.s.makefile("rb")
        self.tag = 0
        self.f.readline()   # greeting

    def cmd(self, line):
        self.tag += 1
        tag = "r%d" % self.tag
        self.s.sendall(("%s %s\r\n" % (tag, line)).encode())
        out = b""
        while True:
            ln = self.f.readline()
            if not ln:
                raise SystemExit("FAIL imap: connection closed during %r" % line)
            out += ln
            if ln.startswith(tag.encode() + b" "):
                return out.decode()

    def login(self):
        r = self.cmd("LOGIN alice waldorf")
        if " OK" not in r:
            raise SystemExit("FAIL imap: LOGIN refused: %r" % r)

    def select(self, mbx="INBOX"):
        r = self.cmd("SELECT %s" % mbx)
        if " OK" not in r:
            raise SystemExit("FAIL imap: SELECT refused: %r" % r)

    def uids(self):
        r = self.cmd("UID SEARCH ALL")
        for line in r.splitlines():
            if line.startswith("* SEARCH"):
                return [int(x) for x in line.split()[2:]]
        return []

    def close(self):
        try:
            self.cmd("LOGOUT")
        except Exception:
            pass
        self.s.close()


# ------------------------------------------------------------------ JMAP
def call(payload):
    req = urllib.request.Request(JMAP_BASE + "/api",
                                data=json.dumps(payload).encode())
    req.add_header("Authorization", AUTH)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def one(name, args, using=(CORE, MAIL)):
    resp = call({"using": list(using), "methodCalls": [[name, args, "c0"]]})
    return resp["methodResponses"][0][1]


def mailboxes():
    res = one("Mailbox/get", {"accountId": "alice"})
    return {m["name"]: m["id"] for m in res["list"]}


# ------------------------------------------------------------- the writers
def deliver(n):
    """A raw maildir delivery: a file lands in new/ behind both daemons."""
    d = os.path.join(root, "alice", "Inbox", "new")
    name = "%d.RACE%d.%d.%d" % (time.time() * 1000, n, os.getpid(),
                                threading.get_ident())
    with open(os.path.join(d, name), "wb") as f:
        f.write(("From: bob@example.com\r\nTo: alice@example.com\r\n"
                 "Subject: delivered %d\r\nMessage-ID: <race%d@example.com>\r\n"
                 "\r\nrace body %d\r\n" % (n, n, n)).encode())


def jmap_create(mbox_id, n):
    one("Email/set", {"accountId": "alice", "create": {"c%d" % n: {
        "mailboxIds": {mbox_id: True},
        "keywords": {"$seen": True},
        "from": [{"email": "alice@example.com"}],
        "to": [{"email": "bob@example.com"}],
        "subject": "race create %d" % n,
        "textBody": [{"partId": "t1", "type": "text/plain"}],
        "bodyValues": {"t1": {"value": "created during the race\n"}},
    }}})


def jmap_keyword_flips(inbox_id):
    res = one("Email/query", {"accountId": "alice",
                             "filter": {"inMailbox": inbox_id}, "limit": 5})
    ids = res["ids"]
    for i, eid in enumerate(ids):
        one("Email/set", {"accountId": "alice", "update": {
            eid: {"keywords/$flagged": bool(i % 2)}}})


def imap_store_flips(session, stop):
    uids = session.uids() or [1]
    i = 0
    while not stop.is_set():
        flag = "\\Flagged" if i % 2 else "\\Seen"
        op = "+FLAGS" if (i // 2) % 2 == 0 else "-FLAGS"
        session.cmd("UID STORE %d %s (%s)" % (uids[i % len(uids)], op, flag))
        i += 1


def sidecar_stamp(mbx):
    path = os.path.join(root, "alice", mbx, "imapd-uidlist")
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return None
    return (st.st_mtime_ns, st.st_size)


def wait_sidecar_change(mbx, before, timeout=5.0):
    """imapd writes its snapshot asynchronously at connection teardown, so the
    LOGOUT reply is not the save.  Wait for the sidecar to actually change."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if sidecar_stamp(mbx) != before:
            return True
        time.sleep(0.02)
    return False


def run_pass(pass_no):
    """One pass: an IMAP session holds a mailbox open while both other writers
    and raw deliveries mutate it, then it saves its now-stale snapshot."""
    mbs = mailboxes()
    inbox_id = mbs["Inbox"]

    session = Imap()
    session.login()
    session.select("INBOX")
    before = {m: sidecar(m) for m in MBOXES}

    stop = threading.Event()
    workers = [threading.Thread(target=deliver, args=(i,)) for i in range(4)]
    workers.append(threading.Thread(target=imap_store_flips,
                                    args=(session, stop)))
    workers.append(threading.Thread(target=jmap_create, args=(inbox_id, 1)))
    workers.append(threading.Thread(target=jmap_create,
                                    args=(mbs["Drafts"], 2)))
    workers.append(threading.Thread(target=jmap_keyword_flips,
                                    args=(inbox_id,)))
    # the STORE loop is the only unbounded writer: it runs until the timer
    # ends the overlap window, so every writer really does run concurrently
    timer = threading.Timer(0.5, stop.set)
    timer.start()
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    timer.cancel()

    mid = {m: sidecar(m) for m in MBOXES}

    # --- cross-daemon expunge while this session still holds the row --------
    # jmapd deletes a message the open IMAP session has in its snapshot: unlink
    # plus a tombstoned save, so the row leaves the sidecar.  The stale
    # close-save below can then union it back — tombstones are session-local,
    # the known bounded case documented in uidlist_merge — so what this probes
    # is CONVERGENCE after the healing scan, not the absence of the transient
    # row (a future fix that prevents the resurrect must not fail this script).
    doomed = seed_base("Inbox", pass_no + 1)
    check(doomed is not None,
          "pass%d Inbox: found the seed message for the expunge probe" % pass_no)
    doomed_uid = 0
    if doomed:
        for u, b in sidecar("Inbox")[2]:
            if b == doomed:
                doomed_uid = u
        check(doomed_uid != 0 and doomed_uid in session.uids(),
              "pass%d Inbox: the doomed message is in the open session's view"
              % pass_no,
              "uid %d absent from the session's UID SEARCH" % doomed_uid)
        check(jmap_destroy_base(doomed),
              "pass%d Inbox: the other daemon expunged the message" % pass_no)
        check(doomed not in maildir_bases("Inbox"),
              "pass%d Inbox: the expunge removed the message file" % pass_no)
        check(doomed not in set(b for _, b in sidecar("Inbox")[2]),
              "pass%d Inbox: the expunging daemon's save dropped the row"
              % pass_no, "row %r still in the sidecar" % doomed)

    stamp = sidecar_stamp("Inbox")   # taken AFTER the expunge's own save
    session.close()          # imapd writes its stale snapshot here
    check(wait_sidecar_change("Inbox", stamp),
          "pass%d Inbox: the session's close-save reached the sidecar"
          % pass_no,
          "no sidecar write within 5s (the measurement would be vacuous)")
    after = {m: sidecar(m) for m in MBOXES}

    # --- the checks the pre-fix blind save breaks ---
    for mbx in MBOXES:
        _, un_mid, rows_mid = mid[mbx]
        _, un_after, rows_after = after[mbx]
        check(un_after >= un_mid,
              "pass%d %s: uidnext did not rewind across the stale save"
              % (pass_no, mbx),
              "uidnext %d -> %d" % (un_mid, un_after))
        # a base the other daemon deliberately expunged is not a lost row
        lost = (set(b for _, b in rows_mid) - set(b for _, b in rows_after)
                - ({doomed} if doomed else set()))
        check(not lost,
              "pass%d %s: rows registered while a session was open survive "
              "the stale save" % (pass_no, mbx),
              "lost %d row(s), e.g. %s" % (len(lost), sorted(lost)[:3]))

    structural(pass_no)

    # --- settle: both daemons scan, so raw deliveries get their rows ---
    s2 = Imap()
    s2.login()
    s2.select("INBOX")
    s2.close()
    one("Email/query", {"accountId": "alice", "limit": 50})
    coverage(pass_no)

    # --- the expunge probe converges: no row for the deleted base, no
    # duplicate uids, uidnext still clear of every uid ---
    if doomed:
        _, un_final, rows_final = sidecar("Inbox")
        final_uids = [u for u, _ in rows_final]
        check(doomed not in set(b for _, b in rows_final),
              "pass%d Inbox: the expunged row is gone after the next scan"
              % pass_no,
              "resurrected row %r survived the healing scan" % doomed)
        check(len(set(final_uids)) == len(final_uids),
              "pass%d Inbox: no duplicate uid after the expunge/stale-save "
              "overlap" % pass_no, "duplicate uid in %s" % sorted(final_uids))
        check(un_final > max(final_uids) if final_uids else un_final >= 1,
              "pass%d Inbox: uidnext still clears every uid after the expunge"
              % pass_no,
              "uidnext=%d max(uid)=%s"
              % (un_final, max(final_uids) if final_uids else None))

    return {m: sidecar(m)[1] for m in MBOXES}


un_before = run_pass(1)
un_after = run_pass(2)
for mbx in MBOXES:
    check(un_after[mbx] >= un_before[mbx],
          "pass2 %s: uidnext is monotonic across both passes" % mbx,
          "uidnext %d -> %d" % (un_before[mbx], un_after[mbx]))

if fails:
    print("\n%d check(s) failed" % len(fails))
    sys.exit(1)
print("\nall uidlist invariants held")
PYEOF
then
    pass "uidlist sidecar invariants under imapd + jmapd on one root"
else
    fail "uidlist sidecar invariants under imapd + jmapd on one root"
fi

if [ "$FAILS" -ne 0 ]; then
    echo "FAIL uidlist_race.sh ($FAILS check(s) failed)" >&2
    exit 1
fi
echo "PASS uidlist_race.sh"
