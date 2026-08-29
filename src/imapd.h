/* imapd.h — companion IMAP mailbox server (imapd).

   imapd is a single-process, poll()-based daemon with two listeners that
   mirrors smtp_in.c's event-loop model:
     - an SMTP INGEST listener (default 127.0.0.1:2526) that accepts relayed
       mail from visage's smtp_out (EHLO/MAIL/RCPT/DATA; STARTTLS per RFC
       3207 when --cert/--key are configured) and stores each message into
       a per-user maildir, and
     - an IMAP4rev1 listener (default 127.0.0.1:143) that serves those
       maildirs to real clients (RFC 3501 subset; STARTTLS per RFC 2595
       when --cert/--key are configured; see imapd_imap.c).

   Mailbox store: standard maildir per user --
       <root>/<user>/Inbox/{tmp,new,cur}      (INBOX)
       <root>/<user>/.<Folder>/{tmp,new,cur}  (other folders)
   Flags live in the ":2,DFRST" filename info suffix and UIDs in a sidecar
   "<mailboxdir>/imapd-uidlist" file.  Single-writer: one daemon owns the
   tree; external writers are not supported (v1).

   The pure helpers (flag suffix codec, seq-set, base64 decode, wildcards,
   SEARCH parse/match, tokenizer) are exported here and unit-tested by
   imap_check.c without sockets or threads. */
#ifndef VISAGE_IMAPD_H
#define VISAGE_IMAPD_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Limits (mirroring smtp_in.c's bounded-buffer discipline)           */
/* ------------------------------------------------------------------ */

#define IMAPD_MAX_CONNS          512
#define IMAPD_MAX_CONNS_PER_IP   16
/* Hard cap on the pending reply backlog per connection (SMTP_IN_MAX_OUT). */
#define IMAPD_MAX_OUT            (256u * 1024u)
#define IMAPD_RECV_CHUNK         4096
#define IMAPD_LISTEN_BACKLOG     128
#define IMAPD_MAX_LINE           1000   /* one IMAP/SMTP line excl. literals */
#define IMAPD_MAX_RCPTS          32
#define IMAPD_MAX_USER           128    /* maildir user (path component) */
#define IMAPD_MAX_MBOX           512    /* mailbox name length cap */
#define IMAPD_MAX_TAG            64
#define IMAPD_MAX_UNK            16     /* unknown maildir flag letters kept */
/* Header bytes scanned/built for BODY[HEADER.FIELDS] (bounded). */
#define IMAPD_HDR_CAP            (256u * 1024u)
/* Literals at/below this size are inlined into the reply buffer; larger
   literals stream straight from the message file on POLLOUT. */
#define IMAPD_INLINE_LIT         (16u * 1024u)

#define IMAPD_DEFAULT_ROOT        "./var/mail"
#define IMAPD_DEFAULT_INGEST_PORT 2526   /* config.example.dhall relay target */
#define IMAPD_DEFAULT_IMAP_PORT   143
#define IMAPD_DEFAULT_POP3_PORT   110
#define IMAPD_DEFAULT_MAX_MSG     (32u * 1024u * 1024u)
#define IMAPD_DEFAULT_CMD_TMO     300
#define IMAPD_DEFAULT_DATA_TMO    600
#define IMAPD_IDLE_SCAN_MS        1000   /* RFC 2177: cadence for IDLE re-scan */
#define IMAPD_IDLE_TMO            1800   /* RFC 2177 §4: server-side IDLE cap */

#define IMAPD_PASSWD_FILE  "imapd.passwd"       /* under <root>, 0600 */
#define IMAPD_SUBS_FILE    "imapd-subscriptions" /* under <user> */
#define IMAPD_UIDLIST_FILE "imapd-uidlist"       /* under <mailboxdir> */

/* ------------------------------------------------------------------ */
/* Configuration (CLI flags + env, no Dhall on purpose: keeps imapd    */
/* free of the dhall/datalog link deps; TLS is opt-in via cert/key)    */
/* ------------------------------------------------------------------ */

typedef struct ImapdConfig {
    const char *root;         /* maildir root (IMAPD_ROOT) */
    const char *ingest_addr;  /* SMTP ingest bind address */
    uint16_t    ingest_port;
    const char *imap_addr;    /* IMAP bind address */
    uint16_t    imap_port;
    const char *pop3_addr;    /* POP3 bind address */
    uint16_t    pop3_port;
    const char *hostname;     /* greeted hostname */
    uint32_t    max_msg;      /* max message bytes (ingest + APPEND) */
    uint32_t    cmd_tmo;      /* idle timeout, seconds */
    uint32_t    data_tmo;     /* DATA idle timeout, seconds (ingest) */
    const char *cert;         /* TLS certificate PEM (IMAPD_CERT / --cert) */
    const char *key;          /* TLS private key PEM (IMAPD_KEY / --key) */
} ImapdConfig;

/* ------------------------------------------------------------------ */
/* Maildir view                                                        */
/* ------------------------------------------------------------------ */

/* Known maildir flags (filename letters D F R S T).  IMAIL_RECENT is
   session-only (\Recent): never encoded in filenames. */
#define IMAIL_DRAFT    0x01u  /* D */
#define IMAIL_FLAGGED  0x02u  /* F */
#define IMAIL_ANSWERED 0x04u  /* R (replied) */
#define IMAIL_SEEN     0x08u  /* S */
#define IMAIL_TRASHED  0x10u  /* T (deleted) */
#define IMAIL_RECENT   0x20u  /* session-only */

typedef struct Imail {
    uint32_t uid;
    uint8_t  flags;             /* IMAIL_* bitmask (known flags) */
    char     unk[IMAPD_MAX_UNK];/* unknown flag letters preserved */
    bool     recent;            /* arrived in new/ for this session */
    time_t   internal_date;     /* st_mtime */
    size_t   size;              /* file byte size */
    char    *base;              /* owned: unique base name (no ":2,") */
    char    *path;              /* owned: current full path */
} Imail;

typedef struct Mbox {
    char     dir[4096];         /* mailbox directory */
    uint32_t uidvalidity;
    uint32_t uidnext;
    Imail   *msgs;              /* sorted by uid ascending */
    size_t   nmsgs, cap;
} Mbox;

/* ------------------------------------------------------------------ */
/* SEARCH key tree (pure; tested over synthetic views)                 */
/* ------------------------------------------------------------------ */

typedef enum {
    SK_ALL, SK_ANSWERED, SK_DELETED, SK_DRAFT, SK_FLAGGED, SK_NEW, SK_OLD,
    SK_RECENT, SK_SEEN, SK_UNSEEN, SK_SEQ, SK_UID, SK_FROM, SK_TO, SK_SUBJECT,
    SK_HEADER, SK_BODY, SK_TEXT, SK_NOT, SK_OR, SK_AND
} SearchKind;

typedef struct SearchKey {
    SearchKind kind;
    char      *set;   /* SK_SEQ / SK_UID: seq-set spec (owned) */
    char      *hdr;   /* SK_HEADER: header name (owned) */
    char      *str;   /* FROM/TO/SUBJECT/HEADER/BODY/TEXT needle (owned) */
    struct SearchKey *a, *b;  /* NOT(a) / OR(a,b) / AND(a,b) */
} SearchKey;

/* One message as SEARCH sees it: view metadata + (lazily loaded) content. */
typedef struct ImailDoc {
    const Imail *m;
    size_t       seq;    /* 1-based sequence number in the view */
    const char  *msg;    /* full message bytes (may be NULL: metadata-only) */
    size_t       msglen;
} ImailDoc;

/* ------------------------------------------------------------------ */
/* Per-connection state (shared by the ingest and IMAP state machines) */
/* ------------------------------------------------------------------ */

typedef struct ImapdCred {
    char *user;   /* owned */
    char *pass;   /* owned */
} ImapdCred;

typedef struct ImapdServer {
    ImapdConfig cfg;
    ImapdCred  *creds;
    size_t      ncreds;
    int         listen_ingest;   /* SMTP ingest listener */
    int         listen_imap;     /* IMAP listener */
    int         listen_pop3;     /* POP3 listener */
    struct Conn **conns;
    size_t      nconns, conn_cap;
    bool        tls_ready;       /* cert+key loaded: STARTTLS is offered  */
    bool        imap_loopback;   /* IMAP listener bound to a loopback addr */
    bool        pop3_loopback;   /* POP3 listener bound to a loopback addr */
} ImapdServer;

typedef struct FetchGen FetchGen;   /* opaque: imapd_imap.c */
typedef struct Pop3Gen  Pop3Gen;    /* opaque: pop3d.c */
typedef struct ImapdTls ImapdTls;   /* opaque: imapd_tls.c (mbedTLS) */

/* Session states. */
enum { IST_NOT_AUTH = 0, IST_AUTH, IST_SELECTED };

enum { CONN_INGEST = 0, CONN_IMAP, CONN_POP3 };

/* POP3 session states (RFC 1939). */
enum { PO_AUTH = 0, PO_TRANS };

/* Ingest SMTP session states (mirroring smtp_in.c). */
enum { ST_INIT = 0, ST_HELO, ST_MAIL, ST_DATA };

/* IMAP reader modes: whole lines vs. collecting {n} literal bytes. */
enum { IC_LINE = 0, IC_LIT };

typedef struct Conn {
    int    fd;
    int    kind;               /* CONN_INGEST / CONN_IMAP */
    bool   closed;             /* close once the output buffer drains */
    char  *in;                 /* raw recv buffer (owned) */
    size_t in_len, in_cap;
    char  *out;                /* reply output buffer (owned) */
    size_t out_len, out_off, out_cap;
    time_t last_act;           /* last activity (idle-timeout clock) */
    unsigned char peer_ip[16];
    uint8_t       peer_ip_len; /* 0 = not set */
    /* ingest-only (kind == CONN_INGEST) */
    int    st;                 /* ST_* */
    char  *from;               /* reverse-path (owned) */
    char **rcpts;              /* accepted RCPT local-parts (owned strings) */
    size_t nrcpts, rcpt_cap;
    char  *data;               /* DATA buffer (owned, dot-stuffed) */
    size_t data_len, data_cap;
    /* imap-only (kind == CONN_IMAP) */
    char  *user;               /* logged-in user (owned) */
    int    ist;                /* IST_* */
    bool   examine;            /* read-only session (EXAMINE) */
    bool   mb_open;            /* c->mb is valid */
    Mbox   mb;                 /* selected mailbox */
    char   mbname[IMAPD_MAX_MBOX + 1];  /* selected mailbox name */
    char   auth_tag[IMAPD_MAX_TAG + 1]; /* pending AUTHENTICATE continuation */
    char   idle_tag[IMAPD_MAX_TAG + 1]; /* pending IDLE command tag */
    bool   idle;              /* RFC 2177 IDLE in progress (SELECTED) */
    int    mode;               /* IC_LINE / IC_LIT */
    bool   cont_auth;          /* next line is an AUTHENTICATE b64 reply */
    size_t lit_left;           /* IC_LIT: literal bytes still expected */
    char  *cmd;                /* assembled command (literals quote-wrapped) */
    size_t cmd_len, cmd_cap;
    FetchGen *fg;              /* active streaming FETCH (owned) */
    ImapdTls *tls;             /* STARTTLS state (NULL = plaintext conn)  */
    /* pop3-only (kind == CONN_POP3) */
    int    pst;                /* PO_AUTH / PO_TRANS */
    char  *pend_user;          /* USER from authorization (owned) */
    bool  *del;                /* deleted marks, len = mb.nmsgs (owned) */
    size_t ndel;               /* count of marked-deleted messages */
    Pop3Gen *pg;               /* active streaming RETR/TOP (owned) */
} Conn;

/* ------------------------------------------------------------------ */
/* Pure helpers (unit-tested by imap_check.c)                          */
/* ------------------------------------------------------------------ */

/* Parse a maildir info suffix (the text AFTER the ':' of ":2,DFS" -- i.e.
   "2,DFS", or ""). Sets *flags to the known-flag bitmask and copies any
   unknown flag letters into unk (NUL-terminated, preserved verbatim) so a
   flag rename never loses them.  Returns 0, or -1 on malformed input. */
int imapd_flags_parse(const char *info, uint8_t *flags, char *unk,
                      size_t unksz);

/* Encode "2," + known flags in canonical D F R S T order + unk letters into
   out (NUL-terminated).  Returns 0, or -1 if out is too small. */
int imapd_flags_encode(uint8_t flags, const char *unk, char *out,
                       size_t outsz);

/* Validate a UID/sequence set spec ("1", "3:5", "*", "*:10", "1,2:4,9").
   Returns 1 if well-formed, 0 otherwise (uids/seqs are 1-based; "0" and
   trailing ':' are invalid). */
int imapd_seqset_valid(const char *set);

/* Membership test over a VALIDATED set: does it match n?  '*' stands for
   `star` (the uidnext / message count, depending on context).  Reversed
   ranges ("*:10") match the inclusive span either way.  An invalid set
   matches nothing. */
bool imapd_seqset_has(const char *set, uint32_t n, uint32_t star);

/* Base64-decode inlen bytes (AUTH PLAIN).  Rejects non-alphabet bytes,
   misplaced '=' padding, and output that does not fit.  Returns 0 and sets
   *outlen, or -1 (with *outlen 0) on any error. */
int imapd_b64_decode(const char *in, size_t inlen, unsigned char *out,
                     size_t outsz, size_t *outlen);

/* IMAP LIST wildcard match: '*' matches any run (incl. '.'), '%' matches any
   run NOT containing '.', comparison is ASCII case-insensitive. */
bool imapd_wildmat(const char *pat, const char *str);

/* Maildir user validation: 1..IMAPD_MAX_USER chars of [A-Za-z0-9._-], not
   starting with '.', never "." or ".." (it becomes a path component). */
bool imapd_user_ok(const char *u);

/* Mailbox name validation: nonempty, <= IMAPD_MAX_MBOX, no '/', no control
   chars, no leading/trailing '.', no "..".  Returns 0, or -1 if invalid. */
int imapd_mbox_name_ok(const char *name);

/* Detect a trailing "{n}" literal marker on a (CRLF-stripped) command line.
   Returns n (> 0) when present, 0 when absent, -1 on a malformed "{...}". */
int imapd_lit_marker(const char *line);

/* Tokenizer over an ASSEMBLED command (literals were quote-wrapped by the
   reader).  Parses one astring: an atom (run of non-space bytes) or a
   quoted string with backslash escapes.  Skips leading spaces.  Returns 1
   and heap-allocates *out (NUL-terminated, *outlen excludes the NUL), 0 at
   end of input, -1 on malformed input. */
int imapd_next_astring(const char **p, char **out, size_t *outlen);

/* Parse a plain paren list "(atom atom ...)" (e.g. HEADER.FIELDS names).
   Returns 0 and heap-allocates *out and *nout (caller frees each string and
   the array), or -1 on malformed input. */
int imapd_parse_plain_list(const char **p, char ***out, size_t *nout);

/* Parse ONE search key from *p.  Returns 1 and sets *out, 0 at end of the
   program, -1 on a malformed key. */
int imapd_search_parse(const char **p, SearchKey **out);

/* Parse a full search program (keys until end of input, implicitly ANDed).
   Returns 1 with *out set, 0 for an empty program, -1 on error. */
int imapd_search_parse_program(const char **p, SearchKey **out);

void imapd_search_free(SearchKey *k);

/* Evaluate the key against one message.  Content keys (FROM/TO/SUBJECT/
   HEADER/BODY/TEXT) match nothing when d->msg is NULL.  `uidnext` resolves
   '*' in UID sets, `nmsgs` in SEQ sets. */
bool imapd_search_match(const SearchKey *k, const ImailDoc *d,
                        uint32_t uidnext, size_t nmsgs);

/* Does the key tree contain any content key (needs the message body)? */
bool imapd_search_needs_body(const SearchKey *k);

/* ------------------------------------------------------------------ */
/* Maildir store (imap_maildir.c)                                      */
/* ------------------------------------------------------------------ */

/* Resolve user+mailbox name to its directory: "INBOX" (case-insensitive)
   -> <root>/<user>/Inbox; anything else -> <root>/<user>/.<Name>.
   Returns 0, or -1 on an invalid user/name or a truncated path. */
int imapd_mbox_dir(const ImapdConfig *cfg, const char *user, const char *name,
                   char *out, size_t outsz);

/* Create the mailbox directory (tmp/new/cur; idempotent).  Returns 0, or
   -1 on error. */
int imapd_mbox_create(const char *dir);

/* Recursively delete a mailbox directory (bounded to dirs; INBOX is refused
   by the caller).  Returns 0, or -1 on error. */
int imapd_mbox_delete(const char *dir);

/* Deliver msg into the maildir at dir (creating tmp/new/cur as needed):
   write <dir>/tmp/<uniq> then rename into new/ (flags == 0 and no unk) or
   cur/ with a ":2," info suffix.  Rejects messages containing NUL or
   C0/DEL control bytes (8-bit bytes stay allowed).  Returns 0, or -1. */
int imapd_mbox_deliver(const char *dir, const char *msg, size_t len,
                       uint8_t flags, const char *unk);

/* Scan the mailbox into mb (assigning UIDs to new files via the uidlist
   sidecar, pruning vanished entries).  When move_new is true, files still
   in new/ are moved to cur/ and flagged \Recent for this session (SELECT
   semantics); with move_new false nothing is touched (STATUS semantics).
   The mailbox directory is created if missing.  Returns 0, or -1. */
int imapd_mbox_open(const ImapdConfig *cfg, const char *user,
                    const char *name, Mbox *mb);
int imapd_mbox_peek(const ImapdConfig *cfg, const char *user,
                    const char *name, Mbox *mb);
void imapd_mbox_close(Mbox *mb);

/* Find a message by uid (NULL when absent). */
Imail *imapd_mbox_find(Mbox *mb, uint32_t uid);

/* Rewrite one message's flags (rename keeps the base name and unknown
   letters; the file moves into cur/).  Returns 0, or -1. */
int imapd_mbox_store(Mbox *mb, uint32_t uid, uint8_t flags);

/* Unlink one message and compact the view (also prunes the uidlist).
   Returns 0, or -1 when the uid is absent. */
int imapd_mbox_expunge(Mbox *mb, uint32_t uid);

/* Move or copy one message (by uid) out of mb into the mailbox dest_name.
   See imap_maildir.c.  Returns 0 on success, -1 on failure. */
int imapd_mbox_file(const ImapdConfig *cfg, const char *user, Mbox *mb,
                    uint32_t uid, const char *dest_name, bool move);

/* List folder names (IMAP-visible, WITHOUT the INBOX) under the user's dir
   matching the LIST pattern.  Heap-allocates *out and *nout (caller frees
   each name and the array).  Returns 0, or -1 on error. */
int imapd_mbox_list(const ImapdConfig *cfg, const char *user,
                    const char *pattern, char ***out, size_t *nout);

/* Subscription file (one name per line) helpers.  add=false removes.
   Returns 0, or -1 on error. */
int imapd_sub_write(const char *path, const char *name, bool add);
bool imapd_sub_has(const char *path, const char *name);

/* ------------------------------------------------------------------ */
/* Credentials ($ROOT/imapd.passwd, "user:pass" lines, 0600)           */
/* ------------------------------------------------------------------ */

/* Load the passwd file (missing file -> empty table, not an error).
   Returns 0, or -1 on allocation failure. */
int imapd_auth_load(const ImapdConfig *cfg, ImapdServer *srv);

/* Exact user+pass match against the loaded table. */
bool imapd_auth_check(const ImapdServer *srv, const char *user,
                      const char *pass);

/* Add/replace one "user:pass" line in $ROOT/imapd.passwd (creating the root
   dir and chmod 0600).  Used by the `imapd passwd` subcommand. */
int imapd_auth_set(const ImapdConfig *cfg, const char *user,
                   const char *pass);

/* ------------------------------------------------------------------ */
/* Entry points (imapd.c poll loop + per-kind state machines)          */
/* ------------------------------------------------------------------ */

int imapd_main(ImapdServer *srv);   /* daemon: bind + poll loop */

/* Queue the greeting on a freshly accepted connection. */
void imapd_ingest_greeting(ImapdServer *srv, Conn *c);
void imapd_imap_greeting(ImapdServer *srv, Conn *c);
void imapd_pop3_greeting(ImapdServer *srv, Conn *c);

/* Feed readable bytes into the state machine (also drains pending output).
   Both close c->closed on fatal errors; the caller handles the rest. */
void imapd_ingest_readable(ImapdServer *srv, Conn *c, time_t now);
void imapd_imap_readable(ImapdServer *srv, Conn *c, time_t now);
void imapd_pop3_readable(ImapdServer *srv, Conn *c, time_t now);

/* Generate more of an active streaming FETCH into c->out (POLLOUT drain). */
void imapd_fetch_pump(ImapdServer *srv, Conn *c);

/* RFC 2177 IDLE: re-scan the selected mailbox and emit unsolicited
   EXISTS/RECENT updates if its message set changed.  No-op unless the
   connection is currently IDLE with a SELECTED mailbox. */
void imapd_imap_idle_refresh(ImapdServer *srv, Conn *c);

/* Free a streaming FETCH generator (NULL-safe). */
void imapd_fetch_free(Conn *c);

/* POP3 (pop3d.c) */
void imapd_pop3_tls_reset(ImapdServer *srv, Conn *c);
void imapd_pop3_pump(ImapdServer *srv, Conn *c);
void imapd_pop3_free(Conn *c);

/* ------------------------------------------------------------------ */
/* STARTTLS (imapd_tls.c; mbedTLS SERVER role over the non-block fds).  */
/* imapd_capability / imapd_addr_loopback are pure helpers unit-tested  */
/* by imap_check.c; the imapd_tls_* entry points live only in binaries  */
/* linked with src/imapd_tls.c + the vendored mbedTLS objects.          */
/* ------------------------------------------------------------------ */

/* Load cfg.cert/cfg.key into the process-wide server config (no-op TLS-off
   when both are NULL).  Returns 0, or -1 after printing an mbedtls error
   (bad/missing/unmatched cert+key is fatal: the caller must exit). */
int  imapd_tls_global_init(ImapdServer *srv);

/* Begin STARTTLS on a pre-auth connection: allocates the per-conn context in
   the PENDING state (the queued plaintext OK/220 reply drains first).
   Returns 0, or -1 on allocation/setup failure (plaintext conn preserved). */
int  imapd_tls_start(ImapdServer *srv, Conn *c);

/* Drive one handshake round.  Returns 1 established, 0 still negotiating
   (poll POLLIN or POLLOUT per imapd_tls_wants_write), -1 fatal (the wire is
   mid-TLS: the caller must drop the conn WITHOUT queueing any reply).
   PENDING -> HANDSHAKE advance requires c->out to be fully drained. */
int  imapd_tls_handshake_step(Conn *c, time_t now);

/* Decrypted read: >0 n bytes, 0 no data right now (WANT_READ), -1 fatal or
   the peer closed (caller sets c->closed). */
int  imapd_tls_recv(Conn *c, char *buf, size_t len);

/* True when the raw fd has reached EOF (peer sent FIN) even though mbedtls
   has not surfaced it as a TLS error yet.  Used to break a poll busy-loop:
   a half-closed peer keeps poll() reporting POLLIN, but mbedtls_ssl_read
   returns WANT_READ (0) forever on it, so the readable loop must close
   explicitly or the daemon spins at 100% CPU. */
bool imapd_tls_eof(const Conn *c);

/* Encrypted write: >0 n plaintext bytes accepted, 0 socket would block
   (retry on POLLOUT), -1 fatal. */
int  imapd_tls_send(Conn *c, const char *buf, size_t len);

/* Best-effort close_notify + free (the fd is closed by the caller). */
void imapd_tls_conn_free(Conn *c);

bool imapd_tls_available(const ImapdServer *srv);  /* cert+key loaded      */
bool imapd_tls_pending(const Conn *c);      /* plaintext reply still draining */
bool imapd_tls_handshaking(const Conn *c);  /* PENDING or HANDSHAKE (not up) */
bool imapd_tls_established(const Conn *c);  /* TLS active: speak TLS        */
bool imapd_tls_wants_write(const Conn *c);  /* handshake wants POLLOUT      */

/* Canonical CAPABILITY string for a session (pure; unit-tested).
     tls_active      -> "IMAP4rev1 AUTH=PLAIN" (STARTTLS MUST NOT reappear)
     tls_avail+plain -> "IMAP4rev1 STARTTLS AUTH=PLAIN"
     tls_avail+!plain-> "IMAP4rev1 STARTTLS LOGINDISABLED" (RFC 3501 11.1)
     no TLS          -> "IMAP4rev1 AUTH=PLAIN" (legacy loopback default)  */
const char *imapd_capability(bool tls_active, bool tls_avail,
                             bool plain_auth_ok);

/* Bind-address classifier for RFC 3501 11.1 cleartext-auth gating
   ("127.x.x.x", "localhost", "::1" -> true).  Pure; unit-tested. */
bool imapd_addr_loopback(const char *addr);

/* Post-handshake session resets (STARTTLS is only valid pre-auth, so the
   session restarts clean: fresh CAPABILITY + LOGIN / fresh EHLO). */
void imapd_imap_tls_reset(ImapdServer *srv, Conn *c);
void imapd_ingest_tls_reset(ImapdServer *srv, Conn *c);

#endif /* VISAGE_IMAPD_H */

/* Build the RFC 3501 BODYSTRUCTURE string for a full message. Heap-allocates
   *out (NUL-terminated); *outlen excludes the NUL. */
int imapd_bodystructure(const char *msg, size_t len, char **out, size_t *outlen);

/* Resolve a 1-based MIME part path against a full message; fills the part's
   byte range [start,end) and header/body boundary hdr_end. Returns 0 on
   success, -1 if the path does not resolve. */
int imapd_mime_part(const char *msg, size_t len, const int *path, int npath,
                    size_t *start, size_t *end, size_t *hdr_end);
