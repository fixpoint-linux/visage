let Auth = { enabled : Bool, username : Text, password : Text }
in  let Config =
      { hostname : Text
      , domains : List Text
      , listen : { address : Text, port : Natural, proxy_from : List Text }
      , tls_listen : { address : Text, port : Natural }
      , limits : { message : Natural, line : Natural, rcpts : Natural
                 , cmd_timeout : Natural, data_timeout : Natural }
      , relay : { host : Text, port : Natural, auth : Auth, retries : Natural
                , tls : Text, tls_ca : Text, max_attempts : Natural }
      -- Optional outbound relay for reverse-alias REPLIES only.  Normal alias
      -- forwards keep using `relay` (the local imapd ingest); replies from the
      -- local mailbox back to the original external sender go out through
      -- `reply_relay` — typically an authenticated STARTTLS submission server
      -- (e.g. node-one's outbox on :587) that can deliver to external
      -- recipients.  Omit the field (older configs) to default to a copy of
      -- `relay` (previous behaviour).  Same schema as `relay`.
      , reply_relay : { host : Text, port : Natural, auth : Auth, retries : Natural
                      , tls : Text, tls_ca : Text, max_attempts : Natural }
      , storage : { path : Text, spool : Text, retention_days : Natural }
      , reply : { prefix : Text, separator : Text }
      , catch_all : Text
      , aliases : List { alias : Text, destinations : List Text }
      , http : { address : Text, port : Natural }
      , admin : { token : Text }
      , tls : { cert : Text, key : Text }
      , dkim : List { domain : Text, selector : Text, private_key : Text }
      }
in  { hostname = "mx.example.com"
   , domains = [ "example.com" ]
   , listen = { address = "0.0.0.0", port = 2525, proxy_from = [] : List Text }
   -- proxy_from lists the TRUSTED PROXY-protocol v1 peers (IP literals, e.g.
   -- the fly edge / nginx stream proxy in front of this listener).  A PROXY
   -- header is honored only when the actual TCP peer is in this list; from
   -- any other peer it is ignored, so an empty list means a directly
   -- reachable listener cannot forge the client IP (SPF / conn caps).
   -- Put the edge's address here when running behind a PROXY-protocol proxy.
   -- Optional implicit-TLS (SMTPS) listener; the fly edge uses it to deliver
   -- over TLS (nginx stream `proxy_ssl`).  port 0 = disabled.
   , tls_listen = { address = "0.0.0.0", port = 0 }
   , limits = { message = 26214400, line = 1000, rcpts = 100
              , cmd_timeout = 300, data_timeout = 600 }
   , relay = { host = "127.0.0.1", port = 2526
             , auth = { enabled = False, username = "", password = "" }
             , retries = 3, tls = "starttls-verify"
             -- tls_ca = "" uses the embedded Mozilla CA bundle; a non-empty path
             -- points at an operator-provided PEM CA bundle (only consulted
             -- when tls == "starttls-verify").
             , tls_ca = "", max_attempts = 100 }
   -- reply_relay carries reverse-alias replies to an EXTERNAL submission
   -- server (AUTH + STARTTLS on :587).  Replace host/username/password with
   -- node-one's outbox credentials.  AUTH is only ever sent over a
   -- certificate-VERIFIED TLS leg, so auth.enabled=True requires
   -- tls = "starttls-verify" (implicit/starttls are privacy-only: an active
   -- MITM terminates them and would capture the password).
   , reply_relay = { host = "outbox.node-one", port = 587
                   , auth = { enabled = True, username = "visage", password = "change-me" }
                   , retries = 3, tls = "starttls-verify"
                   , tls_ca = "", max_attempts = 100 }
   -- jmapd (the JMAP server, `dhake jmapd.com`) takes NO Dhall: its whole
   -- configuration is flags and JMAPD_* env, so there is no field to add here.
   -- Three facts a reader of this file needs, because they tie jmapd to the
   -- settings above:
   --   * SAME MAILDIR ROOT AS IMAPD — `--root /opt/imapd/var/mail`, i.e. the
   --     same tree and the same imapd.passwd this daemon's mail lands in.  It
   --     is a second protocol front end on one store, never a second store.
   --   * ONE ACCOUNT PER CREDENTIAL — each line of <root>/imapd.passwd is one
   --     JMAP accountId (the username) with its own state counters.  There is
   --     no shared or global account, and no account without a passwd line.
   --   * SUBMISSION IS RELAYED TO THE OUTBOX — jmapd never signs or resolves
   --     MX itself; it hands each submission to the outbox on :465 with SMTP
   --     AUTH (JMAPD_OUTBOX_USER/PASS from /etc/jmapd/outbox.env).  DKIM
   --     signing and DMARC/DNS policy live THERE, not here, which is why
   --     jmapd's send path is at-most-once and has no retry queue of its own.
   -- See deploy/jmapd.service, deploy/Caddyfile.jmap and docs/jmapd.md.
   , storage = { path = "./var/db", spool = "./var/spool", retention_days = 30 }
   , reply = { prefix = "reply", separator = "+" }
   , catch_all = ""
   , aliases = [ { alias = "jane@example.com", destinations = [ "jane@realmail.example" ] }
               , { alias = "shopping@example.com", destinations = [ "jane@realmail.example", "bob@realmail.example" ] }
               ]
   , http = { address = "127.0.0.1", port = 8080 }
   -- admin.token is the bearer token for the admin HTTP API.  It is read into
   -- a 512-byte Authorization buffer, so it must be at most ~505 chars (config
   -- enforces a 500-char ceiling); the placeholder below is fine for config-check
   -- but a real deployment must use a long random token.
   , admin = { token = "change-me" }
   -- tls enables inbound STARTTLS (RFC 3207) on the SMTP listener.  Both
   -- paths are required when the record is present; empty paths (below) or
   -- an omitted tls record disable TLS entirely (plaintext default).
   , tls = { cert = "", key = "" }
   , dkim = [] : List { domain : Text, selector : Text, private_key : Text }
   } : Config
