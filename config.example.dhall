let Auth = { enabled : Bool, username : Text, password : Text }
in  let Config =
      { hostname : Text
      , domains : List Text
      , listen : { address : Text, port : Natural }
      , limits : { message : Natural, line : Natural, rcpts : Natural
                 , cmd_timeout : Natural, data_timeout : Natural }
      , relay : { host : Text, port : Natural, auth : Auth, retries : Natural
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
   , listen = { address = "0.0.0.0", port = 2525 }
   , limits = { message = 26214400, line = 1000, rcpts = 100
              , cmd_timeout = 300, data_timeout = 600 }
   , relay = { host = "127.0.0.1", port = 2526
             , auth = { enabled = False, username = "", password = "" }
             , retries = 3, tls = "starttls-verify"
             -- tls_ca = "" uses the embedded Mozilla CA bundle; a non-empty path
             -- points at an operator-provided PEM CA bundle (only consulted
             -- when tls == "starttls-verify").
             , tls_ca = "", max_attempts = 100 }
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
