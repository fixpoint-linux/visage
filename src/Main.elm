module Main exposing (main)

{-| The visage documentation site as a plain `Browser.element` app.

This module renders all 6 pages (landing, compactness, security, config, cli,
playground) using the shared `Fixpoint.*` design package. It mirrors the
datalog-dafsa docs site structure exactly: one Elm bundle, one MFE module
(`shell/mfe/visage-page.js`), and a `{ pathname }` flag that selects which page
to render. The playground page hosts a `<visage-playground>` custom element
(registered by `shell/mfe/visage-playground.js`) that boots the real C
alias-resolver compiled to WebAssembly.

-}

import Browser
import Fixpoint.Callout
import Fixpoint.Checks
import Fixpoint.Code
import Fixpoint.Cta
import Fixpoint.Footer
import Fixpoint.Grid
import Fixpoint.Headline
import Fixpoint.Hero
import Fixpoint.Nav
import Fixpoint.Section
import Fixpoint.Style
import Html exposing (Attribute, Html, a, b, code, div, em, h3, img, li, node, p, span, strong, table, tbody, td, text, th, thead, tr, ul)
import Html.Attributes exposing (alt, attribute, class, href, src)


main : Program Flags Model Msg
main =
    Browser.element
        { init = init
        , update = update
        , view = view
        , subscriptions = subscriptions
        }


type alias Flags =
    { pathname : String }


type Page
    = Landing
    | Compactness
    | Security
    | Config
    | Cli
    | Playground


type alias Model =
    Page


type Msg
    = NoOp


init : Flags -> ( Model, Cmd Msg )
init flags =
    ( parsePage (stripVisagePrefix flags.pathname), Cmd.none )


{-| Strip a leading `/visage` prefix and any surrounding slashes so the result
is the bare sub-page slug (e.g. `"/visage/compactness/"` -> `"compactness"`,
`"/visage/"` -> `""`). Falls back to `""` for `/`.
-}
stripVisagePrefix : String -> String
stripVisagePrefix raw =
    let
        withoutPrefix =
            if String.startsWith "/visage" raw then
                String.dropLeft (String.length "/visage") raw

            else if raw == "/" then
                ""

            else
                raw
    in
    withoutPrefix
        |> String.dropLeft (if String.startsWith "/" withoutPrefix then 1 else 0)
        |> (\s -> if String.endsWith "/" s then String.dropRight 1 s else s)


parsePage : String -> Page
parsePage path =
    case path of
        "" ->
            Landing

        "compactness" ->
            Compactness

        "security" ->
            Security

        "config" ->
            Config

        "cli" ->
            Cli

        "playground" ->
            Playground

        _ ->
            Landing


update : Msg -> Model -> ( Model, Cmd Msg )
update _ model =
    ( model, Cmd.none )


subscriptions : Model -> Sub Msg
subscriptions _ =
    Sub.none


view : Model -> Html Msg
view model =
    div [] [ Fixpoint.Style.stylesheet, navView, pageView model, footerView ]



-- Route helpers (absolute hrefs + `data-mfe-route` for in-shell nav)


routeHref : String -> String
routeHref sub =
    "https://fixpointlinux.org/visage" ++ sub ++ "/"


routeAttr : String -> Attribute Msg
routeAttr sub =
    attribute "data-mfe-route" ("/visage" ++ sub)


docLink : String -> String -> Html Msg
docLink sub label =
    a [ href (routeHref sub), routeAttr sub ] [ text label ]



-- Top nav


navView : Html Msg
navView =
    Fixpoint.Nav.view
        { brand =
            span []
                [ span [ class "fx" ] [ text "fx" ]
                , text "://visage"
                ]
        , links =
            [ docLink "" "Overview"
            , docLink "/compactness" "Compactness"
            , docLink "/security" "Security"
            , docLink "/config" "Config"
            , docLink "/cli" "CLI"
            ]
        , extra =
            [ a [ class "home", href (routeHref "/playground"), routeAttr "/playground" ] [ text "Playground" ]
            , a [ class "home", href "https://fixpointlinux.org/", attribute "data-mfe-route" "/" ] [ text "fixpoint-linux" ]
            ]
        }


pageView : Model -> Html Msg
pageView model =
    case model of
        Landing ->
            landingView

        Compactness ->
            compactnessView

        Security ->
            securityView

        Config ->
            configView

        Cli ->
            cliView

        Playground ->
            playgroundView


footerView : Html Msg
footerView =
    Fixpoint.Footer.view
        [ text "visage source lives in "
        , a [ href "https://github.com/fixpoint-linux/visage" ] [ text "github.com/fixpoint-linux/visage" ]
        , Fixpoint.Footer.sep
        , text "part of "
        , a [ href "https://fixpointlinux.org" ] [ text "fixpoint-linux" ]
        ]



-- Landing


landingView : Html Msg
landingView =
    div []
        [ Fixpoint.Hero.view
            { prompt =
                [ Fixpoint.Hero.hash
                , text " visage "
                , Fixpoint.Hero.dollar
                , text " ./visage.com daemon -c config.example.dhall"
                , Fixpoint.Hero.blink
                ]
            , title =
                [ text "Email aliases that "
                , Fixpoint.Hero.fx [ text "hide your real address" ]
                , text "."
                ]
            , tagline =
                [ text "a compact "
                , b [] [ text "alias@domain" ]
                , text " forwarding server — C11 · typechecked Dhall · cosmocc · DAFSA store"
                ]
            }
        , Fixpoint.Section.view
            { id = "idea"
            , title = "The idea: disposable aliases"
            , hint = "// alias@domain → your real inbox, and reply through it"
            , children =
                [ p []
                    [ text "Give out disposable "
                    , strong [] [ text "alias@domain" ]
                    , text " addresses that forward to your real inbox — and reply through them too. You never hand out your real address; only disposable aliases. Replies route back through a "
                    , Fixpoint.Code.inline "reply+<token>@yourdomain"
                    , text " reverse alias, so the sender only ever sees the alias."
                    ]
                , p []
                    [ text "The whole service — "
                    , em [] [ text "daemon and alias store" ]
                    , text " — fits in one small, portable APE binary, configured in typechecked Dhall. The same C core also builds to WebAssembly and runs fully client-side in your browser."
                    ]
                , Fixpoint.Cta.view
                    { body =
                        [ strong [] [ text "Try it right here" ]
                        , text " — the real C config + alias pipeline, compiled to WebAssembly, runs in your browser. No setup, no server."
                        ]
                    , href = routeHref "/playground"
                    , label = "Open the Playground →"
                    , attrs = [ routeAttr "/playground" ]
                    }
                , Fixpoint.Checks.view
                    [ li [] [ b [] [ text "One C codebase" ], text " — one ", Fixpoint.Code.inline "visage.com", text " APE binary, no VM, no runtime, no database process." ]
                    , li [] [ b [] [ text "DAFSA alias store" ], text " — aliases live in a minimal acyclic DAFSA sharing prefixes and suffixes; lookups are byte-prefix walks." ]
                    , li [] [ b [] [ text "Reverse-alias reply" ], text " — reply through a ", Fixpoint.Code.inline "reply+<token>", text " address so your real address stays hidden." ]
                    ]
                ]
            }
        , Fixpoint.Section.view
            { id = "targets"
            , title = "One source, two targets"
            , hint = "// native APE · browser wasm"
            , children =
                [ Fixpoint.Headline.view
                    [ Fixpoint.Headline.card
                        { n = "01"
                        , title = [ text "Native binary — ", code [] [ text "visage.com" ] ]
                        , body =
                            [ p []
                                [ text "A single self-contained "
                                , strong [] [ text "~2.6 MB" ]
                                , text " polyglot binary — an Actually Portable Executable built with "
                                , Fixpoint.Code.inline "cosmocc"
                                , text ". The same file runs on Linux, macOS, Windows, and the BSDs with no VM, no runtime, no recompile."
                                ]
                            , p []
                                [ text "An SMTP receiver with a typechecked Dhall config, alias + reverse-alias forwarding, STARTTLS relay (optionally cert-verified), DKIM signing, and a durable outbound retry queue."
                                ]
                            ]
                        }
                    , Fixpoint.Headline.card
                        { n = "02"
                        , title = [ text "In the browser — ", code [] [ text "visage.wasm" ] ]
                        , body =
                            [ p []
                                [ text "The real C config + alias pipeline compiled to a small "
                                , Fixpoint.Code.inline ".wasm"
                                , text " module. It runs 100% client-side — the actual "
                                , Fixpoint.Code.inline "config_load"
                                , text " + address resolution, no server, no build step. Your config and addresses never leave the tab."
                                ]
                            , p [] [ docLink "/playground" "The live alias resolver →" ]
                            ]
                        }
                    ]
                ]
            }
        , Fixpoint.Section.view
            { id = "features"
            , title = "Feature summary"
            , hint = "// the whole service in one table"
            , children =
                [ table [ class "features" ]
                    [ thead []
                        [ tr []
                            [ th [] [ text "Area" ]
                            , th [] [ text "Capabilities" ]
                            ]
                        ]
                    , tbody []
                        [ tr []
                            [ td [ class "name" ] [ text "Config" ]
                            , td [] [ text "Typechecked Dhall record (aliases, domains, relay, limits, storage, DKIM) evaluated at startup — config errors surface before the daemon binds a port." ]
                            ]
                        , tr []
                            [ td [ class "name" ] [ text "SMTP" ]
                            , td [] [ text "Hand-rolled RFC 5321 state machine for receiver and relay (HELO/EHLO, MAIL, RCPT, DATA) with full bounds-checking on the wire path." ]
                            ]
                        , tr []
                            [ td [ class "name" ] [ text "Store" ]
                            , td [] [ text "datalog-dafsa minimal-DAFSA store: fixed-width big-endian keys, symbol interner, WAL + flock, mmap zero-copy reads. Prefix-search lookups, no separate index." ]
                            ]
                        , tr []
                            [ td [ class "name" ] [ text "Delivery" ]
                            , td [] [ text "Durable outbound retry queue (spooled to disk, bounded retries), STARTTLS / STARTTLS-verify relay, DKIM signing." ]
                            ]
                        , tr []
                            [ td [ class "name" ] [ text "Reply" ]
                            , td [] [ text "Reverse-alias reply routing via ", Fixpoint.Code.inline "reply+<token>@domain", text " — 32-hex-char tokens from /dev/urandom, 30-day TTL." ]
                            ]
                        ]
                    ]
                ]
            }
        , Fixpoint.Section.view
            { id = "compact"
            , title = "Compact server, compact store"
            , hint = "// ~480 B/alias · sub-linear resolve"
            , children =
                [ p []
                    [ text "Two things stay small as you grow: the server is one ≈2.6 MB APE binary, and its alias store is a "
                    , strong [] [ text "minimal DAFSA" ]
                    , text " that shares prefixes and suffixes across every key — on-disk size is ~480 B/alias at 1,000 aliases and ~542 B/alias at 1,000,000, roughly constant across three decades."
                    ]
                , p []
                    [ text "Email routing needs exactly two lookups, and both are native DAFSA primitives: forward routing ("
                    , Fixpoint.Code.inline "alias@domain"
                    , text " → destinations) and reverse reply routing ("
                    , Fixpoint.Code.inline "reply+<token>"
                    , text " → sender) are byte-prefix walks, O(prefix length) regardless of alias count. "
                    ]
                , p [] [ docLink "/compactness" "The compactness & prefix-search story →" ]
                ]
            }
        , Fixpoint.Section.view
            { id = "how"
            , title = "One daemon, end to end"
            , hint = "// accept · forward · reply"
            , children =
                [ Fixpoint.Headline.view
                    [ Fixpoint.Headline.card
                        { n = "1"
                        , title = [ text "Accept" ]
                        , body =
                            [ p [] [ text "The SMTP receiver (", Fixpoint.Code.inline "src/smtp_in.c", text ") parses the envelope, gates on served domains, and resolves each alias@domain case-insensitively against the DAFSA store, falling back to catch-all." ]
                            ]
                        }
                    , Fixpoint.Headline.card
                        { n = "2"
                        , title = [ text "Forward" ]
                        , body =
                            [ p [] [ text "Accepted mail is spooled to disk and handed to the outbound queue (", Fixpoint.Code.inline "src/smtp_out.c", text "): bounded retries, STARTTLS to the relay, DKIM-signed before it goes out." ]
                            ]
                        }
                    , Fixpoint.Headline.card
                        { n = "3"
                        , title = [ text "Reply privately" ]
                        , body =
                            [ p [] [ text "When you reply, the ", Fixpoint.Code.inline "reply+<token>@yourdomain", text " reverse alias (", Fixpoint.Code.inline "src/reply.c", text ") routes back to the original sender — the sender only ever sees your alias." ]
                            ]
                        }
                    ]
                ]
            }
        , Fixpoint.Section.view
            { id = "quickstart"
            , title = "Quickstart"
            , hint = "// make · make wasm"
            , children =
                [ Fixpoint.Code.block
                    [ text "git submodule update --init --recursive   # fetch vendor/dhall-c + vendor/datalog-dafsa\n"
                    , text "make                                      # builds visage.com (APE) + *_check tools\n"
                    , text "make wasm                                 # → docs/visage.js + docs/visage.wasm\n"
                    , text "node tests/wasm-smoke.js                  # headless smoke test of the wasm module"
                    ]
                , p [] [ docLink "/cli" "The full CLI reference & usage →" ]
                ]
            }
        , Fixpoint.Section.view
            { id = "reference"
            , title = "Reference pages"
            , hint = "// compactness · security · config · cli · playground"
            , children =
                [ ul []
                    [ li [] [ docLink "/compactness" "Compactness", text " — the DAFSA store, prefix search, and the benchmark numbers." ]
                    , li [] [ docLink "/security" "Security", text " — the wire-path hardening and the pre-launch review." ]
                    , li [] [ docLink "/config" "Config", text " — the typechecked Dhall schema and ", Fixpoint.Code.inline "config.example.dhall", text "." ]
                    , li [] [ docLink "/cli" "CLI", text " — daemon, config-check, add-alias, rm-alias, log." ]
                    , li [] [ docLink "/playground" "Playground", text " — the wasm alias resolver, in your browser." ]
                    ]
                ]
            }
        ]



-- Compactness


compactnessView : Html Msg
compactnessView =
    div []
        [ Fixpoint.Hero.view
            { prompt =
                [ Fixpoint.Hero.hash
                , text " visage "
                , Fixpoint.Hero.dollar
                , text " make bench"
                , Fixpoint.Hero.blink
                ]
            , title = [ text "Compact by design" ]
            , tagline = []
            }
        , Fixpoint.Section.view
            { id = "store"
            , title = "The data store"
            , hint = "// minimal acyclic DAFSA · interned symbols · mmap + WAL"
            , children =
                [ p []
                    [ text "Aliases live in a datalog-dafsa store built on a "
                    , strong [] [ text "minimal acyclic DAFSA" ]
                    , text " — a graph that shares common prefixes "
                    , em [] [ text "and" ]
                    , text " suffixes across every key, so the store stays tiny even as you add thousands of aliases. Strings are interned to 32-bit symbol ids; each relation is one on-disk DAFSA that is mmap'd for read-only serving and durably WAL'd (single-writer, "
                    , Fixpoint.Code.inline "flock"
                    , text ")."
                    ]
                , p []
                    [ text "Measured ("
                    , Fixpoint.Code.inline "make bench"
                    , text "): on-disk store size is ~480 B/alias at 1,000 aliases and ~542 B/alias at 1,000,000 — roughly "
                    , strong [] [ text "constant across three decades" ]
                    , text ", with no per-alias index bloat. The footprint is dominated by the string interner (every distinct address stored once), not per-alias metadata."
                    ]
                , img [ src "/visage/bench-size.svg", alt "Store size in bytes per alias vs alias count: roughly constant near 500 bytes", attribute "style" "width:100%;height:auto;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px;margin:12px 0" ] []
                ]
            }
        , Fixpoint.Section.view
            { id = "prefix"
            , title = "Prefix search, not indexes"
            , hint = "// forward + reverse routing are byte-prefix walks"
            , children =
                [ p []
                    [ text "Email routing needs exactly two lookups, and both are native DAFSA primitives — so visage carries "
                    , strong [] [ text "no separate index" ]
                    , text ", and lookup cost scales with address length, not alias count."
                    ]
                , Fixpoint.Checks.view
                    [ li [] [ b [] [ text "Forward routing" ], text " — resolving ", Fixpoint.Code.inline "alias@domain", text " → its destinations is a prefix walk binding the (domain, local) columns of the ", Fixpoint.Code.inline "alias", text " relation." ]
                    , li [] [ b [] [ text "Reverse reply routing" ], text " — ", Fixpoint.Code.inline "reply+<token>@domain", text " → (original sender, alias) is a prefix walk binding the ", Fixpoint.Code.inline "token", text " column of the ", Fixpoint.Code.inline "revmap", text " relation." ]
                    , li [] [ b [] [ text "O(prefix), not O(aliases)" ], text " — alias resolution and reply-token routing are O(prefix length) regardless of how many aliases exist." ]
                    ]
                , p []
                    [ text "Measured ("
                    , Fixpoint.Code.inline "make bench"
                    , text "): warm "
                    , Fixpoint.Code.inline "store_resolve"
                    , text "/"
                    , Fixpoint.Code.inline "store_revmap_resolve"
                    , text " latency is ~0.6 µs at 1,000 aliases and ~3 µs at 1,000,000 — "
                    , strong [] [ text "sub-linear" ]
                    , text " (≈5× over three decades of scale), i.e. the cost tracks address length, not alias count."
                    ]
                , img [ src "/visage/bench-latency.svg", alt "Resolve latency vs alias count: sub-linear, about 0.6 microseconds at 1k aliases to about 3 microseconds at 1M", attribute "style" "width:100%;height:auto;background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px;margin:12px 0" ] []
                ]
            }
        ]



-- Security


securityView : Html Msg
securityView =
    div []
        [ Fixpoint.Hero.view
            { prompt =
                [ Fixpoint.Hero.hash
                , text " visage "
                , Fixpoint.Hero.dollar
                , text " ./visage.com config-check -c config.example.dhall"
                , Fixpoint.Hero.blink
                ]
            , title = [ text "Security posture" ]
            , tagline = []
            }
        , Fixpoint.Section.view
            { id = "posture"
            , title = "The wire path is hand-rolled C11"
            , hint = "// so the hardening is explicit"
            , children =
                [ p []
                    [ text "visage was given a deep wire-path security review before public launch (3 HIGH + 4 MEDIUM findings, all fixed, no CRITICAL). Where it stands:"
                    ]
                , Fixpoint.Checks.view
                    [ li [] [ b [] [ text "Wire memory safety" ], text " — bounded per-connection buffers on the SMTP and admin paths; a reply-backlog cap (", Fixpoint.Code.inline "SMTP_IN_MAX_OUT", text " 256 KB) + TCP backpressure; hard command-length limits." ]
                    , li [] [ b [] [ text "Reply tokens" ], text " — 32 hex chars from ", Fixpoint.Code.inline "/dev/urandom", text ", no weak fallback (fail-closed), expiring after 30 days. Tokens are the reply feature's only credential." ]
                    , li [] [ b [] [ text "Admin API" ], text " — constant-time bearer-token comparison; ", Fixpoint.Code.inline "config-check", text " rejects tokens that can never authenticate (>500 chars) and warns on weak defaults." ]
                    , li [] [ b [] [ text "Anti-injection" ], text " — MAIL FROM and RCPT validated (printable ASCII, no quote/angle chars); no SMTP-envelope CRLF injection to the relay; mail with NUL/control bytes rejected (", Fixpoint.Code.inline "554", text ")." ]
                    , li [] [ b [] [ text "Relay integrity" ], text " — ", Fixpoint.Code.inline "starttls-verify", text " does mandatory STARTTLS with CA + hostname verification and never falls back to plaintext or sends AUTH over it." ]
                    , li [] [ b [] [ text "Availability" ], text " — inbound SMTP rate-bounded (512 conns global / 16 per-IP, ", Fixpoint.Code.inline "421", text " on excess); queue-driven relay sends batched (8/tick); null reverse-path preserved end-to-end (", Fixpoint.Code.inline "MAIL FROM:<>", text ")." ]
                    , li [] [ b [] [ text "Browser demo" ], text " — remote ", Fixpoint.Code.inline "http://", text " Dhall imports are compiled out of the wasm build, so a pasted config can't make your browser probe URLs." ]
                    ]
                , Fixpoint.Callout.note
                    [ text "The wasm demo stubs out "
                    , code [] [ text "http_fetch" ]
                    , text " / "
                    , code [] [ text "url_dirname" ]
                    , text " / "
                    , code [] [ text "url_join" ]
                    , text " so no remote import ever issues an XHR — a hostile pasted config cannot SSRF from visitor browsers."
                    ]
                ]
            }
        ]



-- Config


configView : Html Msg
configView =
    div []
        [ Fixpoint.Hero.view
            { prompt =
                [ Fixpoint.Hero.hash
                , text " visage "
                , Fixpoint.Hero.dollar
                , text " ./visage.com config-check -c config.example.dhall"
                , Fixpoint.Hero.blink
                ]
            , title = [ text "Config format" ]
            , tagline = []
            }
        , Fixpoint.Section.view
            { id = "config"
            , title = "A typechecked Dhall record"
            , hint = "// aliases · domains · relay · limits · storage · DKIM"
            , children =
                [ p []
                    [ text "The config is a Dhall record — aliases, domains, relay, limits, storage, DKIM keys — typechecked against its schema before the daemon binds a port. Config errors (bad types, unknown fields) are caught at startup, not at 3 a.m. when mail bounces."
                    ]
                , Fixpoint.Code.block
                    [ text "let Auth = { enabled : Bool, username : Text, password : Text }\n"
                    , text "in  let Config =\n"
                    , text "      { hostname : Text\n"
                    , text "      , domains : List Text\n"
                    , text "      , listen : { address : Text, port : Natural }\n"
                    , text "      , limits : { message : Natural, line : Natural, rcpts : Natural\n"
                    , text "                 , cmd_timeout : Natural, data_timeout : Natural }\n"
                    , text "      , relay : { host : Text, port : Natural, auth : Auth, retries : Natural\n"
                    , text "                , tls : Text, tls_ca : Text, max_attempts : Natural }\n"
                    , text "      , storage : { path : Text, spool : Text, retention_days : Natural }\n"
                    , text "      , reply : { prefix : Text, separator : Text }\n"
                    , text "      , catch_all : Text\n"
                    , text "      , aliases : List { alias : Text, destinations : List Text }\n"
                    , text "      , http : { address : Text, port : Natural }\n"
                    , text "      , admin : { token : Text }\n"
                    , text "      , dkim : List { domain : Text, selector : Text, private_key : Text }\n"
                    , text "      }\n"
                    , text "in  { hostname = \"mx.example.com\"\n"
                    , text "    , domains = [ \"example.com\" ]\n"
                    , text "    , listen = { address = \"0.0.0.0\", port = 2525 }\n"
                    , text "    , limits = { message = 26214400, line = 1000, rcpts = 100\n"
                    , text "               , cmd_timeout = 300, data_timeout = 600 }\n"
                    , text "    , relay = { host = \"127.0.0.1\", port = 2526\n"
                    , text "              , auth = { enabled = False, username = \"\", password = \"\" }\n"
                    , text "              , retries = 3, tls = \"none\", tls_ca = \"\", max_attempts = 100 }\n"
                    , text "    , storage = { path = \"./var/db\", spool = \"./var/spool\", retention_days = 30 }\n"
                    , text "    , reply = { prefix = \"reply\", separator = \"+\" }\n"
                    , text "    , catch_all = \"\"\n"
                    , text "    , aliases = [ { alias = \"jane@example.com\", destinations = [ \"jane@realmail.example\" ] }\n"
                    , text "                , { alias = \"shopping@example.com\", destinations = [ \"jane@realmail.example\", \"bob@realmail.example\" ] }\n"
                    , text "                ]\n"
                    , text "    , http = { address = \"127.0.0.1\", port = 8080 }\n"
                    , text "    , admin = { token = \"change-me\" }\n"
                    , text "    , dkim = [] : List { domain : Text, selector : Text, private_key : Text }\n"
                    , text "    } : Config"
                    ]
                , p []
                    [ Fixpoint.Code.inline "relay.tls"
                    , text " is "
                    , Fixpoint.Code.inline "none"
                    , text ", "
                    , Fixpoint.Code.inline "starttls"
                    , text ", or "
                    , Fixpoint.Code.inline "starttls-verify"
                    , text ". An empty "
                    , Fixpoint.Code.inline "tls_ca"
                    , text " uses the embedded Mozilla CA bundle (only consulted when tls == "
                    , Fixpoint.Code.inline "starttls-verify"
                    , text "). "
                    , Fixpoint.Code.inline "admin.token"
                    , text " is the bearer token for the admin HTTP API — a real deployment must use a long random token (a 500-char ceiling is enforced)."
                    ]
                ]
            }
        ]



-- CLI


cliView : Html Msg
cliView =
    div []
        [ Fixpoint.Hero.view
            { prompt =
                [ Fixpoint.Hero.hash
                , text " visage "
                , Fixpoint.Hero.dollar
                , text " ./visage.com add-alias -c config.example.dhall --alias dev@example.com --dest me@real.example"
                , Fixpoint.Hero.blink
                ]
            , title = [ text "CLI & usage" ]
            , tagline = []
            }
        , Fixpoint.Section.view
            { id = "usage"
            , title = "Subcommands"
            , hint = "// daemon · config-check · add-alias · rm-alias · log"
            , children =
                [ Fixpoint.Code.block
                    [ text "./visage.com <command> [options]\n"
                    , text "\n"
                    , text "  daemon -c FILE          run the SMTP + admin HTTP daemon\n"
                    , text "  config-check -c FILE    validate the config file and exit\n"
                    , text "  add-alias -c FILE --alias A@D --dest X@Y\n"
                    , text "                          add an alias via the running daemon\n"
                    , text "  rm-alias  -c FILE --alias A@D --dest X@Y\n"
                    , text "                          remove an alias via the running daemon\n"
                    , text "  log -c FILE [-n N]      print recent log entries via the daemon\n"
                    , text "  --help · --version"
                    ]
                , p []
                    [ text "The daemon owns the store (single-writer "
                    , Fixpoint.Code.inline "flock"
                    , text "); the CLI admin subcommands ("
                    , Fixpoint.Code.inline "add-alias"
                    , text ", "
                    , Fixpoint.Code.inline "rm-alias"
                    , text ", "
                    , Fixpoint.Code.inline "log"
                    , text ") are HTTP clients to the running daemon, not direct store writers."
                    ]
                ]
            }
        , Fixpoint.Section.view
            { id = "build"
            , title = "Build"
            , hint = "// cosmocc · make · make wasm"
            , children =
                [ p [] [ text "Requires ", Fixpoint.Code.inline "cosmocc", text ". ", Fixpoint.Code.inline "dhall-c", text " and ", Fixpoint.Code.inline "datalog-dafsa", text " are vendored as git submodules; mbedTLS is vendored under ", Fixpoint.Code.inline "vendor/", text "." ]
                , Fixpoint.Code.block
                    [ text "git submodule update --init --recursive   # fetch vendor/dhall-c + vendor/datalog-dafsa\n"
                    , text "make                                      # builds visage.com (APE) + visage.com.dbg (ELF) + *_check tools"
                    ]
                , p []
                    [ text "To use sibling "
                    , Fixpoint.Code.inline "dhall-c"
                    , text "/"
                    , Fixpoint.Code.inline "datalog-dafsa"
                    , text " checkouts instead of the submodules, build with "
                    , Fixpoint.Code.inline "make DHALL_C=../dhall-c DATALOG=../datalog-dafsa"
                    , text " (likewise "
                    , Fixpoint.Code.inline "scripts/build-wasm.sh"
                    , text " honors "
                    , Fixpoint.Code.inline "DHALL_C"
                    , text ")."
                    ]
                , p [] [ text "For the browser build (needs ", Fixpoint.Code.inline "emscripten clang lld llvm nodejs", text "):" ]
                , Fixpoint.Code.block
                    [ text "make wasm                # → docs/visage.js + docs/visage.wasm\n"
                    , text "node tests/wasm-smoke.js # headless smoke test of the wasm module"
                    ]
                ]
            }
        ]



-- Playground


playgroundView : Html Msg
playgroundView =
    div []
        [ Fixpoint.Hero.view
            { prompt =
                [ Fixpoint.Hero.hash
                , text " visage "
                , Fixpoint.Hero.dollar
                , text " make wasm"
                , Fixpoint.Hero.blink
                ]
            , title = [ text "Playground" ]
            , tagline = []
            }
        , Fixpoint.Section.view
            { id = "playground"
            , title = "Resolve an alias"
            , hint = "// the real config + alias pipeline, in your browser"
            , children =
                [ p []
                    [ text "Edit the Dhall config (a real "
                    , strong [] [ text "CodeMirror" ]
                    , text " editor with Dhall highlighting), then type an "
                    , Fixpoint.Code.inline "alias@domain"
                    , text " address and press "
                    , strong [] [ text "Run" ]
                    , text ". The "
                    , em [] [ text "actual C pipeline" ]
                    , text " ("
                    , Fixpoint.Code.inline "src/config.c"
                    , text " + "
                    , Fixpoint.Code.inline "src/mail.c"
                    , text ", compiled to wasm) parses the config, typechecks it, and resolves the address — accept/reject, via alias or catch-all."
                    ]
                , node "visage-playground" [] []
                ]
            }
        , Fixpoint.Section.view
            { id = "rebuild"
            , title = "Rebuild"
            , hint = "// make wasm"
            , children =
                [ p []
                    [ text "The WebAssembly bundle is rebuilt from the C source with "
                    , Fixpoint.Code.inline "make wasm"
                    , text "; see "
                    , a [ href "https://github.com/fixpoint-linux/visage" ] [ text "the repo" ]
                    , text " for details."
                    ]
                ]
            }
        ]
