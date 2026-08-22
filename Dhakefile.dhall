-- Dhakefile.dhall — build visage's docs site with dhake.
--
-- Web build:
--    ./vendor/dhake/dhake.com            # default target: dist/index.html
--    ./vendor/dhake/dhake.com dist/index.html   # the docs site (Elm + MFE + SSG)
--
--   The site is an Elm app (src/Main.elm) rendered against the shared
--   Fixpoint.* design package (the `design` submodule at vendor/design) and
--   the mfe-framework (the `mfe-framework` submodule at vendor/mfe-framework).
--   The pipeline:
--     1. build mfe-framework (tsc) -> its dist JS at vendor/mfe-framework/packages/*/dist
--     2. copy mfe-framework dist JS into vendor/@mfe/  (served here)
--     3. elm make src/Main.elm -> dist/elm.js
--     4. node scripts/ssg.mjs   -> dist/index.html + dist/<slug>/index.html (SSG render)

let Action =
      < Shell : Text
      | Copy : { from : Text, to : Text }
      | Mkdir : < Plain : Text | Parents : { path : Text, parents : Bool } >
      | Rm : < Plain : Text | Recursive : { path : Text, recursive : Bool } >
      | Touch : Text
      | Move : { from : Text, to : Text }
      | Symlink : { from : Text, to : Text }
      | Chmod : { path : Text, mode : Text }
      | Echo : Text
      | Env : { key : Text, value : Text }
      | Run : { argv : List Text }
      >

let Target = { deps : List Text, phony : Bool, recipe : List Action }

in  { targets =
        [ { mapKey = "mfe-framework"
          , mapValue =
              { deps = [] : List Text
              , phony = True
              , recipe =
                  [ < Shell = "cd vendor/mfe-framework && npm ci && npm run build" > ]
              }
          }
        , { mapKey = "vendor-mfe"
          , mapValue =
              { deps = [ "mfe-framework" ]
              , phony = True
              , recipe =
                  [ < Rm = { path = "vendor/@mfe", recursive = True } >
                  , < Mkdir = { path = "vendor/@mfe/core", parents = True } >
                  , < Mkdir = { path = "vendor/@mfe/framework", parents = True } >
                  , < Shell =
                        "cp vendor/mfe-framework/packages/core/dist/*.js vendor/@mfe/core/"
                    >
                  , < Shell =
                        "cp vendor/mfe-framework/packages/framework/dist/*.js vendor/@mfe/framework/"
                    >
                  ]
              }
          }
        , { mapKey = "dist/elm.js"
          , mapValue =
              { deps = [ "src/Main.elm", "elm.json", "vendor/design/src" ]
              , phony = False
              , recipe =
                  [ < Shell =
                        "node_modules/elm/bin/elm make src/Main.elm --output=dist/elm.js --optimize"
                    >
                  ]
              }
          }
        , { mapKey = "dist/index.html"
          , mapValue =
              { deps =
                  [ "dist/elm.js"
                  , "vendor-mfe"
                  , "shell/index.html"
                  , "shell/pages.js"
                  , "shell/shell.js"
                  , "shell/templates/visage-landing.html"
                  , "shell/templates/visage-compactness.html"
                  , "shell/templates/visage-security.html"
                  , "shell/templates/visage-config.html"
                  , "shell/templates/visage-cli.html"
                  , "shell/templates/visage-playground.html"
                  , "shell/templates/fixpoint.html"
                  , "shell/mfe/visage-page.js"
                  , "shell/mfe/visage-playground.js"
                  , "scripts/ssg.mjs"
                  , "docs/visage.js"
                  , "docs/visage.wasm"
                  , "docs/app.js"
                  , "docs/bench-size.svg"
                  , "docs/bench-latency.svg"
                  , "docs/vendor/codemirror.min.js"
                  , "docs/vendor/codemirror.css"
                  , "docs/vendor/codemirror-simple.js"
                  , "docs/vendor/dhall-mode.js"
                  ]
              , phony = False
              , recipe = [ < Shell = "node scripts/ssg.mjs" > ]
              }
          }
        ]
      , default = "dist/index.html"
      }
