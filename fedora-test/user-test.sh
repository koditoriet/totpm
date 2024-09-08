#!/bin/bash
set -exo pipefail
cd "$HOME"
totpm init
[ "$(totpm list)" == "" ]
[ -f ".local/state/totpm/secrets.sqlite" ]

# base32("hellohello")
echo "NBSWY3DPNBSWY3DP" | totpm add --secret-on-stdin foo bar
[ "$(totpm list)" == "foo (bar)" ]
[ "$(totpm gen foo bar)" != "" ]

totpm del foo bar
[ "$(totpm list)" == "" ]

echo "NBSWY3DPNBSWY3DP" | totpm add --secret-on-stdin foo bar
totpm clear --yes-i-know-what-i-am-doing
[ ! -f ".local/state/totpm/secrets.sqlite" ]
[ "$(totpm list)" == "" ]
