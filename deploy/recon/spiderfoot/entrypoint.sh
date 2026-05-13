#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2024-2026 usulnet contributors
#
# recon-spiderfoot entrypoint.  Writes a minimal spiderfoot.cfg that
# disables every module requiring an API key (the usulnet host enables
# them per-connector at runtime via the HTTP API), then execs sf.py.
set -eu

CFG="${SPIDERFOOT_HOME:-/tmp}/spiderfoot.cfg"

# Only write the config on first start; if a connector has already
# updated values via the API, do not clobber them.
if [ ! -f "$CFG" ]; then
    cat > "$CFG" <<'EOF'
# Minimal spiderfoot.cfg written by recon-spiderfoot entrypoint.
# Modules requiring an external API key are disabled by default.  The
# usulnet host enables them per-connector via the SpiderFoot HTTP API at
# runtime when the operator configures credentials.
__database=spiderfoot.db
__modules_disabled=sfp_hibp,sfp_shodan,sfp_intelx,sfp_virustotal,sfp_securitytrails,sfp_fullcontact,sfp_haveibeenpwned,sfp_emailrep,sfp_apility,sfp_riskiq,sfp_pulsedive,sfp_zetalytics,sfp_circl,sfp_alienvault,sfp_greynoise
__logging=1
EOF
fi

exec python3 /opt/spiderfoot/sf.py -l 0.0.0.0:5001 -q
