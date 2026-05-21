# Marketplace catalogue — upstream image licenses

Every template in `apps/<slug>/` references a publicly-published
container image. The table below records the upstream license usulnet
ships under, the image it pulls at install time, and the source URL the
audit was performed against. The catalogue ships as part of usulnet
itself (AGPL-3.0-or-later); the upstream images keep their own license
and are not redistributed by usulnet — they are pulled from the
operator's configured registry at install time.

A new entry in this table is **required** for every PR that adds an
`apps/<slug>/` directory. The marketplace service refuses to load
manifests with an empty `license:` field, so the audit cannot be skipped
silently.

| Slug | Upstream | Image | License | AGPL-compatible | Notes |
|---|---|---|---|---|---|
| `nginx-demo` | nginx | `docker.io/library/nginx:1.27-alpine` | BSD-2-Clause | Yes | Reference: https://github.com/nginx/nginx/blob/master/docs/text/LICENSE |
| `whoami` | traefik/whoami | `docker.io/traefik/whoami:v1.10` | MIT | Yes | Reference: https://github.com/traefik/whoami/blob/master/LICENSE.md |
| `gitea` | Gitea | `docker.io/gitea/gitea:1.22` | MIT | Yes | Reference: https://github.com/go-gitea/gitea/blob/main/LICENSE |
| `uptime-kuma` | Uptime Kuma | `docker.io/louislam/uptime-kuma:1.23.13-alpine` | MIT | Yes | Reference: https://github.com/louislam/uptime-kuma/blob/master/LICENSE |
| `cowrie` | Cowrie | `docker.io/cowrie/cowrie:2.5.0` | BSD-3-Clause | Yes | Reference: https://github.com/cowrie/cowrie/blob/master/LICENSE.rst |
| `dionaea` | DinoTools/dionaea | `docker.io/dinotools/dionaea:0.11.0` | GPL-2.0-or-later | Yes | Reference: https://github.com/DinoTools/dionaea/blob/master/LICENSE |
| `endlessh` | linuxserver/endlessh (skeeto/endlessh) | `lscr.io/linuxserver/endlessh:1.1` | GPL-3.0-or-later | Yes | Reference: https://github.com/skeeto/endlessh/blob/master/COPYING |
| `tor-socks-proxy` | PeterDaveHello/tor-socks-proxy (Tor Project) | `docker.io/peterdavehello/tor-socks-proxy:0.4.8` | BSD-3-Clause | Yes | Reference: https://github.com/PeterDaveHello/tor-socks-proxy/blob/master/LICENSE — Tor itself ships under the modified BSD maintained by the Tor Project |

## AGPL compatibility policy

All catalogue templates **must** reference images under licenses that
do not impose obligations stricter than AGPL-3.0-or-later. The
following families are accepted without further review:

- MIT, BSD-2-Clause, BSD-3-Clause, ISC
- Apache-2.0
- MPL-2.0
- LGPL (2.1, 3.0)
- GPL-2.0-or-later, GPL-3.0-or-later
- AGPL-3.0-or-later

Anything else (proprietary, source-available, "free for personal use",
SSPL, Elastic License, BSL, CC-BY-NC-*) is **rejected**.

When in doubt, link the upstream `LICENSE` file in the table above and
ask in the PR. The marketplace catalogue is the most-visible curated
surface in usulnet; shipping a non-AGPL-compatible app would violate
both the AGPL build promise and the no-call-home principle (because the
operator would be using a proprietary image without realising it).

## Hosting model

usulnet does **not** rehost upstream images. At install time, the
generated `docker-compose.yml` references the image by its full
canonical name; the operator's Docker daemon pulls it from
`docker.io` (or whichever registry mirror they have configured). usulnet
caches nothing on its own infrastructure and makes no outbound network
calls to validate or update the catalogue.
