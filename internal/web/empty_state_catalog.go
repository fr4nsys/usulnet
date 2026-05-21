// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"github.com/fr4nsys/usulnet/internal/web/templates/components"
)

// Empty-state catalog (v26.5.2 session 05).
//
// One function per module returns the EmptyStateData rendered when
// that module's primary list is empty. Centralising the copy here
// means reviewers can audit every operator-facing empty-state
// message in one diff, and the per-module templ files only call
// EmptyStateCatalog<Module>() — they never own the wording.
//
// Copy guidelines:
//
//   - Title: noun in title case. The thing being listed
//     ("Firewall rules", "DNS providers", etc.).
//   - What:  one sentence describing the module mechanically. No
//     marketing voice; just say what it does.
//   - Why:   one sentence explaining operator value. Why would they
//     configure one? What pain does it solve?
//   - CTAs:  one primary "create" action, then one "Read the docs"
//     secondary. Two CTAs total is the norm. No external links.
//
// Adding a new module: add an EmptyStateCatalog<Name>() function
// here, then call it from the matching templ page inside an
// `if len(items) == 0 { @components.EmptyStateCTAs(...) }` branch.
// Keep functions alphabetised by module noun.

// EmptyStateCatalogBackups returns the empty-state for /backups.
func EmptyStateCatalogBackups() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-archive",
		Title: "Backups",
		What:  "Compressed and verified snapshots of your volumes, configurations, and stacks.",
		Why:   "Set up a nightly schedule so a bad deploy or compromised image is one restore away from recovery.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New schedule", Href: "/backups", Icon: "fa-plus", Primary: true},
			{Label: "Read the docs", Href: "/docs/installation.md"},
		},
	}
}

// EmptyStateCatalogBackupVerify returns the empty-state for /backup-verify.
func EmptyStateCatalogBackupVerify() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-clipboard-check",
		Title: "Backup verification",
		What:  "Sandboxed restore tests that confirm each backup is actually recoverable.",
		Why:   "A backup that never restored is a backup that won't restore. Schedule periodic verifies and learn before the incident, not during.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New verification", Href: "/backup-verify", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogCalendar returns the empty-state for /calendar.
func EmptyStateCatalogCalendar() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-calendar",
		Title: "Operations calendar",
		What:  "A unified view of manual events, scheduled jobs, and backup runs across every host.",
		Why:   "Stop reconciling cron, backup, and human maintenance windows in your head. See conflicts before they bite.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New event", Href: "/calendar/new", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogCrontab returns the empty-state for /crontab.
func EmptyStateCatalogCrontab() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-clock",
		Title: "Cron jobs",
		What:  "Schedule shell commands, docker exec calls, and HTTP webhooks across your hosts.",
		Why:   "Centralise nightly cleanup, healthcheck polls, and ad-hoc maintenance instead of editing crontabs by SSH.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New cron job", Href: "/crontab", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogDNS returns the empty-state for /dns.
func EmptyStateCatalogDNS() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-cloud",
		Title: "DNS providers",
		What:  "Plug Cloudflare, Route 53, DigitalOcean, or RFC 2136 into the proxy for ACME DNS-01 challenges.",
		Why:   "Lets Encrypt certificates for wildcards and internal services that can't expose port 80 to the public internet.",
		CTAs: []components.EmptyStateCTA{
			{Label: "Add provider", Href: "/dns/new", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogFirewall returns the empty-state for /firewall.
func EmptyStateCatalogFirewall() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-fire",
		Title: "Firewall rules",
		What:  "Manage UFW / iptables / nftables rules per host without SSH.",
		Why:   "Block public access to admin ports, rate-limit APIs, and stage rule changes before applying them.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New rule", Href: "/firewall", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogImageBuilder returns the empty-state for /image-builder.
func EmptyStateCatalogImageBuilder() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-hammer",
		Title: "Image builder",
		What:  "Build, tag, and (optionally) sign Docker images from the UI with live log streaming.",
		Why:   "Skip the local Dockerfile dance for one-off builds. Useful for patching base images or rebuilding from a Git tag.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New build", Href: "/image-builder", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogMarketplace returns the empty-state for /marketplace
// (shown when the catalogue exists but is filtered to zero results).
func EmptyStateCatalogMarketplace() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-store",
		Title: "Marketplace",
		What:  "Curated catalogue of self-host apps deployable in one click. Offline-first, baked into the binary.",
		Why:   "No outbound HTTP to install. Reviews and templates are local to this instance.",
		CTAs: []components.EmptyStateCTA{
			{Label: "Browse all apps", Href: "/marketplace", Icon: "fa-search", Primary: true},
		},
	}
}

// EmptyStateCatalogProxy returns the empty-state for /proxy (shown
// when no NPM connection is configured; replaces the bare "NPM Not
// Connected" message from v26.5.1).
func EmptyStateCatalogProxy() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-random",
		Title: "Reverse proxy",
		What:  "Manage Nginx Proxy Manager or Caddy upstream routes, ACME certificates, and access lists.",
		Why:   "Expose stacks to the public internet without hand-editing nginx.conf or wrestling with Let's Encrypt rate limits.",
		CTAs: []components.EmptyStateCTA{
			{Label: "Setup connection", Href: "/proxy", Icon: "fa-plug", Primary: true},
		},
	}
}

// EmptyStateCatalogRollback returns the empty-state for /rollback.
func EmptyStateCatalogRollback() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-undo-alt",
		Title: "Automated rollback",
		What:  "Policies that watch healthchecks and container crashes, and roll back to the last good version on failure.",
		Why:   "Make production safer by undoing a bad deploy in seconds instead of waking up on-call.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New policy", Href: "/rollback", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogSSLObservatory returns the empty-state for /ssl.
func EmptyStateCatalogSSLObservatory() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-lock",
		Title: "SSL Observatory",
		What:  "Continuous TLS certificate scanning with grades, expiry alerts, and protocol / cipher inventory.",
		Why:   "Catch certificates about to expire and weak ciphers before your users (or a security audit) do.",
		CTAs: []components.EmptyStateCTA{
			{Label: "Add target", Href: "/ssl", Icon: "fa-plus", Primary: true},
		},
	}
}

// EmptyStateCatalogWireGuard returns the empty-state for /wireguard.
func EmptyStateCatalogWireGuard() components.EmptyStateData {
	return components.EmptyStateData{
		Icon:  "fa-shield-halved",
		Title: "WireGuard VPN",
		What:  "Manage peers, interfaces, and a master-to-agent mesh over WireGuard with one-time QR config delivery.",
		Why:   "Connect your laptop, edge nodes, and branch offices without exposing admin ports to the public internet.",
		CTAs: []components.EmptyStateCTA{
			{Label: "New interface", Href: "/wireguard", Icon: "fa-plus", Primary: true},
		},
	}
}
