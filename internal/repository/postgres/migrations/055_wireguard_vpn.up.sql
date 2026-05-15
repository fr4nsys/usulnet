-- WireGuard VPN module (v26.5.1 — ported from v26.2.7 migration 053).
-- Renumbered to 055 to fit after the recon module (044-045) and the
-- other ported v26.2.7 modules (049-052, 054).
--
-- Private keys and preshared keys are stored AES-256-GCM-encrypted by
-- the application using the installation data encryption key
-- (USULNET_ENCRYPTION_KEY). Schema-level storage is opaque ciphertext.

CREATE TABLE wireguard_interfaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(50) NOT NULL DEFAULT 'wg0',
    display_name    VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    listen_port     INTEGER NOT NULL DEFAULT 51820,
    address         VARCHAR(50) NOT NULL,                  -- e.g. 10.0.0.1/24
    private_key     TEXT NOT NULL DEFAULT '',              -- AES-256-GCM ciphertext (base64)
    public_key      TEXT NOT NULL DEFAULT '',
    dns             VARCHAR(255) NOT NULL DEFAULT '1.1.1.1',
    mtu             INTEGER NOT NULL DEFAULT 1420,
    post_up         TEXT NOT NULL DEFAULT '',
    post_down       TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    status          VARCHAR(20) NOT NULL DEFAULT 'inactive', -- inactive, active, error
    peer_count      INTEGER NOT NULL DEFAULT 0,
    last_handshake  TIMESTAMPTZ,
    transfer_rx     BIGINT NOT NULL DEFAULT 0,
    transfer_tx     BIGINT NOT NULL DEFAULT 0,
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wireguard_interfaces_host ON wireguard_interfaces(host_id);
CREATE INDEX idx_wireguard_interfaces_status ON wireguard_interfaces(status);
CREATE UNIQUE INDEX idx_wireguard_interfaces_host_name
    ON wireguard_interfaces(host_id, name);

CREATE TABLE wireguard_peers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    interface_id    UUID NOT NULL REFERENCES wireguard_interfaces(id) ON DELETE CASCADE,
    host_id         UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    name            VARCHAR(255) NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    public_key      TEXT NOT NULL,
    preshared_key   TEXT NOT NULL DEFAULT '',              -- AES-256-GCM ciphertext (base64)
    allowed_ips     TEXT NOT NULL DEFAULT '10.0.0.0/24',   -- comma-separated CIDRs
    endpoint        VARCHAR(255) NOT NULL DEFAULT '',      -- client endpoint if known
    persistent_keepalive INTEGER NOT NULL DEFAULT 25,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    last_handshake  TIMESTAMPTZ,
    transfer_rx     BIGINT NOT NULL DEFAULT 0,
    transfer_tx     BIGINT NOT NULL DEFAULT 0,
    config_client   TEXT NOT NULL DEFAULT '',              -- rendered [Interface]/[Peer] config (encrypted)
    created_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_wireguard_peers_interface ON wireguard_peers(interface_id);
CREATE INDEX idx_wireguard_peers_host ON wireguard_peers(host_id);
CREATE INDEX idx_wireguard_peers_enabled ON wireguard_peers(enabled);

-- Mesh propagation table — one row per (agent_host, peer) pair that has
-- been (or is being) applied on a remote agent. Used by the mesh-status
-- UI page and by retry workers. Agent host id and peer id form a unique
-- pair; the row is upserted on every push attempt.
CREATE TABLE wireguard_mesh_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    peer_id         UUID NOT NULL REFERENCES wireguard_peers(id) ON DELETE CASCADE,
    agent_host_id   UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    status          VARCHAR(20) NOT NULL DEFAULT 'pending', -- pending, applied, failed
    last_error      TEXT NOT NULL DEFAULT '',
    last_handshake  TIMESTAMPTZ,
    applied_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_wireguard_mesh_links_peer_agent
    ON wireguard_mesh_links(peer_id, agent_host_id);
CREATE INDEX idx_wireguard_mesh_links_status
    ON wireguard_mesh_links(status);
CREATE INDEX idx_wireguard_mesh_links_agent
    ON wireguard_mesh_links(agent_host_id);
