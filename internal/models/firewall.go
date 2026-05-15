// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// FirewallChain represents an iptables chain.
type FirewallChain string

const (
	FirewallChainInput      FirewallChain = "INPUT"
	FirewallChainOutput     FirewallChain = "OUTPUT"
	FirewallChainForward    FirewallChain = "FORWARD"
	FirewallChainDockerUser FirewallChain = "DOCKER-USER"
)

// FirewallAction represents a rule action.
type FirewallAction string

const (
	FirewallActionAccept FirewallAction = "ACCEPT"
	FirewallActionDrop   FirewallAction = "DROP"
	FirewallActionReject FirewallAction = "REJECT"
	FirewallActionLog    FirewallAction = "LOG"
)

// FirewallProtocol represents a network protocol.
type FirewallProtocol string

const (
	FirewallProtocolTCP  FirewallProtocol = "tcp"
	FirewallProtocolUDP  FirewallProtocol = "udp"
	FirewallProtocolICMP FirewallProtocol = "icmp"
	FirewallProtocolAll  FirewallProtocol = "all"
)

// FirewallBackend represents the detected firewall backend on a host.
type FirewallBackend string

const (
	FirewallBackendIptables FirewallBackend = "iptables"
	FirewallBackendNftables FirewallBackend = "nftables"
	FirewallBackendUFW      FirewallBackend = "ufw"
	FirewallBackendUnknown  FirewallBackend = "unknown"
)

// FirewallRule represents a single firewall rule.
type FirewallRule struct {
	ID            uuid.UUID      `json:"id" db:"id"`
	HostID        uuid.UUID      `json:"host_id" db:"host_id"`
	Name          string         `json:"name" db:"name"`
	Description   string         `json:"description,omitempty" db:"description"`
	Chain         FirewallChain  `json:"chain" db:"chain"`
	Protocol      string         `json:"protocol" db:"protocol"`
	Source        string         `json:"source,omitempty" db:"source"`
	Destination   string         `json:"destination,omitempty" db:"destination"`
	SrcPort       string         `json:"src_port,omitempty" db:"src_port"`
	DstPort       string         `json:"dst_port,omitempty" db:"dst_port"`
	Action        FirewallAction `json:"action" db:"action"`
	Direction     string         `json:"direction" db:"direction"`
	InterfaceName string         `json:"interface_name,omitempty" db:"interface_name"`
	Position      int            `json:"position" db:"position"`
	Enabled       bool           `json:"enabled" db:"enabled"`
	Applied       bool           `json:"applied" db:"applied"`
	ContainerID   string         `json:"container_id,omitempty" db:"container_id"`
	NetworkName   string         `json:"network_name,omitempty" db:"network_name"`
	Comment       string         `json:"comment,omitempty" db:"comment"`
	CreatedBy     *uuid.UUID     `json:"created_by,omitempty" db:"created_by"`
	CreatedAt     time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at" db:"updated_at"`
}

// CreateFirewallRuleInput is the input for creating a firewall rule.
type CreateFirewallRuleInput struct {
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Chain         FirewallChain  `json:"chain"`
	Protocol      string         `json:"protocol"`
	Source        string         `json:"source,omitempty"`
	Destination   string         `json:"destination,omitempty"`
	SrcPort       string         `json:"src_port,omitempty"`
	DstPort       string         `json:"dst_port,omitempty"`
	Action        FirewallAction `json:"action"`
	Direction     string         `json:"direction"`
	InterfaceName string         `json:"interface_name,omitempty"`
	ContainerID   string         `json:"container_id,omitempty"`
	NetworkName   string         `json:"network_name,omitempty"`
	Comment       string         `json:"comment,omitempty"`
	Enabled       bool           `json:"enabled"`
}

// UpdateFirewallRuleInput is the input for updating a firewall rule.
// Any field left nil is preserved untouched.
type UpdateFirewallRuleInput struct {
	Name          *string         `json:"name,omitempty"`
	Description   *string         `json:"description,omitempty"`
	Chain         *FirewallChain  `json:"chain,omitempty"`
	Protocol      *string         `json:"protocol,omitempty"`
	Source        *string         `json:"source,omitempty"`
	Destination   *string         `json:"destination,omitempty"`
	SrcPort       *string         `json:"src_port,omitempty"`
	DstPort       *string         `json:"dst_port,omitempty"`
	Action        *FirewallAction `json:"action,omitempty"`
	Direction     *string         `json:"direction,omitempty"`
	InterfaceName *string         `json:"interface_name,omitempty"`
	ContainerID   *string         `json:"container_id,omitempty"`
	NetworkName   *string         `json:"network_name,omitempty"`
	Comment       *string         `json:"comment,omitempty"`
	Enabled       *bool           `json:"enabled,omitempty"`
}

// FirewallAuditLog records firewall changes.
type FirewallAuditLog struct {
	ID          uuid.UUID  `json:"id" db:"id"`
	HostID      uuid.UUID  `json:"host_id" db:"host_id"`
	UserID      *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Action      string     `json:"action" db:"action"`
	RuleID      *uuid.UUID `json:"rule_id,omitempty" db:"rule_id"`
	RuleSummary string     `json:"rule_summary" db:"rule_summary"`
	Details     string     `json:"details,omitempty" db:"details"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
}

// FirewallHostStatus represents the firewall status on a host.
type FirewallHostStatus struct {
	Backend      FirewallBackend `json:"backend"`
	Version      string          `json:"version"`
	ActiveRules  int             `json:"active_rules"`
	ManagedRules int             `json:"managed_rules"`
	LastApplied  *time.Time      `json:"last_applied,omitempty"`
	LastSynced   *time.Time      `json:"last_synced,omitempty"`
}
