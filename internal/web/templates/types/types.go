// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package types contains shared types for templates
package types

// PageData contains common data for all pages
type PageData struct {
	Title              string
	Description        string
	Active             string
	User               *UserData
	Stats              *StatsData
	CSRFToken          string
	Theme              string
	Version            string
	NotificationsCount int
	Flash              *FlashData
	FullScreen         bool   // For editors - removes main padding wrapper
	Edition            string // "ce", "biz", "ee" — from license provider
	EditionName        string // "Community Edition", "Business", "Enterprise"
	Hosts              []HostSelectorItem
	ActiveHostID       string
	ActiveHostName     string
}

// HostSelectorItem represents a host in the header dropdown selector
type HostSelectorItem struct {
	ID           string
	Name         string
	Status       string // online, offline, error, connecting
	EndpointType string // local, tcp, agent
}

// UserData contains user information
type UserData struct {
	ID       string
	Username string
	Role     string // Display name of the role
	RoleID   string // UUID of the role for permission checking
	Email    string
}

// StatsData contains dashboard statistics
type StatsData struct {
	ContainersRunning int
	ContainersTotal   int
	ImagesCount       int
	VolumesCount      int
	NetworksCount     int
	SecurityIssues    int
	UpdatesAvailable  int
}

// FlashData contains flash message data
type FlashData struct {
	Type    string // success, error, warning, info
	Message string
}
