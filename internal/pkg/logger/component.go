// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package logger

import (
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ============================================================================
// Per-Component Log Level Configuration
// ============================================================================

// ComponentLevels manages per-component log level overrides. Components
// that do not have an explicit override use the global logger level.
//
// Configuration example (config.yaml):
//
//	logging:
//	  level: info            # global default
//	  levels:
//	    api: debug           # verbose API logging
//	    docker: info
//	    nats: warn
//	    scheduler: info
//	    security: debug
//	    gateway: warn
type ComponentLevels struct {
	mu     sync.RWMutex
	levels map[string]zapcore.Level
	global zapcore.Level
}

// NewComponentLevels creates a new component level manager with the given
// global default level and per-component overrides.
func NewComponentLevels(global string, overrides map[string]string) *ComponentLevels {
	cl := &ComponentLevels{
		levels: make(map[string]zapcore.Level),
		global: parseLevel(global),
	}

	for component, level := range overrides {
		cl.levels[strings.ToLower(component)] = parseLevel(level)
	}

	return cl
}

// LevelFor returns the log level configured for the named component.
// If no override exists, the global level is returned.
func (cl *ComponentLevels) LevelFor(component string) zapcore.Level {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	if lvl, ok := cl.levels[strings.ToLower(component)]; ok {
		return lvl
	}
	return cl.global
}

// SetLevel sets the log level for a specific component at runtime.
func (cl *ComponentLevels) SetLevel(component string, level string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.levels[strings.ToLower(component)] = parseLevel(level)
}

// SetGlobal updates the global default log level at runtime.
func (cl *ComponentLevels) SetGlobal(level string) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.global = parseLevel(level)
}

// ForComponent creates a child Logger for the named component with the
// appropriate log level and a "component" field.
func (cl *ComponentLevels) ForComponent(parent *Logger, component string) *Logger {
	lvl := cl.LevelFor(component)

	child := parent.Named(component)
	child.SetLevel(lvl.String())

	return child
}

// ListOverrides returns a copy of all component-level overrides.
func (cl *ComponentLevels) ListOverrides() map[string]string {
	cl.mu.RLock()
	defer cl.mu.RUnlock()

	result := make(map[string]string, len(cl.levels))
	for k, v := range cl.levels {
		result[k] = v.String()
	}
	return result
}

// parseLevel converts a string to a zap level. Defaults to InfoLevel for
// unrecognized values.
func parseLevel(s string) zapcore.Level {
	var lvl zapcore.Level
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		lvl = zap.DebugLevel
	case "warn", "warning":
		lvl = zap.WarnLevel
	case "error":
		lvl = zap.ErrorLevel
	case "fatal":
		lvl = zap.FatalLevel
	default:
		lvl = zap.InfoLevel
	}
	return lvl
}
