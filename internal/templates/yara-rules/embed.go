// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package yararules exposes the embedded YARA ruleset library used by
// the v26.5.2 yara scanner. New rulesets land as additional .yar files
// in this directory and become available to operators on the next
// build — there is no runtime upload path.
package yararules

import "embed"

// FS is the embed.FS containing every shipped .yar file.
//
//go:embed *.yar
var FS embed.FS
