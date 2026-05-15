// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package rollback

import "strconv"

// itoaPad is the canonical int-to-string helper used inside the rollback
// templ files. Existing in a non-templ file means the generated
// rollback templ code stays free of strconv imports.
func itoaPad(n int) string {
	return strconv.Itoa(n)
}
