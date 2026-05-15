// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package marketplace

import "strconv"

func ratingStr(i int) string { return strconv.Itoa(i) }

func reviewMatch(r *ReviewView, i int) bool {
	if r == nil {
		return false
	}
	return r.Rating == i
}

func reviewExistingTitle(r *ReviewView) string {
	if r == nil {
		return ""
	}
	return r.Title
}

func reviewExistingComment(r *ReviewView) string {
	if r == nil {
		return ""
	}
	return r.Comment
}
