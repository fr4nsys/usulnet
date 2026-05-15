// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	calendarsvc "github.com/fr4nsys/usulnet/internal/services/calendar"
	calendartpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/calendar"
)

// requireCalendarSvc returns the calendar service or renders a
// "not configured" error.
func (h *Handler) requireCalendarSvc(w http.ResponseWriter, r *http.Request) *calendarsvc.Service {
	if reg, ok := h.services.(*ServiceRegistry); ok && reg.calendarSvc != nil {
		return reg.calendarSvc
	}
	h.RenderErrorTempl(w, r, http.StatusServiceUnavailable,
		"Calendar Not Configured",
		"The operations calendar is not enabled in this build.")
	return nil
}

func (h *Handler) getCalendarHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

func (h *Handler) calendarUserUUID(r *http.Request) *uuid.UUID {
	user := h.getUserData(r)
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// ============================================================================
// List (month grid + event table)
// ============================================================================

// CalendarListTempl renders the operations calendar.
func (h *Handler) CalendarListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCalendarSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getCalendarHostID(r)
	pageData := h.prepareTemplPageData(r, "Calendar", "calendar")

	now := time.Now().UTC()
	month := r.URL.Query().Get("month")
	monthStart := firstDayOfMonth(now)
	if month != "" {
		if t, err := time.Parse("2006-01", month); err == nil {
			monthStart = firstDayOfMonth(t)
		}
	}
	rangeFrom := monthStart.AddDate(0, 0, -7)
	rangeTo := monthStart.AddDate(0, 1, 7)

	events, err := svc.ListEvents(ctx, hostID, rangeFrom, rangeTo)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError,
			"Error", "Failed to load calendar events: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	eventViews := make([]calendartpl.EventView, 0, len(events))
	for _, e := range events {
		eventViews = append(eventViews, eventToView(e))
	}

	weeks := buildMonthGrid(monthStart, events, now)

	statsView := calendartpl.StatsView{}
	if stats != nil {
		statsView = calendartpl.StatsView{
			Total:       stats.Total,
			Maintenance: stats.Maintenance,
			Backup:      stats.Backup,
			Deploy:      stats.Deploy,
			Job:         stats.Job,
			Alert:       stats.Alert,
			Note:        stats.Note,
		}
	}

	h.renderTempl(w, r, calendartpl.List(calendartpl.ListData{
		PageData:   pageData,
		Events:     eventViews,
		Stats:      statsView,
		MonthLabel: monthStart.Format("January 2006"),
		PrevMonth:  monthStart.AddDate(0, -1, 0).Format("2006-01"),
		NextMonth:  monthStart.AddDate(0, 1, 0).Format("2006-01"),
		Today:      now.Format("2006-01-02"),
		Weeks:      weeks,
		RangeFrom:  rangeFrom.Format("2006-01-02"),
		RangeTo:    rangeTo.Format("2006-01-02"),
		Sources:    svc.Sources(),
	}))
}

// ============================================================================
// Create
// ============================================================================

// CalendarNewTempl renders the create-event form.
func (h *Handler) CalendarNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCalendarSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Event", "calendar")
	now := time.Now().UTC()
	h.renderTempl(w, r, calendartpl.Form(calendartpl.FormData{
		PageData: pageData,
		Mode:     "new",
		Kind:     string(models.CalendarKindMaintenance),
		StartsAt: now.Format("2006-01-02T15:04"),
		EndsAt:   now.Add(time.Hour).Format("2006-01-02T15:04"),
	}))
}

// CalendarCreateTempl handles POST /calendar.
func (h *Handler) CalendarCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCalendarSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getCalendarHostID(r)
	userID := h.calendarUserUUID(r)

	form, err := parseEventForm(r)
	if err != nil {
		pageData := h.prepareTemplPageData(r, "New Event", "calendar")
		form.PageData = pageData
		form.Mode = "new"
		form.Error = err.Error()
		h.renderTempl(w, r, calendartpl.Form(form))
		return
	}

	input := models.CreateCalendarEventInput{
		Kind:        models.CalendarEventKind(form.Kind),
		Title:       form.Title,
		Description: form.Description,
		Location:    form.Location,
		URL:         form.URL,
		StartsAt:    mustParseDatetimeLocal(form.StartsAt),
		EndsAt:      mustParseDatetimeLocal(form.EndsAt),
		AllDay:      form.AllDay,
	}

	if _, err := svc.Create(r.Context(), hostID, input, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New Event", "calendar")
		form.PageData = pageData
		form.Mode = "new"
		form.Error = "Failed to create event: " + err.Error()
		h.renderTempl(w, r, calendartpl.Form(form))
		return
	}

	http.Redirect(w, r, "/calendar", http.StatusSeeOther)
}

// ============================================================================
// Edit / Update
// ============================================================================

// CalendarEditTempl renders the edit-event form.
func (h *Handler) CalendarEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCalendarSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The event ID is not valid.")
		return
	}
	event, err := svc.Get(r.Context(), id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested event was not found.")
		return
	}
	pageData := h.prepareTemplPageData(r, "Edit Event", "calendar")
	h.renderTempl(w, r, calendartpl.Form(calendartpl.FormData{
		PageData:    pageData,
		Mode:        "edit",
		ID:          event.ID.String(),
		Kind:        string(event.Kind),
		Title:       event.Title,
		Description: event.Description,
		Location:    event.Location,
		URL:         event.URL,
		StartsAt:    event.StartsAt.Format("2006-01-02T15:04"),
		EndsAt:      event.EndsAt.Format("2006-01-02T15:04"),
		AllDay:      event.AllDay,
	}))
}

// CalendarUpdateTempl handles POST /calendar/{id}.
func (h *Handler) CalendarUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCalendarSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The event ID is not valid.")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}
	form, err := parseEventForm(r)
	if err != nil {
		pageData := h.prepareTemplPageData(r, "Edit Event", "calendar")
		form.PageData = pageData
		form.Mode = "edit"
		form.ID = id.String()
		form.Error = err.Error()
		h.renderTempl(w, r, calendartpl.Form(form))
		return
	}
	kind := models.CalendarEventKind(form.Kind)
	starts := mustParseDatetimeLocal(form.StartsAt)
	ends := mustParseDatetimeLocal(form.EndsAt)

	in := models.UpdateCalendarEventInput{
		Kind:        &kind,
		Title:       &form.Title,
		Description: &form.Description,
		Location:    &form.Location,
		URL:         &form.URL,
		StartsAt:    &starts,
		EndsAt:      &ends,
		AllDay:      &form.AllDay,
	}

	if _, err := svc.Update(r.Context(), id, in); err != nil {
		pageData := h.prepareTemplPageData(r, "Edit Event", "calendar")
		form.PageData = pageData
		form.Mode = "edit"
		form.ID = id.String()
		form.Error = "Failed to update event: " + err.Error()
		h.renderTempl(w, r, calendartpl.Form(form))
		return
	}

	http.Redirect(w, r, "/calendar", http.StatusSeeOther)
}

// ============================================================================
// Delete
// ============================================================================

// CalendarDeleteTempl handles DELETE /calendar/{id}.
func (h *Handler) CalendarDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCalendarSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}
	if err := svc.Delete(r.Context(), id); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete event: "+err.Error())
		return
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/calendar")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/calendar", http.StatusSeeOther)
}

// ============================================================================
// Helpers
// ============================================================================

func eventToView(e *models.CalendarEvent) calendartpl.EventView {
	return calendartpl.EventView{
		ID:          e.ID.String(),
		Source:      string(e.Source),
		Kind:        string(e.Kind),
		Title:       e.Title,
		Description: e.Description,
		Location:    e.Location,
		URL:         e.URL,
		StartsAt:    e.StartsAt.Format("2006-01-02 15:04"),
		EndsAt:      e.EndsAt.Format("2006-01-02 15:04"),
		StartsLabel: e.StartsAt.Format("15:04"),
		EndsLabel:   e.EndsAt.Format("15:04"),
		AllDay:      e.AllDay,
		ExternalID:  e.ExternalID,
	}
}

func parseEventForm(r *http.Request) (calendartpl.FormData, error) {
	form := calendartpl.FormData{
		Kind:        r.FormValue("kind"),
		Title:       strings.TrimSpace(r.FormValue("title")),
		Description: r.FormValue("description"),
		Location:    r.FormValue("location"),
		URL:         r.FormValue("url"),
		StartsAt:    r.FormValue("starts_at"),
		EndsAt:      r.FormValue("ends_at"),
		AllDay:      r.FormValue("all_day") == "on" || r.FormValue("all_day") == "true",
	}
	if form.Title == "" {
		return form, errFormTitleRequired
	}
	if form.Kind == "" {
		return form, errFormKindRequired
	}
	if _, err := time.Parse("2006-01-02T15:04", form.StartsAt); err != nil {
		return form, errFormStartsInvalid
	}
	if _, err := time.Parse("2006-01-02T15:04", form.EndsAt); err != nil {
		return form, errFormEndsInvalid
	}
	return form, nil
}

// formErr satisfies error with a stable string value so the web layer can
// surface form errors via Error fields without introducing a typed error
// hierarchy specific to calendar.
type formErr string

func (e formErr) Error() string { return string(e) }

var (
	errFormTitleRequired = formErr("Title is required.")
	errFormKindRequired  = formErr("Kind is required.")
	errFormStartsInvalid = formErr("Starts at must be a valid date/time.")
	errFormEndsInvalid   = formErr("Ends at must be a valid date/time.")
)

func mustParseDatetimeLocal(s string) time.Time {
	t, err := time.Parse("2006-01-02T15:04", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func firstDayOfMonth(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// buildMonthGrid lays out a 6x7 grid covering the displayed month and a
// little before/after so each row is exactly 7 days. Events are bucketed
// into the day cell their StartsAt falls on (UTC).
func buildMonthGrid(monthStart time.Time, events []*models.CalendarEvent, now time.Time) [][]calendartpl.DayCell {
	// Start grid on Monday containing the 1st of the month.
	first := monthStart
	weekday := int(first.Weekday())
	if weekday == 0 {
		weekday = 7 // Sunday
	}
	gridStart := first.AddDate(0, 0, -(weekday - 1))

	byDay := make(map[string][]calendartpl.EventView, len(events))
	for _, e := range events {
		key := e.StartsAt.UTC().Format("2006-01-02")
		byDay[key] = append(byDay[key], eventToView(e))
	}

	todayKey := now.UTC().Format("2006-01-02")

	grid := make([][]calendartpl.DayCell, 0, 6)
	for w := 0; w < 6; w++ {
		row := make([]calendartpl.DayCell, 0, 7)
		for d := 0; d < 7; d++ {
			day := gridStart.AddDate(0, 0, w*7+d)
			key := day.Format("2006-01-02")
			row = append(row, calendartpl.DayCell{
				DateLabel: day.Format("Jan 2"),
				DateISO:   key,
				InMonth:   day.Month() == monthStart.Month(),
				IsToday:   key == todayKey,
				Events:    byDay[key],
			})
		}
		grid = append(grid, row)
	}
	return grid
}
