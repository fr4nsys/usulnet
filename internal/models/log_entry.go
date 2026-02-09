// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// LogSeverity represents log severity levels
type LogSeverity string

const (
	LogSeverityDebug    LogSeverity = "debug"
	LogSeverityInfo     LogSeverity = "info"
	LogSeverityWarning  LogSeverity = "warning"
	LogSeverityError    LogSeverity = "error"
	LogSeverityCritical LogSeverity = "critical"
	LogSeverityUnknown  LogSeverity = "unknown"
)

// LogSource represents the source type of a log
type LogSource string

const (
	LogSourceContainer  LogSource = "container"
	LogSourceHost       LogSource = "host"
	LogSourceApplication LogSource = "application"
	LogSourceCustom     LogSource = "custom"
)

// LogFormat represents detected log format
type LogFormat string

const (
	LogFormatJSON     LogFormat = "json"
	LogFormatSyslog   LogFormat = "syslog"
	LogFormatApache   LogFormat = "apache"
	LogFormatNginx    LogFormat = "nginx"
	LogFormatDocker   LogFormat = "docker"
	LogFormatPlain    LogFormat = "plain"
)

// LogEntry represents a parsed log entry
type LogEntry struct {
	ID           uuid.UUID         `json:"id"`
	Timestamp    time.Time         `json:"timestamp"`
	Source       LogSource         `json:"source"`
	SourceID     string            `json:"source_id"`     // container ID, host ID, etc.
	SourceName   string            `json:"source_name"`   // container name, hostname, etc.
	Severity     LogSeverity       `json:"severity"`
	Message      string            `json:"message"`
	RawLine      string            `json:"raw_line"`
	Format       LogFormat         `json:"format"`
	Fields       map[string]string `json:"fields,omitempty"` // Parsed structured fields
	Labels       map[string]string `json:"labels,omitempty"` // Additional metadata
	ErrorPattern *ErrorPattern     `json:"error_pattern,omitempty"`
}

// ErrorPattern represents a detected error pattern
type ErrorPattern struct {
	Type        string `json:"type"`        // "exception", "stack_trace", "timeout", etc.
	Name        string `json:"name"`        // Specific error name
	File        string `json:"file,omitempty"`
	Line        int    `json:"line,omitempty"`
	Stacktrace  string `json:"stacktrace,omitempty"`
}

// CustomLogUpload represents an uploaded log file
type CustomLogUpload struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	UserID      uuid.UUID   `json:"user_id" db:"user_id"`
	Filename    string      `json:"filename" db:"filename"`
	Size        int64       `json:"size" db:"size"`
	Format      LogFormat   `json:"format" db:"format"`
	LineCount   int         `json:"line_count" db:"line_count"`
	ErrorCount  int         `json:"error_count" db:"error_count"`
	UploadedAt  time.Time   `json:"uploaded_at" db:"uploaded_at"`
	Description string      `json:"description,omitempty" db:"description"`
	FilePath    string      `json:"file_path,omitempty" db:"file_path"`
}

// LogAggregation represents aggregated log statistics
type LogAggregation struct {
	Timeframe      string            `json:"timeframe"` // "1h", "24h", "7d"
	TotalCount     int64             `json:"total_count"`
	BySeverity     map[LogSeverity]int64 `json:"by_severity"`
	BySource       map[string]int64  `json:"by_source"`
	TopErrors      []ErrorSummary    `json:"top_errors"`
	ErrorRate      float64           `json:"error_rate"` // errors per minute
	PeakTime       *time.Time        `json:"peak_time,omitempty"`
}

// ErrorSummary represents aggregated error information
type ErrorSummary struct {
	Pattern    string    `json:"pattern"`
	Count      int64     `json:"count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Sources    []string  `json:"sources"`
	Severity   LogSeverity `json:"severity"`
}

// LogSearchOptions represents search/filter options
type LogSearchOptions struct {
	Query       string        `json:"query,omitempty"`
	Sources     []string      `json:"sources,omitempty"`
	Severities  []LogSeverity `json:"severities,omitempty"`
	StartTime   *time.Time    `json:"start_time,omitempty"`
	EndTime     *time.Time    `json:"end_time,omitempty"`
	Limit       int           `json:"limit"`
	Offset      int           `json:"offset"`
	SortDesc    bool          `json:"sort_desc"`
}

// LogParseResult contains the result of parsing a log line
type LogParseResult struct {
	Entry        LogEntry
	ParsedFields int
	Confidence   float64 // 0-1 confidence in parse accuracy
}

// Common error patterns for detection
var errorPatterns = []struct {
	Pattern *regexp.Regexp
	Type    string
	Name    string
}{
	// Go errors
	{regexp.MustCompile(`panic:\s+(.+)`), "panic", "Go Panic"},
	{regexp.MustCompile(`fatal error:\s+(.+)`), "fatal", "Go Fatal"},
	{regexp.MustCompile(`runtime error:\s+(.+)`), "runtime", "Go Runtime Error"},

	// Python errors
	{regexp.MustCompile(`Traceback \(most recent call last\):`), "traceback", "Python Traceback"},
	{regexp.MustCompile(`(\w+Error):\s+(.+)`), "exception", "Python Exception"},

	// Java/JVM errors
	{regexp.MustCompile(`Exception in thread "([^"]+)"\s+(\S+)`), "exception", "Java Exception"},
	{regexp.MustCompile(`Caused by:\s+(\S+):\s+(.+)`), "caused_by", "Java Caused By"},
	{regexp.MustCompile(`at\s+(\S+)\(([^:]+):(\d+)\)`), "stack_frame", "Java Stack Frame"},

	// Node.js errors
	{regexp.MustCompile(`Error:\s+(.+)`), "error", "Node.js Error"},
	{regexp.MustCompile(`TypeError:\s+(.+)`), "type_error", "TypeError"},
	{regexp.MustCompile(`ReferenceError:\s+(.+)`), "reference_error", "ReferenceError"},

	// Database errors
	{regexp.MustCompile(`(?i)connection refused`), "connection", "Connection Refused"},
	{regexp.MustCompile(`(?i)deadlock`), "deadlock", "Database Deadlock"},
	{regexp.MustCompile(`(?i)timeout`), "timeout", "Timeout"},

	// Generic patterns
	{regexp.MustCompile(`(?i)out of memory`), "oom", "Out of Memory"},
	{regexp.MustCompile(`(?i)permission denied`), "permission", "Permission Denied"},
	{regexp.MustCompile(`(?i)file not found`), "not_found", "File Not Found"},
	{regexp.MustCompile(`(?i)segmentation fault`), "segfault", "Segmentation Fault"},
}

// Severity detection patterns
var severityPatterns = []struct {
	Pattern  *regexp.Regexp
	Severity LogSeverity
}{
	{regexp.MustCompile(`(?i)\b(FATAL|CRITICAL|CRIT)\b`), LogSeverityCritical},
	{regexp.MustCompile(`(?i)\b(ERROR|ERR|FAIL|FAILED)\b`), LogSeverityError},
	{regexp.MustCompile(`(?i)\b(WARN|WARNING|WRN)\b`), LogSeverityWarning},
	{regexp.MustCompile(`(?i)\b(INFO|INF)\b`), LogSeverityInfo},
	{regexp.MustCompile(`(?i)\b(DEBUG|DBG|TRACE|TRC)\b`), LogSeverityDebug},
}

// ParseLogLine parses a raw log line and extracts structured information
func ParseLogLine(line string, source LogSource, sourceID, sourceName string) LogParseResult {
	entry := LogEntry{
		ID:         uuid.New(),
		Timestamp:  time.Now(),
		Source:     source,
		SourceID:   sourceID,
		SourceName: sourceName,
		RawLine:    line,
		Fields:     make(map[string]string),
		Labels:     make(map[string]string),
	}

	result := LogParseResult{
		Entry:      entry,
		Confidence: 0.5,
	}

	// Try JSON parsing first
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		var jsonData map[string]interface{}
		if err := json.Unmarshal([]byte(line), &jsonData); err == nil {
			result.Entry.Format = LogFormatJSON
			result.Confidence = 0.95
			parseJSONLog(&result.Entry, jsonData)
			result.ParsedFields = len(result.Entry.Fields)
			detectErrorPattern(&result.Entry)
			return result
		}
	}

	// Try syslog format
	if parsed, ok := parseSyslog(line); ok {
		result.Entry = parsed
		result.Entry.ID = uuid.New()
		result.Entry.Source = source
		result.Entry.SourceID = sourceID
		result.Entry.SourceName = sourceName
		result.Entry.Format = LogFormatSyslog
		result.Confidence = 0.85
		detectErrorPattern(&result.Entry)
		return result
	}

	// Try common log format (Apache/Nginx)
	if parsed, ok := parseCommonLogFormat(line); ok {
		result.Entry = parsed
		result.Entry.ID = uuid.New()
		result.Entry.Source = source
		result.Entry.SourceID = sourceID
		result.Entry.SourceName = sourceName
		result.Confidence = 0.8
		return result
	}

	// Fall back to plain text with severity detection
	result.Entry.Format = LogFormatPlain
	result.Entry.Message = line
	result.Entry.Severity = detectSeverity(line)
	detectErrorPattern(&result.Entry)

	return result
}

// parseJSONLog extracts fields from JSON log data
func parseJSONLog(entry *LogEntry, data map[string]interface{}) {
	// Common timestamp fields
	timestampFields := []string{"timestamp", "time", "@timestamp", "ts", "datetime", "date"}
	for _, field := range timestampFields {
		if v, ok := data[field]; ok {
			if t, err := parseTimestamp(v); err == nil {
				entry.Timestamp = t
				break
			}
		}
	}

	// Common message fields
	messageFields := []string{"message", "msg", "log", "text", "body"}
	for _, field := range messageFields {
		if v, ok := data[field].(string); ok {
			entry.Message = v
			break
		}
	}

	// Common level/severity fields
	levelFields := []string{"level", "severity", "lvl", "log.level", "loglevel"}
	for _, field := range levelFields {
		if v, ok := data[field].(string); ok {
			entry.Severity = normalizeSeverity(v)
			break
		}
	}

	// Store all fields
	for k, v := range data {
		switch val := v.(type) {
		case string:
			entry.Fields[k] = val
		case float64:
			entry.Fields[k] = strings.TrimRight(strings.TrimRight(
				strings.Replace(string(rune(int(val))), ",", "", -1), "0"), ".")
		case bool:
			if val {
				entry.Fields[k] = "true"
			} else {
				entry.Fields[k] = "false"
			}
		default:
			if b, err := json.Marshal(val); err == nil {
				entry.Fields[k] = string(b)
			}
		}
	}

	if entry.Severity == "" {
		entry.Severity = detectSeverity(entry.Message)
	}
}

// parseSyslog attempts to parse syslog format
func parseSyslog(line string) (LogEntry, bool) {
	// RFC 3164 format: <PRI>TIMESTAMP HOSTNAME TAG: MESSAGE
	// Example: <134>Feb 25 14:09:07 myhost myapp[1234]: Something happened

	syslogRegex := regexp.MustCompile(`^<(\d+)>(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)$`)
	matches := syslogRegex.FindStringSubmatch(line)

	if len(matches) < 7 {
		return LogEntry{}, false
	}

	entry := LogEntry{
		RawLine: line,
		Fields:  make(map[string]string),
		Labels:  make(map[string]string),
	}

	// Parse priority
	// priority := matches[1]
	entry.Fields["hostname"] = matches[3]
	entry.Fields["program"] = matches[4]
	if matches[5] != "" {
		entry.Fields["pid"] = matches[5]
	}
	entry.Message = matches[6]

	// Parse timestamp (assuming current year)
	if t, err := time.Parse("Jan 2 15:04:05", matches[2]); err == nil {
		entry.Timestamp = t.AddDate(time.Now().Year(), 0, 0)
	}

	entry.Severity = detectSeverity(entry.Message)
	return entry, true
}

// parseCommonLogFormat parses Apache/Nginx combined log format
func parseCommonLogFormat(line string) (LogEntry, bool) {
	// Combined Log Format: IP - - [TIMESTAMP] "METHOD PATH PROTOCOL" STATUS SIZE "REFERER" "USER-AGENT"
	clfRegex := regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"`)
	matches := clfRegex.FindStringSubmatch(line)

	if len(matches) < 10 {
		return LogEntry{}, false
	}

	entry := LogEntry{
		RawLine: line,
		Fields:  make(map[string]string),
		Labels:  make(map[string]string),
	}

	entry.Fields["client_ip"] = matches[1]
	entry.Fields["method"] = matches[3]
	entry.Fields["path"] = matches[4]
	entry.Fields["protocol"] = matches[5]
	entry.Fields["status"] = matches[6]
	entry.Fields["size"] = matches[7]
	entry.Fields["referer"] = matches[8]
	entry.Fields["user_agent"] = matches[9]

	// Parse timestamp
	if t, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2]); err == nil {
		entry.Timestamp = t
	}

	// Determine severity based on status code
	status := matches[6]
	switch {
	case strings.HasPrefix(status, "5"):
		entry.Severity = LogSeverityError
		entry.Format = LogFormatApache
	case strings.HasPrefix(status, "4"):
		entry.Severity = LogSeverityWarning
		entry.Format = LogFormatApache
	default:
		entry.Severity = LogSeverityInfo
		entry.Format = LogFormatApache
	}

	entry.Message = line

	return entry, true
}

// detectSeverity detects log severity from text
func detectSeverity(text string) LogSeverity {
	for _, sp := range severityPatterns {
		if sp.Pattern.MatchString(text) {
			return sp.Severity
		}
	}
	return LogSeverityUnknown
}

// detectErrorPattern detects error patterns in the log entry
func detectErrorPattern(entry *LogEntry) {
	for _, ep := range errorPatterns {
		if matches := ep.Pattern.FindStringSubmatch(entry.RawLine); matches != nil {
			entry.ErrorPattern = &ErrorPattern{
				Type: ep.Type,
				Name: ep.Name,
			}

			// Try to extract file and line info
			fileLineRegex := regexp.MustCompile(`(?:at\s+)?(\S+\.(?:go|py|js|java|rb|php|rs)):(\d+)`)
			if flMatches := fileLineRegex.FindStringSubmatch(entry.RawLine); len(flMatches) > 2 {
				entry.ErrorPattern.File = flMatches[1]
				// line number parsing would go here
			}

			if entry.Severity == LogSeverityUnknown {
				entry.Severity = LogSeverityError
			}
			return
		}
	}
}

// normalizeSeverity normalizes various severity strings to LogSeverity
func normalizeSeverity(s string) LogSeverity {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "debug", "dbg", "trace", "trc":
		return LogSeverityDebug
	case "info", "inf", "information":
		return LogSeverityInfo
	case "warn", "warning", "wrn":
		return LogSeverityWarning
	case "error", "err", "fail", "failed":
		return LogSeverityError
	case "fatal", "critical", "crit", "emergency", "alert":
		return LogSeverityCritical
	default:
		return LogSeverityUnknown
	}
}

// parseTimestamp attempts to parse various timestamp formats
func parseTimestamp(v interface{}) (time.Time, error) {
	switch val := v.(type) {
	case string:
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05Z",
			"2006-01-02T15:04:05.000Z",
			"2006-01-02 15:04:05",
			"2006/01/02 15:04:05",
			"Jan 2 15:04:05",
			"02/Jan/2006:15:04:05 -0700",
		}
		for _, format := range formats {
			if t, err := time.Parse(format, val); err == nil {
				return t, nil
			}
		}
	case float64:
		// Unix timestamp (seconds or milliseconds)
		if val > 1e12 {
			return time.UnixMilli(int64(val)), nil
		}
		return time.Unix(int64(val), 0), nil
	}
	return time.Time{}, nil
}
