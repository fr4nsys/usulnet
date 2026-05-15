// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package logger

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// FileConfig configures file-based logging with rotation.
type FileConfig struct {
	Path       string // Log file path (e.g., /var/log/usulnet/usulnet.log)
	MaxSize    int64  // Max file size in bytes before rotation (default 100MB)
	MaxBackups int    // Max rotated files to keep (default 5)
	MaxAge     int    // Max age in days for rotated files (default 30)
	Compress   bool   // Compress rotated files with gzip (default true)
}

// OutputConfig configures the logger output destination.
type OutputConfig struct {
	// Output destination: "stdout", "stderr", or "file" (default "stdout")
	Output string
	// File config (only used when Output == "file")
	File FileConfig
}

// Logger wraps zap.SugaredLogger with additional functionality
type Logger struct {
	*zap.SugaredLogger
	base  *zap.Logger
	level zap.AtomicLevel
}

// New creates a new Logger instance writing to stdout.
func New(level, format string) (*Logger, error) {
	return NewWithOutput(level, format, os.Stdout)
}

// NewFromConfig creates a logger from the full output configuration.
// Supports "stdout" (default), "stderr", and "file" output modes.
// When output is "file", a RotatingFileWriter handles size-based rotation.
func NewFromConfig(level, format string, cfg OutputConfig) (*Logger, error) {
	switch strings.ToLower(cfg.Output) {
	case "file":
		if cfg.File.Path == "" {
			return nil, fmt.Errorf("logging.file.path is required when output is 'file'")
		}
		rfw, err := NewRotatingFileWriter(cfg.File)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		return NewWithOutput(level, format, rfw)
	case "stderr":
		return NewWithOutput(level, format, os.Stderr)
	default: // "stdout" or empty
		return NewWithOutput(level, format, os.Stdout)
	}
}

// NewWithOutput creates a new Logger instance with custom output
func NewWithOutput(level, format string, output io.Writer) (*Logger, error) {
	// Parse level
	atomicLevel := zap.NewAtomicLevel()
	if err := atomicLevel.UnmarshalText([]byte(level)); err != nil {
		atomicLevel.SetLevel(zapcore.InfoLevel)
	}

	// Encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create encoder based on format
	var encoder zapcore.Encoder
	switch format {
	case "json":
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	case "console", "text":
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		encoder = zapcore.NewConsoleEncoder(encoderConfig)
	default:
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	// Create core
	core := zapcore.NewCore(
		encoder,
		zapcore.AddSync(output),
		atomicLevel,
	)

	// Build logger with options
	base := zap.New(core,
		zap.AddCaller(),
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	return &Logger{
		SugaredLogger: base.Sugar(),
		base:          base,
		level:         atomicLevel,
	}, nil
}

// With returns a logger with additional fields
func (l *Logger) With(args ...interface{}) *Logger {
	return &Logger{
		SugaredLogger: l.SugaredLogger.With(args...),
		base:          l.base,
		level:         l.level,
	}
}

// Named returns a named logger
func (l *Logger) Named(name string) *Logger {
	named := l.base.Named(name)
	return &Logger{
		SugaredLogger: named.Sugar(),
		base:          named,
		level:         l.level,
	}
}

// WithFields returns a logger with structured fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	args := make([]interface{}, 0, len(fields)*2)
	for k, v := range fields {
		args = append(args, k, v)
	}
	return l.With(args...)
}

// SetLevel dynamically changes the log level
func (l *Logger) SetLevel(level string) error {
	return l.level.UnmarshalText([]byte(level))
}

// GetLevel returns the current log level
func (l *Logger) GetLevel() string {
	return l.level.Level().String()
}

// Sync flushes any buffered log entries
func (l *Logger) Sync() error {
	return l.base.Sync()
}

// Base returns the underlying zap.Logger
func (l *Logger) Base() *zap.Logger {
	return l.base
}

// Fatal logs a message at Fatal level and exits
func (l *Logger) Fatal(msg string, keysAndValues ...interface{}) {
	l.Fatalw(msg, keysAndValues...)
}

// Panic logs a message at Panic level and panics
func (l *Logger) Panic(msg string, keysAndValues ...interface{}) {
	l.Panicw(msg, keysAndValues...)
}

// Error logs a message at Error level
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.Errorw(msg, keysAndValues...)
}

// Warn logs a message at Warn level
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.Warnw(msg, keysAndValues...)
}

// Info logs a message at Info level
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.Infow(msg, keysAndValues...)
}

// Debug logs a message at Debug level
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.Debugw(msg, keysAndValues...)
}

// Nop returns a no-op logger that discards all output
func Nop() *Logger {
	return &Logger{
		SugaredLogger: zap.NewNop().Sugar(),
		base:          zap.NewNop(),
		level:         zap.NewAtomicLevel(),
	}
}

// =========================================================================
// RotatingFileWriter — size-based log file rotation with compression
// =========================================================================

// RotatingFileWriter implements io.Writer with automatic size-based rotation.
// When the current log file exceeds MaxSize, it is closed and renamed with a
// timestamp suffix. Old rotated files beyond MaxBackups or MaxAge are pruned.
// Optionally, rotated files are compressed with gzip.
type RotatingFileWriter struct {
	mu          sync.Mutex
	cfg         FileConfig
	file        *os.File
	currentSize int64
}

// NewRotatingFileWriter creates a rotating file writer from the given config.
func NewRotatingFileWriter(cfg FileConfig) (*RotatingFileWriter, error) {
	// Apply defaults
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 100 * 1024 * 1024 // 100 MB
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = 30
	}

	// Ensure directory exists
	dir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", dir, err)
	}

	rfw := &RotatingFileWriter{cfg: cfg}
	if err := rfw.openFile(); err != nil {
		return nil, err
	}
	return rfw, nil
}

// Write implements io.Writer. Thread-safe.
func (w *RotatingFileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Rotate if adding this write would exceed max size
	if w.currentSize+int64(len(p)) > w.cfg.MaxSize {
		if err := w.rotate(); err != nil {
			// If rotation fails, still try to write to current file
			_ = err
		}
	}

	n, err = w.file.Write(p)
	w.currentSize += int64(n)
	return n, err
}

// Sync flushes the file (satisfies zapcore.WriteSyncer).
func (w *RotatingFileWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Sync()
}

// Close closes the current file.
func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// openFile opens (or creates) the log file and records its current size.
func (w *RotatingFileWriter) openFile() error {
	f, err := os.OpenFile(w.cfg.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", w.cfg.Path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat log file %s: %w", w.cfg.Path, err)
	}
	w.file = f
	w.currentSize = info.Size()
	return nil
}

// rotate closes the current file, renames it with a timestamp, opens a new
// file, and prunes old rotated files.
func (w *RotatingFileWriter) rotate() error {
	// Close current file
	if err := w.file.Close(); err != nil {
		return fmt.Errorf("close log file for rotation: %w", err)
	}

	// Rename current → timestamped backup
	ts := time.Now().Format("20060102-150405")
	backupPath := w.cfg.Path + "." + ts
	if err := os.Rename(w.cfg.Path, backupPath); err != nil {
		// If rename fails, try to reopen the original
		_ = w.openFile()
		return fmt.Errorf("rename log file for rotation: %w", err)
	}

	// Compress if configured (in background to not block writes)
	if w.cfg.Compress {
		go compressFile(backupPath)
	}

	// Open new file
	if err := w.openFile(); err != nil {
		return err
	}

	// Prune old backups
	go w.pruneOldBackups()

	return nil
}

// pruneOldBackups removes rotated files beyond MaxBackups count or MaxAge days.
func (w *RotatingFileWriter) pruneOldBackups() {
	dir := filepath.Dir(w.cfg.Path)
	base := filepath.Base(w.cfg.Path)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	var backups []os.DirEntry
	for _, e := range entries {
		name := e.Name()
		if name == base {
			continue // skip current log
		}
		// Match pattern: base.YYYYMMDD-HHMMSS or base.YYYYMMDD-HHMMSS.gz
		if strings.HasPrefix(name, base+".") {
			backups = append(backups, e)
		}
	}

	// Sort by name (timestamp suffix ensures chronological order)
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Name() < backups[j].Name()
	})

	cutoff := time.Now().AddDate(0, 0, -w.cfg.MaxAge)

	// Remove by age
	var kept []os.DirEntry
	for _, b := range backups {
		info, err := b.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, b.Name()))
		} else {
			kept = append(kept, b)
		}
	}

	// Remove by count (keep only MaxBackups most recent)
	if len(kept) > w.cfg.MaxBackups {
		excess := kept[:len(kept)-w.cfg.MaxBackups]
		for _, b := range excess {
			_ = os.Remove(filepath.Join(dir, b.Name()))
		}
	}
}

// compressFile gzips a file in place and removes the original.
func compressFile(path string) {
	src, err := os.Open(path)
	if err != nil {
		return
	}
	defer src.Close()

	dst, err := os.Create(path + ".gz")
	if err != nil {
		return
	}

	gz := gzip.NewWriter(dst)
	if _, err := io.Copy(gz, src); err != nil {
		_ = gz.Close()
		_ = dst.Close()
		_ = os.Remove(path + ".gz")
		return
	}
	_ = gz.Close()
	_ = dst.Close()
	_ = src.Close()
	_ = os.Remove(path) // remove uncompressed original
}
