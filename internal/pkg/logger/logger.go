// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package logger

import (
	"io"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger wraps zap.SugaredLogger with additional functionality
type Logger struct {
	*zap.SugaredLogger
	base  *zap.Logger
	level zap.AtomicLevel
}

// New creates a new Logger instance
func New(level, format string) (*Logger, error) {
	return NewWithOutput(level, format, os.Stdout)
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
	l.SugaredLogger.Fatalw(msg, keysAndValues...)
}

// Panic logs a message at Panic level and panics
func (l *Logger) Panic(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Panicw(msg, keysAndValues...)
}

// Error logs a message at Error level
func (l *Logger) Error(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Errorw(msg, keysAndValues...)
}

// Warn logs a message at Warn level
func (l *Logger) Warn(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Warnw(msg, keysAndValues...)
}

// Info logs a message at Info level
func (l *Logger) Info(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Infow(msg, keysAndValues...)
}

// Debug logs a message at Debug level
func (l *Logger) Debug(msg string, keysAndValues ...interface{}) {
	l.SugaredLogger.Debugw(msg, keysAndValues...)
}

// Nop returns a no-op logger that discards all output
func Nop() *Logger {
	return &Logger{
		SugaredLogger: zap.NewNop().Sugar(),
		base:          zap.NewNop(),
		level:         zap.NewAtomicLevel(),
	}
}
