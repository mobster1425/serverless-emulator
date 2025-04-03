package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"net/http"
	"github.com/google/uuid"
	"github.com/go-chi/chi/middleware"

	"github.com/rs/zerolog"
)

// Logger wraps zerolog.Logger to provide additional functionality
type Logger struct {
	zerolog.Logger
}

// Config holds the logger configuration
type Config struct {
	// Level is the minimum level to log
	Level string `json:"level" default:"info"`
	
	// Format specifies the output format (json or console)
	Format string `json:"format" default:"console"`
	
	// Output specifies where to write logs (stdout, stderr, or file path)
	Output string `json:"output" default:"stdout"`
	
	// TimeFormat specifies the format for timestamps
	TimeFormat string `json:"time_format" default:"2006-01-02T15:04:05.000Z07:00"`
	
	// AddCaller adds the caller (file:line) to log entries
	AddCaller bool `json:"add_caller" default:"true"`
}

// contextKey is the type for context keys
type contextKey string

const (
	// loggerContextKey is the key used to store the logger in context
	loggerContextKey = contextKey("logger")

	// defaultTimeFormat is the default time format for logging
	defaultTimeFormat = "2006-01-02T15:04:05.000Z07:00"
)

// NewLogger creates a new logger instance with the provided configuration
func NewLogger(cfg *Config) *Logger {
	if cfg == nil {
		cfg = &Config{
			Level:      "info",
			Format:     "console",
			Output:     "stdout",
			TimeFormat: defaultTimeFormat,
			AddCaller:  true,
		}
	}

	// Configure zerolog
	zerolog.TimeFieldFormat = cfg.TimeFormat
	level := parseLevel(cfg.Level)
	zerolog.SetGlobalLevel(level)

	// Configure output writer
	var output io.Writer
	switch strings.ToLower(cfg.Output) {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// Attempt to open file for writing
		file, err := os.OpenFile(cfg.Output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("Failed to open log file %s: %v\n", cfg.Output, err)
			output = os.Stdout
		} else {
			output = file
		}
	}

	// Configure output format
	if strings.ToLower(cfg.Format) == "console" {
		output = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: cfg.TimeFormat,
			NoColor:    false,
		}
	}

	// Create logger
	logger := zerolog.New(output).
		With().
		Timestamp().
		Logger()

	// Add caller if configured
	if cfg.AddCaller {
		logger = logger.With().Caller().Logger()
	}

	return &Logger{
		Logger: logger,
	}
}

// WithContext returns a copy of context with the logger attached
func WithContext(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, loggerContextKey, logger)
}

// FromContext retrieves the logger from the context
func FromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(loggerContextKey).(*Logger); ok {
		return logger
	}
	return NewLogger(nil) // Return default logger if none in context
}

// WithFields creates a new logger with additional fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	ctx := l.With()
	for k, v := range fields {
		ctx = ctx.Interface(k, v)
	}
	return &Logger{Logger: ctx.Logger()}
}

// WithField creates a new logger with an additional field
func (l *Logger) WithField(key string, value interface{}) *Logger {
	return &Logger{Logger: l.With().Interface(key, value).Logger()}
}

// WithError creates a new logger with an error field
func (l *Logger) WithError(err error) *Logger {
	return &Logger{Logger: l.With().Err(err).Logger()}
}

// WithRequestID adds a request ID to the logger
func (l *Logger) WithRequestID(requestID string) *Logger {
	return l.WithField("request_id", requestID)
}

// WithFunctionID adds a function ID to the logger
func (l *Logger) WithFunctionID(functionID string) *Logger {
	return l.WithField("function_id", functionID)
}

// TraceContext logs a message with trace context
func (l *Logger) TraceContext(ctx context.Context, msg string) {
	addContext(ctx, l.Trace().Time("time", time.Now())).Msg(msg)
}

// DebugContext logs a message with debug context
func (l *Logger) DebugContext(ctx context.Context, msg string) {
	addContext(ctx, l.Debug().Time("time", time.Now())).Msg(msg)
}

// InfoContext logs a message with info context
func (l *Logger) InfoContext(ctx context.Context, msg string) {
	addContext(ctx, l.Info().Time("time", time.Now())).Msg(msg)
}

// WarnContext logs a message with warn context
func (l *Logger) WarnContext(ctx context.Context, msg string) {
	addContext(ctx, l.Warn().Time("time", time.Now())).Msg(msg)
}

// ErrorContext logs a message with error context
func (l *Logger) ErrorContext(ctx context.Context, msg string, err error) {
	addContext(ctx, l.Error().Time("time", time.Now()).Err(err)).Msg(msg)
}

// FatalContext logs a message with fatal context
func (l *Logger) FatalContext(ctx context.Context, msg string) {
	addContext(ctx, l.Fatal().Time("time", time.Now())).Msg(msg)
}

// Helper functions

// parseLevel converts a string level to zerolog.Level
func parseLevel(level string) zerolog.Level {
	switch strings.ToLower(level) {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}

// addContext adds context values to a log event
func addContext(ctx context.Context, e *zerolog.Event) *zerolog.Event {
	if ctx == nil {
		return e
	}
	
	// Add request ID if present
	if requestID, ok := ctx.Value("request_id").(string); ok {
		e = e.Str("request_id", requestID)
	}
	
	// Add function ID if present
	if functionID, ok := ctx.Value("function_id").(string); ok {
		e = e.Str("function_id", functionID)
	}
	
	return e
}

// Example middleware for HTTP handlers
type LogMiddleware struct {
	logger *Logger
}

// NewLogMiddleware creates a new logging middleware
func NewLogMiddleware(logger *Logger) *LogMiddleware {
	return &LogMiddleware{logger: logger}
}

// RequestLogger is an example middleware function for HTTP request logging
func (l *LogMiddleware) RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a request ID if not present
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Add logger to context
		ctx := r.Context()
		logger := l.logger.WithRequestID(requestID)
		ctx = WithContext(ctx, logger)

		// Log request
		logger.Info().
			Time("time", time.Now()).
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Interface("headers", r.Header).
			Msg("Request started")

		// Create response wrapper to capture status code
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

		// Process request
		next.ServeHTTP(ww, r.WithContext(ctx))

		// Log response
		duration := time.Since(start)
		logger.Info().
			Time("time", time.Now()).
			Int("status", ww.Status()).
			Dur("duration", duration).
			Int("bytes_written", ww.BytesWritten()).
			Msg("Request completed")
	})
}
/*
// New creates a new Logger from a zerolog context
func New(ctx zerolog.Context) *Logger {
	return &Logger{
		Logger: ctx.Logger(),
	}
}
	*/