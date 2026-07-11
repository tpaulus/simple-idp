package observability

import (
	"context"
	"log/slog"
	"os"
)

func NewLogger(format string) *slog.Logger {
	if format == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

func WithRequest(logger *slog.Logger, method, path, remote string) *slog.Logger {
	return logger.With("method", method, "path", path, "remote_addr", remote)
}

func ContextWithLogger(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

func LoggerFromContext(ctx context.Context) *slog.Logger {
	logger, ok := ctx.Value(loggerKey{}).(*slog.Logger)
	if ok && logger != nil {
		return logger
	}
	return slog.Default()
}

type loggerKey struct{}
