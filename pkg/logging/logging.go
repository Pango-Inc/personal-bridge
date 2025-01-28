package logging

import (
	"log/slog"
	"os"
	"vpnlite/pkg/config"
)

func Init(cfg config.LoggingConfig) {
	switch cfg.Format {
	case "json":
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: cfg.Level,
		})))
	case "text":
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: cfg.Level,
		})))
	default:
		slog.Error("unsupported log format", "format", cfg.Format)
		os.Exit(1)
	}
}
