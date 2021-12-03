package main

import (
	"context"

	"github.com/gradusp/crispy-ipruler/internal/app"
	"github.com/gradusp/go-platform/logger"
	"github.com/gradusp/go-platform/pkg/signals"
	"go.uber.org/zap"
)

func setupContext() {
	ctx, cancel := context.WithCancel(context.Background())
	signals.WhenSignalExit(func() error {
		logger.SetLevel(zap.InfoLevel)
		logger.Info(ctx, "caught application stop signal")
		cancel()
		return nil
	})
	app.SetContext(ctx)
}
