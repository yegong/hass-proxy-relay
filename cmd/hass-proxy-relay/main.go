package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/yegong/hass-proxy-relay/internal/config"
	"github.com/yegong/hass-proxy-relay/internal/proxy"
	"github.com/yegong/hass-proxy-relay/internal/relay"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("relay stopped", "event", "shutdown_failure", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	var configPath string
	flag.StringVar(&configPath, "c", "", "path to the YAML configuration file (required)")
	flag.Parse()
	if configPath == "" {
		return errors.New("-c is required")
	}
	if flag.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flag.Args())
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.Listen, err)
	}

	connector := proxy.NewHTTPConnector(cfg.Upstream, cfg.Timeouts.Connect, cfg.Timeouts.ProxyHandshake)
	server := relay.NewServer(cfg.AllowedHosts, cfg.Timeouts.ClientHello, connector, logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger.Info(
		"relay started",
		"event", "startup",
		"listen", listener.Addr().String(),
		"upstream", cfg.Upstream.Host,
		"allowed_hosts", len(cfg.AllowedHosts),
	)
	if err := server.Serve(ctx, listener); err != nil {
		return err
	}
	logger.Info("relay stopped", "event", "shutdown")
	return nil
}
