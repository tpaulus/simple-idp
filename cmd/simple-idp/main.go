package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/time/rate"

	"github.com/tpaulus/simple-idp/internal/certauth"
	"github.com/tpaulus/simple-idp/internal/config"
	"github.com/tpaulus/simple-idp/internal/endpoint"
	"github.com/tpaulus/simple-idp/internal/observability"
	"github.com/tpaulus/simple-idp/internal/service"
	"github.com/tpaulus/simple-idp/internal/store"
	"github.com/tpaulus/simple-idp/internal/tokens"
	httptransport "github.com/tpaulus/simple-idp/internal/transport/http"
)

func main() {
	var configPath string
	var httpAddr string
	var logFormat string
	var validateConfig bool
	flag.StringVar(&configPath, "config", "/etc/simple-idp/config.yaml", "path to config file")
	flag.StringVar(&httpAddr, "http-addr", ":8080", "HTTP bind address")
	flag.StringVar(&logFormat, "log-format", "json", "log format: json or text")
	flag.BoolVar(&validateConfig, "validate-config", false, "validate configuration and exit")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatal(err)
	}
	logger := observability.NewLogger(logFormat)
	if validateConfig {
		_, _ = fmt.Fprintln(os.Stdout, cfg.RedactedYAML())
		return
	}
	auth := certauth.New(certauth.Config{
		TrustedProxyNets:      cfg.TrustedProxyNets,
		PEMHeader:             cfg.ForwardedClientCert.PEMHeader,
		InfoHeader:            cfg.ForwardedClientCert.InfoHeader,
		RequirePEM:            cfg.ForwardedClientCert.RequirePEM,
		RequireInfoCommonName: cfg.ForwardedClientCert.RequireInfoCommonName,
		CARoots:               cfg.ClientCARoots,
	})
	svc := service.New(cfg, auth, store.NewCodeStore(cfg.OAuth.MaxOutstandingCodes, nil), tokens.New(cfg, nil), nil)
	eps := endpoint.New(svc, endpoint.NewIPRateLimiter(rate.Every(100000000), 10, nil), endpoint.NewIPRateLimiter(rate.Every(100000000), 10, nil))
	handler := httptransport.NewHandler(cfg, eps, logger)
	server := &http.Server{Addr: httpAddr, Handler: handler, ReadTimeout: cfg.HTTP.ReadTimeout, WriteTimeout: cfg.HTTP.WriteTimeout, IdleTimeout: cfg.HTTP.IdleTimeout, MaxHeaderBytes: cfg.HTTP.MaxHeaderBytes}
	logger.Info("starting server", "addr", httpAddr)
	log.Fatal(server.ListenAndServe())
}
