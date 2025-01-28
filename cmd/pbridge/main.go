package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"pbridge/pkg/apiserver"
	"pbridge/pkg/config"
	"pbridge/pkg/ebpf"
	"pbridge/pkg/logging"
	"pbridge/pkg/wgclient"
	"pbridge/pkg/wgserver"
	"pbridge/testclient"

	"github.com/alecthomas/kingpin/v2"
)

var (
	app = kingpin.New("pbridge", "Personal bridge.")

	commandStart = app.Command("start", "Start personal bridge server")
	flagConfig   = commandStart.Flag("config", "Path to the configuration file").Required().ExistingFile()

	commandConnect      = app.Command("connect", "Run test")
	flagConnectUsername = commandConnect.Flag("username", "Username").Required().String()
	flagConnectPassword = commandConnect.Flag("password", "Password").Required().String()
	flagConnectServers  = commandConnect.Flag("server", "Server").Required().Strings()
)

func main() {
	switch kingpin.MustParse(app.Parse(os.Args[1:])) {
	case commandStart.FullCommand():
		actionStart(*flagConfig)
	case commandConnect.FullCommand():
		testclient.Connect(*flagConnectUsername, *flagConnectPassword, *flagConnectServers)
	}
}

func actionStart(configPath string) {
	// Load the configuration
	cfg, err := config.Load(configPath)
	if err != nil {
		slog.Error("error loading configuration", slog.Any("err", err))
		os.Exit(1)
		return
	}

	// Initialize logging
	logging.Init(cfg.Logging)

	// Check ebpf features
	err = ebpf.CheckEbpfFeatures()
	if err != nil {
		slog.Error("ebpf features check failed", slog.Any("err", err))
		os.Exit(1)
		return
	}
	slog.Info("checking ebpf features succeeded")

	// Remove memlock limits
	err = ebpf.RemoveMemlockLimit()
	if err != nil {
		slog.Error("error removing memlock limit", slog.Any("err", err))
		os.Exit(1)
		return
	}

	// Initialize the Wireguard server
	wgServer := wgserver.New(&cfg.Wireguard.Server)
	err = wgServer.Init()
	if err != nil {
		slog.Error("error initializing wireguard server", slog.Any("err", err))
		os.Exit(1)
		return
	}
	defer wgServer.Close()

	// Initialize the Wireguard client
	wgClient := wgclient.New(&cfg.Wireguard.Client)
	err = wgClient.Init()
	if err != nil {
		slog.Error("error initializing wireguard client", slog.Any("err", err))
		os.Exit(1)
		return
	}

	slog.Info("start API server")
	apiServer, err := apiserver.New(cfg.API, wgServer, wgClient)
	if err != nil {
		slog.Error("error creating API server", slog.Any("err", err))
		os.Exit(1)
		return
	}
	err = apiServer.Load()
	if err != nil {
		slog.Error("error loading API server", slog.Any("err", err))
		os.Exit(1)
		return
	}

	go MustRun("API server", apiServer.ListenAndServe)

	slog.Info("started")

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

func MustRun(name string, fn func() error) {
	if err := fn(); err != nil {
		slog.Error("error running service", slog.String("name", name), slog.Any("err", err))
		os.Exit(1)
	}
}
