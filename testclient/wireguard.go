package testclient

import (
	_ "embed"
	"log/slog"
	"os"
	"text/template"
)

//go:embed wg.gotmpl
var wgTemplate string

type WireguardConfigParams struct {
	ClientPrivateKey string
	ConnectResponse  ConnectResponse
}

func prepareWireguardConfig(clientDir, clientPrivateKey string, connectResponse ConnectResponse) {
	// This code is executed when the migration is applied.
	tmpl, err := template.New("wg.conf").Parse(wgTemplate)
	if err != nil {
		slog.Error("Failed to parse template", slog.Any("err", err))
		os.Exit(1)
		return
	}

	fd, err := os.Create(clientDir + "/wg.conf")
	if err != nil {
		slog.Error("Failed to create file", slog.Any("err", err))
		os.Exit(1)
		return
	}

	err = tmpl.Execute(fd, &WireguardConfigParams{
		ClientPrivateKey: clientPrivateKey,
		ConnectResponse:  connectResponse,
	})
	if err != nil {
		slog.Error("Failed to execute template", slog.Any("err", err))
		os.Exit(1)
		return
	}

	err = fd.Close()
	if err != nil {
		slog.Error("Failed to close file", slog.Any("err", err))
		os.Exit(1)
		return
	}

	slog.Info("Wireguard config file created", slog.Any("path", clientDir+"/wg.conf"))
}
