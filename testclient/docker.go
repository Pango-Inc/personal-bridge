package testclient

import (
	_ "embed"
	"log/slog"
	"os"
	"os/exec"
	"path"
)

func dockerPrepare() {
	_, err := exec.LookPath("docker")
	if err != nil {
		slog.Error("Docker not found", slog.Any("err", err))
		os.Exit(1)
	}

	if !dockerImageExists() {
		dockerImageBuild()
	}
}

func dockerRunClient(clientDir string) {
	slog.Info("Starting wireguard client...")

	// remove old container
	cmd := exec.Command("docker", "rm", "-f", "wireguard-conn")
	_ = cmd.Run()

	cmd = exec.Command("docker", "run", "--name", "wireguard-conn", "--dns", "1.1.1.1", "-d", "--privileged",
		"--sysctl", "net.ipv6.conf.all.disable_ipv6=0",
		"-v", clientDir+":/src", "-w", "/src",
		"-p", "127.0.0.1:8080:8080",
		"vpnlite-testclient",
		"bash", "-c", "wg-quick up ./wg.conf && proxy")
	err := cmd.Run()
	if err != nil {
		slog.Error("Failed to start docker container with wireguard client", slog.Any("err", err))
		os.Exit(1)
	}

	slog.Info("Wireguard client started")
	slog.Info("You can access the client by using:")
	slog.Info(" * http://localhost:8080 - HTTP proxy")
	slog.Info(" * docker exec -it wireguard-conn bash - CLI")
}

func dockerImageExists() bool {
	cmd := exec.Command("docker", "image", "inspect", "vpnlite-testclient")
	err := cmd.Run()
	return err == nil
}

func dockerImageBuild() {
	slog.Info("Preparing to build docker image vpnlite-testclient...")
	tempDir, err := os.MkdirTemp("", "vpnlite-image-*")
	if err != nil {
		slog.Error("Failed to create temporary directory", slog.Any("err", err))
		os.Exit(1)
		return
	}
	defer os.RemoveAll(tempDir)

	// copy image to temp dir
	for fileName, fileData := range dockerSources {
		err = os.WriteFile(path.Join(tempDir, fileName), []byte(fileData), 0644)
		if err != nil {
			slog.Error("Failed to write image file", slog.Any("err", err))
			os.Exit(1)
		}
	}

	slog.Info("Building docker image vpnlite-testclient...")
	cmd := exec.Command("docker", "build", "-t", "vpnlite-testclient", tempDir)
	err = cmd.Run()
	if err != nil {
		slog.Error("Failed to build docker image", slog.Any("err", err))
		os.Exit(1)
	}
	slog.Info("Docker image vpnlite-testclient is ready")
}
