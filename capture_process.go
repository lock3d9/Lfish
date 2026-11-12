package main

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lfish/internal/live"
)

const helperName = "lfish-capture"

func captureHelperPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(executable), helperName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", errors.New("Рядом с LFish должен находиться исполняемый файл lfish-capture")
	}
	return path, nil
}

type captureProcess struct {
	cmd     *exec.Cmd
	cancel  context.CancelFunc
	input   io.WriteCloser
	output  io.ReadCloser
	decoder *gob.Decoder
}

func openCaptureProcess(path, device, filter string) (*captureProcess, live.Message, error) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, path, device, filter)
	input, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, live.Message{}, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = input.Close()
		return nil, live.Message{}, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		_ = input.Close()
		_ = output.Close()
		return nil, live.Message{}, err
	}
	process := &captureProcess{cmd: cmd, cancel: cancel, input: input, output: output, decoder: gob.NewDecoder(output)}
	timer := time.AfterFunc(5*time.Second, cancel)
	var first live.Message
	err = process.decoder.Decode(&first)
	timer.Stop()
	if err != nil || first.Kind != live.Ready {
		process.close()
		process = nil
	}
	return process, first, err
}

func (p *captureProcess) close() {
	_ = p.input.Close()
	_ = p.output.Close()
	p.cancel()
	_ = p.cmd.Wait()
}

func (a *App) GrantCapturePermission() (bool, error) {
	if !a.grant.TryLock() {
		return false, errors.New("Запрос прав уже открыт")
	}
	defer a.grant.Unlock()
	path, err := captureHelperPath()
	if err != nil {
		return false, err
	}
	const pkexec = "/usr/bin/pkexec"
	var setcap string
	for _, path := range []string{"/usr/bin/setcap", "/usr/sbin/setcap", "/sbin/setcap"} {
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			setcap = path
			break
		}
	}
	if _, err := os.Stat(pkexec); err != nil || setcap == "" {
		return false, errors.New("Для запроса прав нужны PolicyKit и утилита setcap")
	}
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	output, err := exec.CommandContext(ctx, pkexec, "--disable-internal-agent", setcap, "cap_net_raw=ep", path).CombinedOutput()
	if ctx.Err() != nil {
		return false, errors.New("Время ожидания подтверждения прав истекло")
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 126 {
		return false, nil
	}
	if err != nil {
		detail := strings.TrimSpace(string(output))
		if detail == "" {
			detail = err.Error()
		}
		return false, fmt.Errorf("Не удалось выдать права на захват: %s", detail)
	}
	return true, nil
}
