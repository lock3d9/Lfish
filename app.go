package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"lfish/internal/live"
)

type App struct {
	ctx     context.Context
	control sync.Mutex
	grant   sync.Mutex
	mu      sync.RWMutex
	session *session
	stop    *captureProcess
	done    chan struct{}
}

type Interface struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
	Loopback  bool     `json:"loopback"`
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.updateTitle()
}

func (a *App) updateTitle() {
	prefs, _ := a.GetPreferences()
	if a.ctx != nil {
		wruntime.WindowSetTitle(a.ctx, "LFish — "+localText(prefs.Language, "Анализатор трафика"))
	}
}
func (a *App) shutdown(context.Context) { a.StopCapture() }

func (a *App) beforeClose(ctx context.Context) bool {
	a.mu.RLock()
	dirty := a.session.noteRevision != a.session.savedNoteRevision
	a.mu.RUnlock()
	if !dirty {
		return false
	}
	prefs, _ := a.GetPreferences()
	cancel := localText(prefs.Language, "Отмена")
	quit := localText(prefs.Language, "Выйти")
	answer, err := wruntime.MessageDialog(ctx, wruntime.MessageDialogOptions{
		Type: wruntime.QuestionDialog, Title: localText(prefs.Language, "Есть несохранённые заметки"),
		Message: localText(prefs.Language, "Вернитесь к захвату, чтобы сохранить заметки в PCAPNG."),
		Buttons: []string{cancel, quit}, DefaultButton: cancel, CancelButton: cancel,
	})
	return err != nil || answer != quit
}

func (a *App) Interfaces() ([]Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var result []Interface
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 {
			continue
		}
		item := Interface{Name: device.Name, Loopback: device.Flags&net.FlagLoopback != 0}
		addresses, _ := device.Addrs()
		for _, address := range addresses {
			ip, _, err := net.ParseCIDR(address.String())
			if err == nil {
				item.Addresses = append(item.Addresses, ip.String())
			}
		}
		result = append(result, item)
	}
	return result, nil
}

func (a *App) StartCapture(device, filter string) (string, error) {
	a.control.Lock()
	defer a.control.Unlock()
	a.mu.RLock()
	running := a.done != nil
	a.mu.RUnlock()
	if running {
		return "", errors.New("Остановите текущий захват")
	}
	interfaces, err := a.Interfaces()
	if err != nil {
		return "", err
	}
	local := make(map[string]bool)
	found := false
	for _, iface := range interfaces {
		if iface.Name == device {
			found = true
		}
		for _, addr := range iface.Addresses {
			local[addr] = true
		}
	}
	if !found {
		return "", errors.New("Выберите активный сетевой интерфейс")
	}
	path, err := captureHelperPath()
	if err != nil {
		return "", err
	}
	process, first, err := openCaptureProcess(path, device, filter)
	if err != nil {
		return "", fmt.Errorf("Не удалось запустить процесс захвата: %w", err)
	}
	switch first.Kind {
	case live.Permission:
		return live.Permission, nil
	case live.OpenError:
		return "", fmt.Errorf("Не удалось открыть: %s: %s", device, first.Detail)
	case live.FilterError:
		return "", fmt.Errorf("Фильтр захвата BPF: %s", first.Detail)
	case live.Ready:
	default:
		return "", errors.New("Неожиданный ответ процесса захвата")
	}

	s := newSession(local)
	s.iface = device
	s.dropped = 0
	done := make(chan struct{})
	a.mu.Lock()
	a.session, a.stop, a.done = s, process, done
	a.mu.Unlock()
	ownerContext, stopOwners := context.WithCancel(context.Background())
	go a.trackSocketOwners(ownerContext, s)
	go a.capture(process, first, s, done, stopOwners)
	return live.Ready, nil
}

func (a *App) capture(process *captureProcess, first live.Message, s *session, done chan struct{}, stopOwners context.CancelFunc) {
	var notice string
	defer func() {
		stopOwners()
		process.close()
		a.mu.Lock()
		a.stop, a.done = nil, nil
		s.notice = notice
		close(done)
		a.mu.Unlock()
	}()
	for {
		var message live.Message
		if err := process.decoder.Decode(&message); err != nil {
			if !errors.Is(err, io.EOF) {
				notice = "Захват завершён: " + err.Error()
			}
			return
		}
		switch message.Kind {
		case live.Stats:
			a.mu.Lock()
			s.dropped = message.Dropped
			a.mu.Unlock()
		case live.Packet:
			p := decodePacket(message.Data, message.CaptureInfo(), first.Link, s.iface)
			a.mu.Lock()
			err := s.append(p)
			a.mu.Unlock()
			if err != nil {
				notice = err.Error()
				return
			}
		case live.ReadError:
			notice = "Захват завершён: " + message.Detail
			return
		}
	}
}

func (a *App) StopCapture() {
	a.control.Lock()
	defer a.control.Unlock()
	a.mu.RLock()
	stop, done := a.stop, a.done
	a.mu.RUnlock()
	if stop != nil {
		_ = stop.input.Close()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			stop.cancel()
			<-done
		}
	}
}

func (a *App) View(query Query) View {
	a.mu.RLock()
	defer a.mu.RUnlock()
	v := a.session.view(query)
	v.Running = a.done != nil
	return v
}

func (a *App) Detail(id int) (PacketDetail, error) {
	a.mu.RLock()
	if id < 1 || id > len(a.session.packets) {
		a.mu.RUnlock()
		return PacketDetail{}, errors.New("Пакет не найден")
	}
	p := a.session.packets[id-1]
	a.mu.RUnlock()
	return p.detail(), nil
}

func (a *App) SetNote(id int, note string, marked bool) error {
	note = strings.TrimSpace(note)
	if !marked {
		note = ""
	}
	if len(note) > 4000 {
		return errors.New("Заметка должна занимать не больше 4000 байт")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if id < 1 || id > len(a.session.packets) {
		return errors.New("Пакет не найден")
	}
	p := &a.session.packets[id-1]
	if p.Note == note && p.Marked == marked {
		return nil
	}
	if !p.Marked && marked {
		a.session.marked++
	}
	if p.Marked && !marked {
		a.session.marked--
	}
	p.Note, p.Marked = note, marked
	a.session.noteRevision++
	return nil
}

func (a *App) Diagnose(target string) (Diagnosis, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.session.diagnose(target)
}

func (a *App) OpenCapture() (bool, error) {
	a.control.Lock()
	defer a.control.Unlock()
	a.mu.RLock()
	running := a.done != nil
	a.mu.RUnlock()
	if running {
		return false, errors.New("Остановите захват перед открытием файла")
	}
	prefs, _ := a.GetPreferences()
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title:   localText(prefs.Language, "Открыть захват"),
		Filters: []wruntime.FileFilter{{DisplayName: localText(prefs.Language, "Файлы захвата"), Pattern: "*.pcap;*.pcapng;*.cap"}, {DisplayName: localText(prefs.Language, "Все файлы"), Pattern: "*"}},
	})
	if err != nil || path == "" {
		return false, err
	}
	s, err := readCapture(path)
	if err != nil {
		return false, fmt.Errorf("Ошибка чтения: %s: %w", filepath.Base(path), err)
	}
	a.mu.Lock()
	a.session = s
	a.mu.Unlock()
	return true, nil
}

func (a *App) SaveCapture(format string) (string, error) {
	if format != "pcap" && format != "pcapng" {
		return "", errors.New("Выберите PCAP или PCAPNG")
	}
	a.control.Lock()
	defer a.control.Unlock()
	a.mu.RLock()
	packets := append([]Packet(nil), a.session.packets...)
	revision := a.session.noteRevision
	a.mu.RUnlock()
	if len(packets) == 0 {
		return "", errors.New("В сеансе пока нет пакетов")
	}
	prefs, _ := a.GetPreferences()
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title: localText(prefs.Language, "Сохранить захват"), DefaultFilename: "lfish-" + time.Now().Format("20060102-150405") + "." + format,
		Filters: []wruntime.FileFilter{{DisplayName: strings.ToUpper(format), Pattern: "*." + format}},
	})
	if err != nil || path == "" {
		return "", err
	}
	if !strings.EqualFold(filepath.Ext(path), "."+format) {
		return "", fmt.Errorf("Укажите расширение файла: .%s", format)
	}
	if err := writeCapture(path, format, packets); err != nil {
		return "", err
	}
	if format == "pcapng" {
		a.mu.Lock()
		a.session.savedNoteRevision = revision
		a.mu.Unlock()
	}
	return path, nil
}

func (a *App) GetMode() (string, error) {
	path, err := settingsPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	mode := strings.TrimSpace(string(data))
	if mode == "simple" || mode == "advanced" {
		return mode, nil
	}
	return "", nil
}

func (a *App) SetMode(mode string) error {
	if mode != "simple" && mode != "advanced" {
		return errors.New("Неизвестный режим")
	}
	path, err := settingsPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return atomicFile(path, func(w io.Writer) error { _, err := io.WriteString(w, mode+"\n"); return err })
}

func settingsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "lfish", "mode"), nil
}
