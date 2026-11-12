package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type Preferences struct {
	Language string `json:"language"`
	Theme    string `json:"theme"`
}

func (p Preferences) valid() bool {
	return (p.Language == "ru" || p.Language == "en" || p.Language == "uk") &&
		(p.Theme == "purple" || p.Theme == "dark" || p.Theme == "light")
}

func (a *App) GetPreferences() (Preferences, error) {
	defaults := Preferences{Language: "ru", Theme: "purple"}
	path, err := preferencesPath()
	if err != nil {
		return defaults, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return defaults, nil
	}
	if err != nil {
		return defaults, err
	}
	prefs := defaults
	if err := json.Unmarshal(data, &prefs); err != nil {
		return defaults, err
	}
	if !prefs.valid() {
		return defaults, nil
	}
	return prefs, nil
}

func (a *App) SetPreferences(prefs Preferences) error {
	if !prefs.valid() {
		return errors.New("Неизвестный язык или тема")
	}
	path, err := preferencesPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := atomicFile(path, func(w io.Writer) error { return json.NewEncoder(w).Encode(prefs) }); err != nil {
		return err
	}
	a.updateTitle()
	return nil
}

func preferencesPath() (string, error) {
	path, err := settingsPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(path), "preferences.json"), nil
}

var translations = func() map[string][2]string {
	data, err := frontend.ReadFile("frontend/i18n.json")
	if err != nil {
		panic(err)
	}
	var result map[string][2]string
	if err := json.Unmarshal(data, &result); err != nil {
		panic(err)
	}
	return result
}()

func localText(language, source string) string {
	pair, ok := translations[source]
	if ok {
		switch language {
		case "en":
			return pair[0]
		case "uk":
			return pair[1]
		}
	}
	return source
}
