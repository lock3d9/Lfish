package main

import "testing"

func TestPreferencesRoundTrip(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	app := &App{}
	if err := app.SetMode("advanced"); err != nil {
		t.Fatal(err)
	}

	initial, err := app.GetPreferences()
	if err != nil || initial != (Preferences{Language: "ru", Theme: "purple"}) {
		t.Fatalf("unexpected defaults: %+v, %v", initial, err)
	}
	selected := Preferences{Language: "uk", Theme: "light"}
	if err := app.SetPreferences(selected); err != nil {
		t.Fatal(err)
	}
	if err := app.SetPreferences(Preferences{Language: "unknown", Theme: "dark"}); err == nil {
		t.Fatal("accepted an unknown language")
	}
	saved, err := (&App{}).GetPreferences()
	if err != nil || saved != selected {
		t.Fatalf("unexpected saved preferences: %+v, %v", saved, err)
	}
	if mode, err := app.GetMode(); err != nil || mode != "advanced" {
		t.Fatalf("unexpected saved mode: %q, %v", mode, err)
	}
}
