package main

import (
	"embed"
	"io/fs"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed frontend
var frontend embed.FS

func main() {
	assets, err := fs.Sub(frontend, "frontend")
	if err != nil {
		log.Fatal(err)
	}

	app := &App{session: newSession(nil)}
	err = wails.Run(&options.App{
		Title: "LFish — анализатор трафика", Width: 1440, Height: 920,
		MinWidth: 780, MinHeight: 610, BackgroundColour: options.NewRGB(14, 15, 21),
		AssetServer: &assetserver.Options{Assets: assets},
		OnStartup:   app.startup, OnShutdown: app.shutdown, OnBeforeClose: app.beforeClose,
		Bind: []interface{}{app},
	})
	if err != nil {
		log.Fatal(err)
	}
}
