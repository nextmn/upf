// Copyright 2022 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/nextmn/upf/internal/app"
	"github.com/nextmn/upf/internal/config"
	"github.com/urfave/cli/v2"
)

func initSignals(ch chan *app.Setup) {
	cancelChan := make(chan os.Signal, 1)
	signal.Notify(cancelChan, syscall.SIGTERM, syscall.SIGINT)
	func(_ os.Signal) {}(<-cancelChan)
	select {
	case setup := <-ch:
		setup.Exit()
	default:
		break
	}
	os.Exit(0)
}

func main() {
	log.SetPrefix("[nextmn-upf] ")
	var config_file string
	ch := make(chan *app.Setup, 1)
	app := &cli.App{
		Name:                 "NextMN-UPF",
		Usage:                "Experimental 5G UPF",
		EnableBashCompletion: true,
		Authors: []*cli.Author{
			{Name: "Louis Royer"},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "Load configuration from `FILE`",
				Destination: &config_file,
				Required:    true,
				DefaultText: "not set",
			},
		},
		Action: func(c *cli.Context) error {
			conf, err := config.ParseConf(config_file)
			if err != nil {
				log.Println("Error loading config, exiting…:", err)
				os.Exit(1)
			}

			setup, err := app.NewSetup(conf)
			if err != nil {
				log.Println("Could not create Setup")
				os.Exit(2)
			}
			go func(cha chan *app.Setup, s *app.Setup) {
				cha <- s
			}(ch, setup)

			if err := setup.Run(); err != nil {
				log.Println("Error while running, exiting…:", err)
				setup.Exit()
				os.Exit(3)
			}
			return nil
		},
	}
	go initSignals(ch)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
