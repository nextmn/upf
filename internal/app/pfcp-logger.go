// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package app

import (
	"time"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
)

type PFCPLogger struct {
	srv  *pfcp_networking.PFCPEntityUP
	stop chan bool
}

func NewPFCPLogger(server *pfcp_networking.PFCPEntityUP) *PFCPLogger {
	return &PFCPLogger{
		srv:  server,
		stop: make(chan bool, 1),
	}
}

func (l *PFCPLogger) Run() {
	for {
		select {
		case <-l.stop:
			return
		case <-time.After(10 * time.Second):
			l.srv.PrintPFCPRules()
		}
	}
}

func (l *PFCPLogger) Exit() {
	l.stop <- true
}
