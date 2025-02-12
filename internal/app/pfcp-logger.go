// Copyright 2024 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"time"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
)

type PFCPLogger struct {
	srv *pfcp_networking.PFCPEntityUP
}

func NewPFCPLogger(server *pfcp_networking.PFCPEntityUP) *PFCPLogger {
	return &PFCPLogger{
		srv: server,
	}
}

func (l *PFCPLogger) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
			l.srv.LogPFCPRules()
		}
	}
}
