// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package app

import (
	"fmt"
	"time"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
	"github.com/nextmn/upf/internal/config"
	"github.com/songgao/water"
)

type Setup struct {
	config       *config.UpfConfig
	pfcpServer   *pfcp_networking.PFCPEntityUP
	farUconnDb   *FARAssociationDB
	tunInterface *water.Interface
	logger       *PFCPLogger
}

func NewSetup(config *config.UpfConfig) (*Setup, error) {
	var t1 *time.Duration
	if config.Pfcp.RetransTimeout != nil {
		if t, err := time.ParseDuration(*config.Pfcp.RetransTimeout); err != nil {
			return nil, fmt.Errorf("Could not parse RetransTimout: %v\n", err)
		} else {
			t1 = &t
		}
	}
	opt, err := pfcp_networking.NewEntityOptions(t1, config.Pfcp.MaxRetrans)
	if err != nil {
		return nil, fmt.Errorf("Could not create EntityOptions: %v\n", err)
	}
	srv := pfcp_networking.NewPFCPEntityUPWithOptions(config.Pfcp.NodeID, config.Pfcp.Addr, opt)
	return &Setup{
		config:     config,
		pfcpServer: srv,
		farUconnDb: NewFARAssociationDB(),
		logger:     NewPFCPLogger(srv),
	}, nil
}
func (s *Setup) Init() error {
	if s.config.Gtpu.Forwarder != "wmnsk/go-gtp" {
		return fmt.Errorf("Only `wmnsk/go-gtp forwarder is supported`")
	}
	s.pfcpServer.Start()
	if err := s.createTun(); err != nil {
		return err
	}
	if err := s.createTUNInterface(); err != nil {
		return nil
	}
	if err := s.createDLRoutes(); err != nil {
		return err
	}
	if err := s.createGTPUProtocolEntities(); err != nil {
		return err
	}
	go s.logger.Run()
	return nil
}

func (s *Setup) Run() error {
	if err := s.Init(); err != nil {
		return err
	}
	for {
		select {}
	}
}

func (s *Setup) Exit() error {
	s.logger.Exit()
	s.removeTun()
	return nil
}
