// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package app

import (
	"context"
	"fmt"

	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
	"github.com/nextmn/upf/internal/config"
	"github.com/songgao/water"
)

type Setup struct {
	config            *config.UpfConfig
	pfcpServer        *pfcp_networking.PFCPEntityUP
	farUconnDb        *FARAssociationDB
	tunInterface      *water.Interface
	logger            *PFCPLogger
	pfcpEntityOptions *pfcp_networking.EntityOptions
}

func NewSetup(config *config.UpfConfig) *Setup {
	opt := pfcp_networking.NewEntityOptions()
	srv := pfcp_networking.NewPFCPEntityUPWithOptions(config.Pfcp.NodeID, config.Pfcp.Addr, opt)
	return &Setup{
		config:            config,
		pfcpServer:        srv,
		farUconnDb:        NewFARAssociationDB(),
		logger:            NewPFCPLogger(srv),
		pfcpEntityOptions: opt,
	}
}
func (s *Setup) Init(ctx context.Context) error {
	if s.config.Gtpu.Forwarder != "wmnsk/go-gtp" {
		return fmt.Errorf("Only `wmnsk/go-gtp forwarder is supported`")
	}
	// setup pfcpEntityOptions
	if s.config.Pfcp.RetransTimeout != nil {
		if err := s.pfcpEntityOptions.SetMessageRetransmissionT1(*s.config.Pfcp.RetransTimeout); err != nil {
			return err
		}
	}
	if s.config.Pfcp.MaxRetrans != nil {
		if err := s.pfcpEntityOptions.SetMessageRetransmissionN1(*s.config.Pfcp.MaxRetrans); err != nil {
			return err
		}
	}

	go s.pfcpServer.ListenAndServeContext(ctx)
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

func (s *Setup) Run(ctx context.Context) error {
	defer s.Exit()
	if err := s.Init(ctx); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return nil
	}
}

func (s *Setup) Exit() error {
	s.logger.Exit()
	s.removeTun()
	s.pfcpServer.Close()
	return nil
}
