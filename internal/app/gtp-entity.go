// Copyright 2024 Louis Royer and the NextMN-UPF contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT
package app

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/nextmn/upf/internal/constants"
	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

func (s *Setup) createGTPUProtocolEntities() error {
	for _, v := range s.config.Gtpu.GTPUProtocolEntities {
		go s.createGtpUProtocolEntity(v.Addr)
	}
	return nil
}

func (s *Setup) createGtpUProtocolEntity(ipAddress string) error {
	fmt.Println("Creating new GTP-U Protocol Entity on", ipAddress)
	var udpaddr string
	if strings.Count(ipAddress, ":") > 0 {
		udpaddr = fmt.Sprintf("[%s]:%s", ipAddress, constants.GTPU_PORT)
	} else {
		udpaddr = fmt.Sprintf("%s:%s", ipAddress, constants.GTPU_PORT)
	}
	laddr, err := net.ResolveUDPAddr("udp", udpaddr)
	if err != nil {
		fmt.Println("Error while resolving UDP address of local GTP entity")
		return err
	}
	uConn := gtpv1.NewUPlaneConn(laddr)
	defer uConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uConn.DisableErrorIndication()
	uConn.AddHandler(message.MsgTypeTPDU, func(c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
		return tpduHandler(ipAddress, c, senderAddr, msg, s.farUconnDb, s.tunInterface, s.pfcpServer)
	})
	if err := uConn.ListenAndServe(ctx); err != nil {
		return err
	}

	return nil
}
