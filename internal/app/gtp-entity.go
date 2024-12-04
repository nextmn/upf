// Copyright 2024 Louis Royer and the NextMN contributors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.
// SPDX-License-Identifier: MIT

package app

import (
	"context"
	"net"
	"net/netip"

	"github.com/nextmn/upf/internal/constants"

	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

func (s *Setup) createGTPUProtocolEntities() error {
	for _, v := range s.config.Gtpu.GTPUProtocolEntities {
		go s.createGtpUProtocolEntity(v.Addr)
	}
	return nil
}

func (s *Setup) createGtpUProtocolEntity(ipAddress netip.Addr) error {
	logrus.WithFields(logrus.Fields{"listen-addr": ipAddress}).Info("Creating new GTP-U Protocol Entity")
	laddr := net.UDPAddrFromAddrPort(netip.AddrPortFrom(ipAddress, constants.GTPU_PORT))
	uConn := gtpv1.NewUPlaneConn(laddr)
	defer uConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uConn.DisableErrorIndication()
	uConn.AddHandler(message.MsgTypeTPDU, func(c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
		return tpduHandler(ipAddress.String(), c, senderAddr, msg, s.farUconnDb, s.tunInterface, s.pfcpServer)
	})
	if err := uConn.ListenAndServe(ctx); err != nil {
		return err
	}

	return nil
}
