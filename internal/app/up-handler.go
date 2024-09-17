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
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	pfcp_networking "github.com/nextmn/go-pfcp-networking/pfcp"
	"github.com/nextmn/go-pfcp-networking/pfcp/api"
	"github.com/nextmn/upf/internal/constants"
	"github.com/sirupsen/logrus"
	"github.com/songgao/water"
	"github.com/songgao/water/waterutil"
	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
	"github.com/wmnsk/go-pfcp/ie"
)

type FARAssociationDB struct {
	table map[uint64]map[uint32]*gtpv1.UPlaneConn
	mu    sync.Mutex
}

func NewFARAssociationDB() *FARAssociationDB {
	return &FARAssociationDB{
		table: make(map[uint64]map[uint32]*gtpv1.UPlaneConn),
		mu:    sync.Mutex{},
	}
}

func (db *FARAssociationDB) Add(seid uint64, farid uint32, uConn *gtpv1.UPlaneConn) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, ok := db.table[seid]; !ok {
		db.table[seid] = make(map[uint32]*gtpv1.UPlaneConn)
	}
	db.table[seid][farid] = uConn
}

func (db *FARAssociationDB) Get(seid uint64, farid uint32) *gtpv1.UPlaneConn {
	if ta, oka := db.table[seid]; oka {
		if tb, okb := ta[farid]; okb {
			return tb
		}
	}
	return nil
}

func ipPacketHandler(packet []byte, db *FARAssociationDB, tuniface *water.Interface, pfcpServer *pfcp_networking.PFCPEntityUP) error {
	logrus.Debug("Received IP packet on TUN interface")
	pfcpSession, err := pfcpSessionLookUp(false, 0, "", packet, pfcpServer)
	if err != nil {
		return err
	}
	defer pfcpSession.RUnlock()
	pdr, err := pfcpSessionPDRLookUp(pfcpSession, false, 0, "", packet)
	if err != nil {
		if logrus.IsLevelEnabled(logrus.TraceLevel) {
			var srcpdu net.IP
			var dstpdu net.IP
			if waterutil.IsIPv4(packet) {
				p := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default).NetworkLayer().(*layers.IPv4)
				srcpdu = p.SrcIP
				dstpdu = p.DstIP
				logrus.WithFields(logrus.Fields{"src": srcpdu.String(), "dst": dstpdu.String()}).Trace("Could not find PDR for IP packet on TUN interface")
			} else if waterutil.IsIPv6(packet) {
				p := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.Default).NetworkLayer().(*layers.IPv6)
				srcpdu = p.SrcIP
				dstpdu = p.DstIP
				logrus.WithFields(logrus.Fields{"src": srcpdu.String(), "dst": dstpdu.String()}).Trace("Could not find PDR for IP packet on TUN interface")
			} else {
				logrus.Trace("Could not find PDR for IP packet on TUN interface")
			}
		}
		return err
	}
	handleIncommingPacket(db, packet, false, pfcpSession, pdr, tuniface)
	return nil
}

func tpduHandler(iface string, c gtpv1.Conn, senderAddr net.Addr, msg message.Message, db *FARAssociationDB, tuniface *water.Interface, pfcpServer *pfcp_networking.PFCPEntityUP) error {
	logrus.WithFields(logrus.Fields{
		"sender":    senderAddr,
		"teid":      msg.TEID(),
		"interface": iface,
	}).Debug("GTP packet received from GTP-U Peer")
	packet := make([]byte, msg.MarshalLen())
	err := msg.MarshalTo(packet)
	if err != nil {
		logrus.WithError(err).Error("Could not marshal GTP packet")
		return err
	}
	pfcpSession, err := pfcpSessionLookUp(true, msg.TEID(), iface, packet, pfcpServer)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"teid":      msg.TEID(),
			"interface": iface,
		}).Error("Could not find Session for this GTP packet")
		return err
	}
	defer pfcpSession.RUnlock()
	pdr, err := pfcpSessionPDRLookUp(pfcpSession, true, msg.TEID(), iface, packet)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"teid":      msg.TEID(),
			"interface": iface,
		}).Error("Could not find PDR for this GTP packet")
		return err
	}
	logrus.WithFields(logrus.Fields{
		"pdr-id":    pdr.ID,
		"teid":      msg.TEID(),
		"interface": iface,
	}).Debug("Found PDR associated on this packet")
	handleIncommingPacket(db, packet, true, pfcpSession, pdr, tuniface)
	return nil
}

func handleOuterHeaderRemoval(packet []byte, isGTP bool, outerHeaderRemoval *ie.IE) (res []byte, headers []*message.ExtensionHeader, err error) {
	description, _ := outerHeaderRemoval.OuterHeaderRemovalDescription()
	switch description {
	case 2:
		fallthrough // UDP/IPv4
	case 3:
		fallthrough // UDP/IPv6
	case 4:
		fallthrough // IPv4
	case 5:
		fallthrough // IPv6
	case 7:
		fallthrough //VLAN S-TAG
	case 8: //S-TAG and C-TAG
		return nil, nil, fmt.Errorf("Could not handle outer header removal with description field set to : %d", description)
	case 0:
		fallthrough // GTP-U/UDP/IPv4
	case 1:
		fallthrough // GTP-U/UDP/IPv6
	case 6:
		fallthrough // GTP-U/UDP/IP
	default: // For future use. Shall not be sent. If received, shall be interpreted as the value "1".
		// TODO: when 9 to 255, send and response with cause Mandatory IE incorrect: Offending IE type outerHeaderRemoval
		// note: this should be done directly into go-pfcp-networking
		if !isGTP {
			return nil, nil, fmt.Errorf("Could not handle outer header removal of non-GTP packet")
		}
		var h message.Header
		err := h.UnmarshalBinary(packet)
		if err != nil {
			return nil, nil, err
		}
		packet = h.Payload
		// Generate list of ExtensionHeaders to forward
		var headers_tmp []*message.ExtensionHeader
		for _, eh := range h.ExtensionHeaders {
			switch eh.Type {
			case message.ExtHeaderTypePDUSessionContainer:
				deletion, _ := outerHeaderRemoval.GTPUExtensionHeaderDeletion()
				if (deletion & 0x01) != 1 {
					headers_tmp = append(headers_tmp, message.NewExtensionHeader(eh.Type, eh.Content, message.ExtHeaderTypeNoMoreExtensionHeaders))
				}
			default:
				switch eh.Type & 0xC0 {
				case 0x00: // comprehension of this header is not required
					// an intermediate node shall forward it to any receiver endpoint
					headers_tmp = append(headers_tmp, message.NewExtensionHeader(eh.Type, eh.Content, message.ExtHeaderTypeNoMoreExtensionHeaders))
				case 0x40: // comprehension of this header is not required;
					// an intermediate node shall discard the extension header content and not forward it to any receiver endpoint
					continue
				case 0x80: // comprehension of this header is required by the endpoint receiver but not by an intermediate node;
					// an intermediate node shall forward the whole field to the endpoint receiver
					headers_tmp = append(headers_tmp, message.NewExtensionHeader(eh.Type, eh.Content, message.ExtHeaderTypeNoMoreExtensionHeaders))
				// TODO: implement comprehension of this type of headers
				case 0xC0: // comprehension of this header type is required by recipient (either endpoint receiver or intermediate node)
					// TODO: implement comprehension of this type of headers
					headers_tmp = append(headers_tmp, message.NewExtensionHeader(eh.Type, eh.Content, message.ExtHeaderTypeNoMoreExtensionHeaders))
				}
			}
		}
		// Set NextExtensionHeader
		if len(headers_tmp) > 1 {
			for i, eh := range headers_tmp[:(len(headers_tmp) - 2)] {
				headers = append(headers, message.NewExtensionHeader(eh.Type, eh.Content, headers_tmp[i+1].Type))
			}
		}
		if len(headers_tmp) > 0 {
			headers = append(headers, headers_tmp[len(headers_tmp)-1])
		}
		return packet, headers, nil
	}
	return packet, nil, nil
}

func handleIncommingPacket(db *FARAssociationDB, packet []byte, isGTP bool, session api.PFCPSessionInterface, pdr api.PDRInterface, tuniface *water.Interface) error {
	if logrus.IsLevelEnabled(logrus.TraceLevel) {
		pdrid, err := pdr.ID()
		if err == nil {
			logrus.WithFields(logrus.Fields{"pdr-id": pdrid}).Trace("Start handling of packet")
		} else {
			logrus.Trace("Bad PDRID")
		}
	}
	// Remove outer header if requested, and store GTP headers
	var gtpHeaders []*message.ExtensionHeader
	var err error
	ohr := pdr.OuterHeaderRemoval()

	if ohr != nil {
		packet, gtpHeaders, err = handleOuterHeaderRemoval(packet, isGTP, ohr)
		if err != nil {
			return err
		}
		if (packet[0]&0xF0 != 0x40) && (packet[0]&0xF0 != 0x60) {
			logrus.Warn("Non IP PDU detected")
		}
	}
	if len(packet) == 0 {
		return fmt.Errorf("Incomming packet of len 0")
	}

	// TODO: apply instruction of associated MARs, QERs, URRs, etc.

	farid, err := pdr.FARID()
	if err != nil {
		return err
	}
	far, err := session.GetFAR(farid)
	if err != nil {
		logrus.WithFields(logrus.Fields{"pdr-id": pdr.ID}).WithError(err).Error("Could not find FAR associated with this PDR")
		return err
	}
	applyAction := far.ApplyAction()
	if applyAction != nil {
		switch {
		case applyAction.HasDROP():
			return nil
		case applyAction.HasFORW():
			break // forwarding
		default:
			logrus.WithFields(logrus.Fields{"apply-action": applyAction, "far-id": farid}).Error("This Action is not implemented yet")
		}
	} else {
		logrus.WithFields(logrus.Fields{"far-id": farid}).Error("Missing forward action for this FAR")
	}

	fp, err := far.ForwardingParameters()
	if err != nil {
		return fmt.Errorf("Apply action is has FORW, but there is no ForwardingParameters")
	}
	ohcfields, _ := fp.OuterHeaderCreation()

	if ohcfields != nil {
		// XXX: No method in go-pfcp to convert OuterHeaderCreationFields directly to ie.IE
		ohcb, _ := ohcfields.Marshal()
		ohc := ie.New(ie.OuterHeaderCreation, ohcb)

		var ipAddress string
		switch {
		case ohc.HasIPv6():
			ipAddress = ohcfields.IPv6Address.String()
		case ohc.HasIPv4():
			ipAddress = ohcfields.IPv4Address.String()
		default:
			ipAddress = ""
		}
		switch {
		case ohc.HasTEID(): // Outer Header Creation
			// forward over GTP/UDP/IP
			gpdu := message.NewHeaderWithExtensionHeaders(0x30, message.MsgTypeTPDU, ohcfields.TEID, 0, packet, gtpHeaders...)
			if err != nil {
				return err
			}
			tlm, err := fp.TransportLevelMarking()
			if err == nil {
				return forwardGTP(gpdu, ipAddress, int(tlm>>8), session, farid, db)
			} else {
				return forwardGTP(gpdu, ipAddress, 0, session, farid, db)
			}
		case ohc.HasPortNumber():
			// forward over UDP/IP
			port := ohcfields.PortNumber
			var udpaddr string
			if strings.Count(ipAddress, ":") > 0 {
				udpaddr = fmt.Sprintf("[%s]:%s", ipAddress, port)
			} else {
				udpaddr = fmt.Sprintf("%s:%s", ipAddress, port)
			}
			raddr, err := net.ResolveUDPAddr("udp", udpaddr)
			if err != nil {
				return err
			}
			udpConn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				return err
			}
			defer udpConn.Close()
			udpConn.Write(packet)
		case ohc.HasIPv4() || ohc.HasIPv6():
			// forward over IP
			raddr, err := net.ResolveIPAddr("ip", ipAddress)
			if err != nil {
				return err
			}
			ipConn, err := net.DialIP("ip", nil, raddr)
			if err != nil {
				return err
			}
			defer ipConn.Close()
			ipConn.Write(packet)
		default:
			return fmt.Errorf("Unsupported option in Outer Header Creation Description")
		}
	} else {
		// forward using TUN interface
		if logrus.IsLevelEnabled(logrus.TraceLevel) {
			var srcpdu net.IP
			var dstpdu net.IP
			if waterutil.IsIPv4(packet) {
				p := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default).NetworkLayer().(*layers.IPv4)
				srcpdu = p.SrcIP
				dstpdu = p.DstIP
				logrus.WithFields(logrus.Fields{
					"src": srcpdu.String(),
					"dst": dstpdu.String(),
				}).Trace("Forwarding IP packet to TUN interface")
			} else if waterutil.IsIPv6(packet) {
				p := gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.Default).NetworkLayer().(*layers.IPv6)
				srcpdu = p.SrcIP
				dstpdu = p.DstIP
				logrus.WithFields(logrus.Fields{
					"src": srcpdu.String(),
					"dst": dstpdu.String(),
				}).Trace("Forwarding IP packet to TUN interface")
			} else {
				logrus.Trace("Forwarding IP packet to TUN interface, but could not find PDR for this IP packet")
			}
		}
		tuniface.Write(packet)
	}
	return nil

}

func forwardGTP(gpdu *message.Header, ipAddress string, dscpecn int, session api.PFCPSessionInterface, farid uint32, db *FARAssociationDB) error {
	if ipAddress == "" {
		return fmt.Errorf("IP Address for GTP Forwarding is empty")
	}
	var udpaddr string
	if strings.Count(ipAddress, ":") > 0 {
		udpaddr = fmt.Sprintf("[%s]:%s", ipAddress, constants.GTPU_PORT)
	} else {
		udpaddr = fmt.Sprintf("%s:%s", ipAddress, constants.GTPU_PORT)
	}
	raddr, err := net.ResolveUDPAddr("udp", udpaddr)
	if err != nil {
		logrus.WithError(err).Error("Error while resolving UDP address of GTP-U Peer")
		return err
	}
	// Check Uconn exists for this FAR
	seid, err := session.LocalSEID()
	if err != nil {
		return err
	}
	uConn := db.Get(seid, farid)
	if uConn == nil {
		// Open new uConn
		// TS 129 281 V16.2.0, section 4.4.2.0:
		// For the GTP-U messages described below (other than the Echo Response message, see clause 4.4.2.2), the UDP Source
		// Port or the Flow Label field (see IETF RFC 6437 [37]) should be set dynamically by the sending GTP-U entity to help
		// balancing the load in the transport network.
		c, err := net.Dial("udp", udpaddr)
		if err != nil {
			return err
		}
		c.Close()
		laddr := c.LocalAddr().(*net.UDPAddr)
		ch := make(chan bool)
		go func(ch chan bool) error {
			ctx, cancel := context.WithCancel(context.Background()) // FIXME: use context
			defer cancel()
			uConn, err = gtpv1.DialUPlane(ctx, laddr, raddr)
			if err != nil {
				logrus.WithError(err).Error("Dial failure")
				return err
			}
			defer uConn.Close()
			db.Add(seid, farid, uConn)
			close(ch)
			for {
				select {} // FIXME: use context
			}
		}(ch)
		_ = <-ch
	}
	if b, err := gpdu.Marshal(); err == nil {
		logrus.WithFields(logrus.Fields{"remote-addr": raddr, "teid": gpdu.TEID}).Debug("Forwarding gpdu")
		uConn.WriteToWithDSCPECN(b, raddr, dscpecn)
	}
	return err
}

func checkPFCPSession(session api.PFCPSessionInterface, isGTP bool, teid uint32, iface string, pdu []byte) (bool, bool, error) {
	isMatching := false
	isWilcard := false
	session.RLock()
	defer func() {
		if !isMatching {
			session.RUnlock()
		}
	}()

	// no need to use sorted PDRs when identifying sessions
	err := session.ForeachUnsortedPDR(func(pdr api.PDRInterface) error {
		pdicontent, err := pdr.PDI()
		if err != nil {
			return err
		}
		pdi := ie.NewPDI(pdicontent...)
		if isPDIMatching(isGTP, pdi, teid, iface, pdu) {
			isMatching = true
			if isPDIAllWilcard(pdi) {
				isWilcard = true
			}
		}
		return nil
	})
	if err != nil {
		return false, false, err
	}
	return isMatching, isWilcard, nil
}
func pfcpSessionLookUp(isGTP bool, teid uint32, iface string, pdu []byte, pfcpServer *pfcp_networking.PFCPEntityUP) (session api.PFCPSessionInterface, err error) {
	// On receipt of a user plane packet, the UP function shall perform a lookup of the provisioned PDRs and:
	// - identify first the PFCP session to which the packet corresponds; and
	// - find the first PDR matching the incoming packet, among all the PDRs provisioned for this PFCP session, starting
	//   with the PDRs with the highest precedence and continuing then with PDRs in decreasing order of precedence.
	//   Only the highest precedence PDR matching the packet shall be selected, i.e. the UP function shall stop the PDRs
	//   lookup once a matching PDR is found.

	// Different PDRs of different PFCP sessions, not including the Packet Replication and Detection Carry-On
	// Information IE, shall not overlap, i.e. there shall be at least one PDR in each PFCP session which differs by at
	// least one different (and not wildcarded) match field in their PDI, such that any incoming user plane packet may
	// only match PDRs of a single PFCP session.

	// As an exception to the previous principle, the CP function may provision a PDR with all match fields wildcarded
	// (i.e. all match fields omitted in the PDI) in a separate PFCP session, to control how the UP function shall process
	// packets unmatched by any PDRs of any other PFCP session. The CP function may provision the UP function to
	// send these packets to the CP function or to drop them. The UP function shall grant the lowest precedence to this
	// PDR.
	sessions := pfcpServer.GetPFCPSessions()
	var wilcard api.PFCPSessionInterface
	for _, session := range sessions {
		isMatching, isWilcard, err := checkPFCPSession(session, isGTP, teid, iface, pdu)
		if err != nil {
			return nil, err
		}
		if isMatching {
			if isWilcard {
				wilcard = session
			} else {
				return session, nil
			}
		}
	}
	if wilcard != nil {
		return wilcard, nil
	}
	return nil, fmt.Errorf("Cannot find PFCP Session for this PDU")
}
func pfcpSessionPDRLookUp(session api.PFCPSessionInterface, isGTP bool, teid uint32, iface string, pdu []byte) (pdr api.PDRInterface, err error) {
	for _, pdrid := range session.GetSortedPDRIDs() {
		pdr, err := session.GetPDR(pdrid)
		if err != nil {
			return nil, err
		}
		pdicontent, err := pdr.PDI()
		if err != nil {
			return nil, err
		}
		pdi := ie.NewPDI(pdicontent...)
		if isPDIMatching(isGTP, pdi, teid, iface, pdu) {
			return pdr, nil
		}
	}
	return nil, fmt.Errorf("Could not find PDR for TEID %d", teid)
}

func isPDIAllWilcard(pdi *ie.IE) bool {
	fteid, _ := pdi.FTEID()
	sdffilter, _ := pdi.SDFFilter()
	ueipaddress, _ := pdi.UEIPAddress()
	if (fteid != nil) || (sdffilter != nil) || (ueipaddress != nil) {
		return false
	}
	return true
}

func isPDIMatching(isGTP bool, pdi *ie.IE, teid uint32, iface string, packet []byte) (res bool) {
	fteid, _ := pdi.FTEID()
	if fteid != nil {
		if !isGTP {
			return false
		} else if !((fteid.TEID == teid) && ((fteid.HasIPv4() && fteid.IPv4Address.Equal(net.ParseIP(iface))) || (fteid.HasIPv6() && fteid.IPv6Address.Equal(net.ParseIP(iface))))) {
			return false
		}
	} else if isGTP {
		return false
	}
	SDFFilter, _ := pdi.SDFFilter()
	UEIPAddress, _ := pdi.UEIPAddress()
	if (SDFFilter != nil) || (UEIPAddress != nil) {
		if isGTP {
			// get ip packet to apply filters
			var h message.Header
			err := h.UnmarshalBinary(packet)
			if err != nil {
				return false
			}
			packet = h.Payload
		}
		var err error

		SourceInterface, _ := pdi.SourceInterface()
		if UEIPAddress != nil {
			res, err = checkUEIPAddress(UEIPAddress, SourceInterface, packet)
			if (err != nil) || !res {
				return false
			}
		}
		if SDFFilter != nil {
			res, err = checkIPFilterRule(SDFFilter.FlowDescription, SourceInterface, packet)
			if (err != nil) || !res {
				return false
			}
		}
	}
	return true
}

func checkUEIPAddress(ueipaddress *ie.UEIPAddressFields, sourceInterface uint8, pdu []byte) (res bool, err error) {
	var srcpdu net.IP
	var dstpdu net.IP
	ueIpAddressIE := ie.NewUEIPAddress(ueipaddress.Flags, ueipaddress.IPv4Address.String(), ueipaddress.IPv6Address.String(), ueipaddress.IPv6PrefixDelegationBits, ueipaddress.IPv6PrefixLength)
	if waterutil.IsIPv4(pdu) {
		p := gopacket.NewPacket(pdu, layers.LayerTypeIPv4, gopacket.Default).NetworkLayer().(*layers.IPv4)
		srcpdu = p.SrcIP
		dstpdu = p.DstIP
	} else if waterutil.IsIPv6(pdu) {
		p := gopacket.NewPacket(pdu, layers.LayerTypeIPv6, gopacket.Default).NetworkLayer().(*layers.IPv6)
		srcpdu = p.SrcIP
		dstpdu = p.DstIP
	} else {
		return false, fmt.Errorf("PDU is not IPv4 or IPv6")
	}
	if ueipaddress == nil {
		return false, fmt.Errorf("Invalid UE IP Address")
	}
	if sourceInterface == ie.SrcInterfaceAccess {
		// check ip src field
		if ueIpAddressIE.HasIPv4() && ueipaddress.IPv4Address.Equal(srcpdu) {
			return true, nil
		}
		if ueIpAddressIE.HasIPv6() && ueipaddress.IPv6Address.Equal(srcpdu) {
			return true, nil
		}
	} else {
		// check ip dst field
		if ueIpAddressIE.HasIPv4() && ueipaddress.IPv4Address.Equal(dstpdu) {
			return true, nil
		}
		if ueIpAddressIE.HasIPv6() && ueipaddress.IPv6Address.Equal(dstpdu) {
			return true, nil
		}
	}
	return false, nil
}

func checkIPFilterRule(rule string, sourceInterface uint8, pdu []byte) (res bool, err error) {
	if sourceInterface != ie.SrcInterfaceAccess {
		return false, fmt.Errorf("IP Filter Rule is only implemented for when source interface is ACCESS")
	}
	// IP Filter rule is specified in clause 5.4.2 of 3GPP TS 29.212
	r := strings.Split(rule, " ")
	if r[3] != "from" || (r[5] != "to" && r[6] != "to") {
		return false, fmt.Errorf("Malformed IP Filter Rule")
	}
	action := r[0]
	dir := r[1]
	proto := r[2]
	src := r[4]
	var dst string
	srcPorts := ""
	dstPorts := ""
	optionsList := map[string]struct{}{"frag": {}, "ipoptions": {}, "tcpoptions": {}, "established": {}, "setup": {}, "tcpflags": {}, "icmptypes": {}}
	if r[5] != "to" {
		srcPorts = r[5]
		dst = r[7]
		if len(r) > 8 {
			if _, ok := optionsList[r[8]]; ok {
				return false, fmt.Errorf("IP Filter Rule shall not use options")
			} else {
				dstPorts = r[8]
			}
		}

	} else {
		dst = r[6]
		if len(r) > 7 {
			if _, ok := optionsList[r[7]]; ok {
				return false, fmt.Errorf("IP Filter Rule shall not use options")
			} else {
				dstPorts = r[7]
			}
		}
	}
	if action != "permit" {
		return false, fmt.Errorf("IP Filter Rule action shall be keyword 'permit'")
	}
	if dir != "out" {
		return false, fmt.Errorf("IP Filter Rule direction shall be keyword 'out'")
	}
	if proto != "ip" {
		return false, fmt.Errorf("IP Filter Rule protocol is only implemented with value 'ip'")
	}
	if strings.HasPrefix(src, "!") || strings.HasPrefix(dst, "!") {
		return false, fmt.Errorf("IP Filter Rule shall not use the invert modifier '!'")
	}
	if srcPorts != "" {
		return false, fmt.Errorf("IP Filter Rule with ports in source is not implemented")
	}
	if dstPorts != "" {
		return false, fmt.Errorf("IP Filter Rule with ports in destination is not implemented")
	}
	var srcpdu net.IP
	var dstpdu net.IP
	if waterutil.IsIPv4(pdu) {
		p := gopacket.NewPacket(pdu, layers.LayerTypeIPv4, gopacket.Default).NetworkLayer().(*layers.IPv4)
		srcpdu = p.SrcIP
		dstpdu = p.DstIP
	} else if waterutil.IsIPv6(pdu) {
		p := gopacket.NewPacket(pdu, layers.LayerTypeIPv6, gopacket.Default).NetworkLayer().(*layers.IPv6)
		srcpdu = p.SrcIP
		dstpdu = p.DstIP
	} else {
		return false, fmt.Errorf("PDU is not IPv4 or IPv6")
	}
	if src != "any" {
		if strings.Contains(src, "/") {
			_, srcNet, err := net.ParseCIDR(src)
			if err != nil {
				logrus.WithFields(logrus.Fields{"cidr": src}).WithError(err).Debug("Could not parse cidr")
				return false, err
			}
			if !srcNet.Contains(srcpdu) {
				return false, nil
			}
		} else {
			srcIp := net.ParseIP(src)
			if srcIp == nil {
				return false, fmt.Errorf("Invalid IP address in SDF Flow Description for source")
			}
			if !(srcIp.Equal(srcpdu)) {
				return false, nil
			}
		}
	}
	if dst != "any" {
		if strings.Contains(dst, "/") {
			_, dstNet, err := net.ParseCIDR(dst)
			if err != nil {
				logrus.WithFields(logrus.Fields{"cidr": dst}).WithError(err).Debug("Could not parse cidr")
				return false, err
			}
			if !dstNet.Contains(dstpdu) {
				return false, nil
			}
		} else {
			dstIp := net.ParseIP(dst)
			if dstIp == nil {
				return false, fmt.Errorf("Invalid IP address in SDF Flow Description for destination")
			}
			if !dstIp.Equal(dstpdu) {
				return false, nil
			}
		}
	}
	return true, nil
}
