package upf

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

func ipPacketHandler(packet []byte) error {
	log.Println("Received IP packet on TUN interface")
	pfcpSession, err := getPFCPSessionIP(packet)
	if err != nil {
		log.Println("Could not find associated PFCP Session for IP packet on TUN interface")
		return err
	}
	pdr, err := findPDR(pfcpSession, false, 0, "")
	if err != nil {
		log.Println("Could not find PDR for IP packet on TUN interface")
		return err
	}
	handleIncommingPacket(packet, pfcpSession, pdr)
	return nil
}

func tpduHandler(iface string, c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
	log.Println("GTP packet received from GTP-U Peer", senderAddr, "with TEID", msg.TEID(), "on interface", iface)
	pfcpSession, err := getPFCPSessionGTP(msg)
	if err != nil {
		log.Println("Could not find associated PFCP Session for message")
		return err
	}
	pdr, err := findPDR(pfcpSession, true, msg.TEID(), iface)
	if err != nil {
		log.Println("Could not find PDR for GTP packet with TEID", msg.TEID(), "on interface", iface)
		return err
	}
	packet := make([]byte, 1500)
	msg.MarshalTo(packet)
	handleIncommingPacket(packet, pfcpSession, pdr)
	return nil
}

func handleOuterHeaderRemoval(packet []byte, outerHeaderRemovalIE *OuterHeaderRemoval) (res []byte, headers []*message.ExtensionHeader, err error) {
	switch outerHeaderRemovalIE.description {
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
		return nil, nil, fmt.Errorf("Could not handle outer header removal with description field set to : %d", outerHeaderRemovalIE.description)
	case 0:
		fallthrough // GTP-U/UDP/IPv4
	case 1:
		fallthrough // GTP-U/UDP/IPv6
	case 6:
		fallthrough // GTP-U/UDP/IP
	default: // For future use. Shall not be sent. If received, shall be interpreted as the value "1".
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
				if outerHeaderRemovalIE.extensionHeaderDeletion != 1 {
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

func handleIncommingPacket(packet []byte, session *PFCPSession, pdr *PDR) (err error) {
	// Remove outer header if requested, and store GTP headers
	var gtpHeaders []*message.ExtensionHeader
	if pdr.OuterHeaderRemoval != nil {
		packet, gtpHeaders, err = handleOuterHeaderRemoval(packet, pdr.OuterHeaderRemoval)
		if err != nil {
			return err
		}
	}

	// TODO: apply instruction of associated MARs, QERs, URRs, etc.

	far, err := getFAR(session.FARS, pdr)
	if err != nil {
		log.Println("Could not find FAR associated with PDR", pdr.ID)
	}
	if far.ForwardingParameters.OuterHeaderCreation != nil {
		// Apply TEID parameter and set back GTP Extension Headers
		gpdu := message.NewHeaderWithExtensionHeaders(0x30, message.MsgTypeTPDU, far.ForwardingParameters.OuterHeaderCreation.TEID, 0, packet, gtpHeaders...)
		if err != nil {
			return err
		}
		gtpuPort := "2152"
		var udpaddr string
		ipAddress := far.ForwardingParameters.OuterHeaderCreation.GTPUPeer
		if strings.Count(ipAddress, ":") > 0 {
			udpaddr = fmt.Sprintf("[%s]:%s", ipAddress, gtpuPort)
		} else {
			udpaddr = fmt.Sprintf("%s:%s", ipAddress, gtpuPort)
		}
		raddr, err := net.ResolveUDPAddr("udp", udpaddr)
		if err != nil {
			log.Println("Error while resolving UDP address of GTP-U Peer")
			return err
		}
		// Check Uconn exists for this FAR
		if far.ForwardingParameters.OuterHeaderCreation.uConn == nil {
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
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				uConn, err := gtpv1.DialUPlane(ctx, laddr, raddr)
				if err != nil {
					log.Println("Dial failure")
					return err
				}
				defer uConn.Close()
				far.ForwardingParameters.OuterHeaderCreation.uConn = uConn
				close(ch)
				for {
					select {}
				}
			}(ch)
			_ = <-ch
		}
		b, err := gpdu.Marshal()
		if err != nil {
			return err
		}
		log.Println("Forwarding gpdu to", raddr, gpdu.String())
		far.ForwardingParameters.OuterHeaderCreation.uConn.WriteTo(b, raddr)
	} else {
		// forward using TUN interface
		TUNInterface.Write(packet)
	}
	return nil

}

func findPDR(session *PFCPSession, isGTP bool, teid uint32, iface string) (pdr *PDR, err error) {
	// session.PDRS is already sorted
	for _, pdr := range session.PDRS {
		if isPDIMatching(isGTP, pdr.PDI, teid, iface) {
			return pdr, nil
		}
	}
	return nil, fmt.Errorf("Could not find PDR for TEID %d", teid)
}

func getFAR(FARs []*FAR, pdr *PDR) (far *FAR, err error) {
	for _, far := range FARs {
		if pdr.FARID == far.ID {
			return far, nil
		}
	}
	return nil, fmt.Errorf("Could not find FAR with id: %d", pdr.FARID)
}

func getPFCPSessionGTP(msg message.Message) (pfcpSession *PFCPSession, err error) {
	//TODO: case of individual PDU session mapped to a PFCP Session
	return Upf.PFCPSessions[0], nil
}

func getPFCPSessionIP(packet []byte) (pfcpSession *PFCPSession, err error) {
	//TODO: case of individual PDU session mapped to a PFCP Session
	return Upf.PFCPSessions[0], nil
}

func isPDIMatching(isGTP bool, pdi *PDI, teid uint32, iface string) bool {
	if isGTP {
		return (pdi.FTEID != nil) && (pdi.FTEID.TEID == teid) && (pdi.FTEID.IPAddress == iface)
	} else {
		return (pdi.FTEID == nil)
	}
}
