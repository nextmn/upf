package upf

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

func pfcpHearthbeatHandler(ipAddress string, ch chan bool) error {
	// A CP function or UP function shall be prepared to receive a Heartbeat Request at any time (even from unknown peers)
	// and it shall reply with a Heartbeat Response.
	recoveryTimeStamp := ie.NewRecoveryTimeStamp(time.Now())
	pfcpPort := "8805"
	var udpaddr string
	if strings.Count(ipAddress, ":") > 0 {
		udpaddr = fmt.Sprintf("[%s]:%s", ipAddress, pfcpPort)
	} else {
		udpaddr = fmt.Sprintf("%s:%s", ipAddress, pfcpPort)
	}
	laddr, err := net.ResolveUDPAddr("udp", udpaddr)
	if err != nil {
		log.Fatal(err)
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
		return err
	}

	log.Println("PFCP Heartbeat handler started on", udpaddr)
	buf := make([]byte, 1500)
	close(ch)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Fatal(err)

		}
		msg, err := message.Parse(buf[:n])
		if err != nil {
			log.Println("Ignored undecodable pfcp message")
			continue
		}
		hbreq, ok := msg.(*message.HeartbeatRequest)
		if !ok {
			log.Printf("got unespected message %s, from: %s\n", msg.MessageTypeName(), addr)
			continue
		}
		ts, err := hbreq.RecoveryTimeStamp.RecoveryTimeStamp()
		if err != nil {
			log.Printf("got Heartbeat Request with invalid TS: %s, from: %s\n", err, addr)
			continue
		} else {
			log.Printf("got Heartbeat Request with TS: %s, from: %s\n", ts, addr)
		}

		hbres, err := message.NewHeartbeatResponse(msg.Sequence(), recoveryTimeStamp).Marshal()
		if err != nil {
			log.Fatal(err)
		}

		if _, err := conn.WriteTo(hbres, addr); err != nil {
			log.Fatal(err)
		}
		log.Printf("sent Heartbeat Response to: %s\n", addr)
	}
	return nil
}
