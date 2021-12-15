package upf

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"

	"github.com/songgao/water"
	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

var Upf *UpfConfig
var ipInterface *water.Interface

func Run() error {
	createIPEndpoints()
	createGtpUProtocolEntities()
	for {
	}
	return nil
}

func createIPEndpoints() error {
	if len(Upf.IPEndpoints) > 0 {
		err := createIPEndpoint(Upf.IPEndpoints[0])
		if err != nil {
			return err
		}

	}
	return nil
}

func createIPEndpoint(endpoint *IPEndpoint) error {
	err := createTun()
	if err != nil {
		return err
	}
	go func() error {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		// TS 129 281 V16.2.0, section 4.4.2.0:
		// For the GTP-U messages described below (other than the Echo Response message, see clause 4.4.2.2), the UDP Source
		// Port or the Flow Label field (see IETF RFC 6437 [37]) should be set dynamically by the sending GTP-U entity to help
		// balancing the load in the transport network.
		laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", endpoint.LocalAddr))
		if err != nil {
			log.Println("Error while resolving local UPD address for client", err)
			return err
		}
		raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", endpoint.GTPUPeer, "2152"))
		if err != nil {
			log.Println("Error while resolving UDP address of GTP-U Peer")
			return err
		}
		uConn, err := gtpv1.DialUPlane(ctx, laddr, raddr)
		defer uConn.Close()
		for {
			packet := make([]byte, 1400)
			n, err := ipInterface.Read(packet)
			if err != nil {
				return err
			}
			if _, err := uConn.WriteToGTP(Upf.IPEndpoints[0].TEID, packet[:n], raddr); err != nil {
				log.Println("Error while sending GTP packet")
				return err
			}
		}
		return nil
	}()
	return nil
}

func createGtpUProtocolEntities() error {
	for _, v := range Upf.GTPUProtocolEntities {
		go createGtpUProtocolEntity(v)
	}
	return nil
}

func tpduHandler(addr string, c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
	fmt.Println("GTP packet received from GTP-U Peer", senderAddr, "with TEID", msg.TEID(), "on interface", addr)
	return nil
}

func createGtpUProtocolEntity(entity *GTPUProtocolEntity) error {
	fmt.Println("Creating new GTP-U Protocol Entity")
	laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%s", entity.IpAddress, "2152"))
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
		return tpduHandler(entity.IpAddress, c, senderAddr, msg)
	})
	if err := uConn.ListenAndServe(ctx); err != nil {
		return err
	}

	return nil
}
func Exit() error {
	if len(Upf.IPEndpoints) > 0 {
		removeTun()
	}
	return nil
}

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Stdin = os.Stdin
	err := cmd.Run()
	if nil != err {
		errLog := fmt.Sprintf("Error running %s: %s", cmd.Args[0], err)
		log.Println(errLog)
		return err
	}
	return nil
}

func removeTun() error {
	err := runIP("link", "del", ipInterface.Name())
	if nil != err {
		log.Println("Unable to delete interface ", ipInterface.Name(), ":", err)
		return err
	}
	return nil
}

func createTun() error {
	config := water.Config{
		DeviceType: water.TUN,
	}
	iface, err := water.New(config)
	if nil != err {
		log.Println("Unable to allocate TUN interface:", err)
		return err
	}
	runIP("link", "set", "dev", iface.Name(), "mtu", "1400")
	if nil != err {
		log.Println("Unable to set MTU for", iface.Name())
		return err
	}
	runIP("link", "set", "dev", iface.Name(), "up")
	if nil != err {
		log.Println("Unable to set", iface.Name(), "up")
		return err
	}

	ipInterface = iface
	return nil
}
