package upf

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

var Upf *UpfConfig
var uConnAccess *gtpv1.UPlaneConn
var uConnCore *gtpv1.UPlaneConn

func PrintAddresses() error {
	fmt.Println("AccessAddress: ", Upf.AccessAddress)
	fmt.Println("CoreAddress: ", Upf.CoreAddress)
	return nil
}
func Run() (err error) {
	uConnAccess, err = CreateEndpoint(Upf.AccessAddress, Upf.AccessGtpInterface, Upf.AccessAction)
	if err != nil {
		return err
	}
	uConnCore, err = CreateEndpoint(Upf.CoreAddress, Upf.CoreGtpInterface, Upf.CoreAction)
	if err != nil {
		return err
	}
	for {
	}
	return nil
}

func TPDUHandler(addr string, c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
	fmt.Println("TEID received on addr", addr, ":", msg.TEID())
	return nil
}

func CreateEndpoint(address string, iface string, action string) (uConn *gtpv1.UPlaneConn, err error) {
	if action != "forward" {
		return nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accessAddress, err := net.ResolveUDPAddr("udp", address+gtpv1.GTPUPort)
	if err != nil {
		log.Println(err)
		return
	}
	uConn = gtpv1.NewUPlaneConn(accessAddress)
	if err != nil {
		fmt.Println("Error binding access-address")
		return
	}
	defer uConn.Close()
	if Upf.KernelRouting {
		if err = uConn.EnableKernelGTP(iface, gtpv1.RoleSGSN); err != nil {
			fmt.Println("Error enabling kernel gtp: ", err)
			fmt.Println("You must enable CAP_NET_ADMIN to run the program.")
			return
		}
	}
	if err = uConn.ListenAndServe(ctx); err != nil {
		fmt.Println("Error listen and serve")
		return
	}
	uConn.AddHandler(message.MsgTypeTPDU, func(c gtpv1.Conn, senderAddr net.Addr, msg message.Message) error {
		return TPDUHandler(address, c, senderAddr, msg)
	})
	return uConn, nil
}

func RemoveUconnLink(uConn *gtpv1.UPlaneConn) error {
	if !Upf.KernelRouting {
		return nil
	}
	if uConn == nil {
		return nil
	}
	if err := netlink.LinkDel(uConn.KernelGTP.Link); err != nil {
		return fmt.Errorf("Failed to remove link %s: %w", uConn.KernelGTP.Link.Name, err)
	}
	return nil

}
func Exit() error {
	RemoveUconnLink(uConnAccess)
	RemoveUconnLink(uConnCore)
	return nil
}
