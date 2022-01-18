package upf

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/songgao/water"
	"github.com/wmnsk/go-gtp/gtpv1"
	"github.com/wmnsk/go-gtp/gtpv1/message"
)

var Upf *UpfConfig
var TUNInterface *water.Interface

func Run() error {
	err := createPFCPNode()
	if err != nil {
		return err
	}
	err = createTUNInterface()
	if err != nil {
		return err
	}
	err = createDLRoutes()
	if err != nil {
		return err
	}
	err = createGtpUProtocolEntities()
	if err != nil {
		return err
	}
	for {
		select {}
	}
	return nil
}

func createPFCPNode() error {
	log.Println("Creating PFCP sessions from config file")
	log.Println("Generating initial sort for PDRs of PFCP sessions")
	for _, session := range Upf.PFCPSessions {
		sort.Sort(PDRs(session.PDRS))
	}
	go func() error {
		for {
			select {}
		}
		// TODO: to add a real PFCP server, at each PDR added we need to sort PDRs of the current session
		return nil
	}()
	return nil
}

func createTUNInterface() error {
	err := createTun()
	if err != nil {
		return err
	}
	go func() error {

		for {
			packet := make([]byte, 1400)
			n, err := TUNInterface.Read(packet)
			if err != nil {
				return err
			}
			go ipPacketHandler(packet[:n])
		}
		return nil
	}()
	return nil
}

func createDLRoutes() error {
	if Upf.DNNList == nil {
		return nil
	}
	for _, ue := range Upf.DNNList {
		err := runIP("route", "add", ue.Cidr, "dev", TUNInterface.Name())
		if err != nil {
			log.Println("Cannot create Uplink route for", ue.Cidr)
			return err
		}
	}
	return nil
}

func createGtpUProtocolEntities() error {
	for _, v := range Upf.GTPUProtocolEntities {
		go createGtpUProtocolEntity(v)
	}
	return nil
}

func createGtpUProtocolEntity(ipAddress string) error {
	fmt.Println("Creating new GTP-U Protocol Entity")
	gtpuPort := "2152"
	var udpaddr string
	if strings.Count(ipAddress, ":") > 0 {
		udpaddr = fmt.Sprintf("[%s]:%s", ipAddress, gtpuPort)
	} else {
		udpaddr = fmt.Sprintf("%s:%s", ipAddress, gtpuPort)
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
		return tpduHandler(ipAddress, c, senderAddr, msg)
	})
	if err := uConn.ListenAndServe(ctx); err != nil {
		return err
	}

	return nil
}
func Exit() error {
	removeTun()
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

func runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
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

func runIP6Tables(args ...string) error {
	cmd := exec.Command("ip6tables", args...)
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
	err := runIP("link", "del", TUNInterface.Name())
	if nil != err {
		log.Println("Unable to delete interface ", TUNInterface.Name(), ":", err)
		return err
	}
	if Upf.SimulateRAN == nil {
		err = runIPTables("-D", "OUTPUT", "-o", TUNInterface.Name(), "-p", "icmp", "--icmp-type", "redirect", "-j", "DROP")
		if err != nil {
			log.Println("Error while removing iptable rule to drop icmp redirects")
		}
		err = runIP6Tables("-D", "OUTPUT", "-o", TUNInterface.Name(), "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP")
		if err != nil {
			log.Println("Error while removing iptable rule to drop icmpv6 redirects")
		}
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
	err = runIP("link", "set", "dev", iface.Name(), "mtu", "1400")
	if nil != err {
		log.Println("Unable to set MTU for", iface.Name())
		return err
	}
	err = runIP("link", "set", "dev", iface.Name(), "up")
	if nil != err {
		log.Println("Unable to set", iface.Name(), "up")
		return err
	}
	TUNInterface = iface

	if Upf.SimulateRAN != nil {
		log.Println("Simulating RAN with ip", Upf.SimulateRAN.Ran)
		err = runIP("addr", "add", Upf.SimulateRAN.Ran, "dev", iface.Name())
		if err != nil {
			return err
		}
	} else {
		err = runIPTables("-A", "OUTPUT", "-o", iface.Name(), "-p", "icmp", "--icmp-type", "redirect", "-j", "DROP")
		if err != nil {
			log.Println("Error while setting iptable rule to drop icmp redirects")
			return err
		}
		err = runIP6Tables("-A", "OUTPUT", "-o", iface.Name(), "-p", "icmpv6", "--icmpv6-type", "redirect", "-j", "DROP")
		if err != nil {
			log.Println("Error while setting iptable rule to drop icmpv6 redirects")
			return err
		}
	}
	return nil
}
