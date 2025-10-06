// Binary magna instantiates an OTG server, with accompanying gNMI server, that can be
// extended to support traffic generation functions described by OTG.
//
// The lwotg package is used as a base which provides simple interface configuration only,
// for new functions that are required additional handlers can be loaded into the server.
// Particularly:
//   - New ConfigHandlers can be added to cover more OTG functionality.
//   - New FlowHandlers can be added to add support for generating more flows. The
//     implementation included here supports only basic MPLS traffic generation.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/open-traffic-generator/snappi/gosnappi/otg"
	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/magna/flows/ip"
	"github.com/openconfig/magna/flows/mpls"
	"github.com/openconfig/magna/lwotg"
	"github.com/openconfig/magna/lwotgtelem"
	"github.com/openconfig/magna/telemetry/arp"
	ping "github.com/prometheus-community/pro-bing"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
	"k8s.io/klog/v2"
)

func main() {
	// Since we have a mix of glog and klog we have flags that overlap - and hence
	// need to override this.
	if flag.CommandLine.Lookup("log_dir") != nil {
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	}
	klog.InitFlags(nil)

	var (
		telemPort, port   string
		certFile, keyFile string
		targetName        string
	)

	flag.StringVar(&port, "port", os.Getenv("PORT"), "Port for OTG server.")
	flag.StringVar(&telemPort, "telemetry_port", os.Getenv("TELEMETRY_PORT"), "Port for gNMI server.")
	flag.StringVar(&certFile, "certfile", "", "Certificate file for gNMI.")
	flag.StringVar(&keyFile, "keyfile", "", "Key file for gNMI.")
	flag.StringVar(&targetName, "target", "ate", "Name for the gNMI target exposed.")
	flag.Parse()

	otgSrv := lwotg.New()
	telemSrv, err := lwotgtelem.New(context.Background(), targetName)
	if err != nil {
		klog.Exitf("cannot set up telemetry server, %v", err)
	}

	fh, task, err := mpls.New()
	if err != nil {
		klog.Exitf("cannot initialise MPLS flow handler, %v", err)
	}

	ipFH, ipTask, err := ip.New()
	if err != nil {
		klog.Exitf("cannot initialise IP flow handler, %v", err)
	}

	otgSrv.AddFlowHandlers(fh)
	otgSrv.AddFlowHandlers(ipFH)
	telemSrv.AddTask(task)
	telemSrv.AddTask(ipTask)

	hintCh := make(chan lwotg.Hint, 100)
	otgSrv.SetHintChannel(hintCh)
	otgSrv.SetProtocolHandler(gatewayPinger)
	telemSrv.SetHintChannel(context.Background(), hintCh)

	telemSrv.AddTask(arp.New(context.Background(), telemSrv.GetHints, time.Now().UnixNano))

	otgLis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		klog.Exitf("cannot listen on port %s, err: %v", port, err)
	}

	gnmiLis, err := net.Listen("tcp", fmt.Sprintf(":%s", telemPort))
	if err != nil {
		klog.Exitf("cannot listen on port %s, err: %v", telemPort, err)
	}

	otgS := grpc.NewServer(grpc.Creds(insecure.NewCredentials()))
	reflection.Register(otgS)
	otg.RegisterOpenapiServer(otgS, otgSrv)

	creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
	if err != nil {
		klog.Exitf("cannot create gNMI credentials, %v", err)
	}

	gnmiS := grpc.NewServer(grpc.Creds(creds))
	reflection.Register(gnmiS)
	gpb.RegisterGNMIServer(gnmiS, telemSrv.GNMIServer)

	klog.Infof("OTG listening at %s", otgLis.Addr())
	klog.Infof("gNMI listening at %s", gnmiLis.Addr())
	go otgS.Serve(otgLis)
	go gnmiS.Serve(gnmiLis)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	sig := <-sigs
	klog.Infof("Received signal %v", sig)
	os.Exit(1)
}

// gatewayPinger is a function that pings all gateway addresses when start protocols is called.
func gatewayPinger(cfg *otg.Config, _ otg.StateProtocolAll_State_Enum) error {
	gw := []string{}
	for _, d := range cfg.GetDevices() {
		for _, i := range d.GetEthernets() {
			for _, a4 := range i.GetIpv4Addresses() {
				gw = append(gw, a4.GetGateway())
			}
		}
	}
	klog.Infof("ping gateways %v", gw)

	for _, a := range gw {
		pinger, err := ping.NewPinger(a)
		if err != nil {
			return fmt.Errorf("cannot parse gateway address %s, %v", a, err)
		}
		pinger.SetPrivileged(true)
		pinger.Count = 1
		if err := pinger.Run(); err != nil {
			return fmt.Errorf("cannot ping address %s, %v", a, err)
		}
		klog.Infof("ping statistics, %v", pinger.Statistics())
	}
	return nil
}
