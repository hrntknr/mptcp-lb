package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
)

const obj = "mptcp_lb_kern.o"

func main() {
	if err := cmd(os.Args[1:]); err != nil {
		fmt.Println(err.Error())
		help()
		os.Exit(1)
	}
}

type servicesKey struct {
	dport uint16
}

type servicesValue struct {
	upstream *upstream
}

type upstream struct {
}

func cmd(params []string) error {
	if len(params) < 1 {
		return errors.New("invalid argument length")
	}
	switch params[0] {
	case "start":
		if len(params) != 2 {
			return errors.New("invalid argument length")
		}
		fmt.Printf("Attaching the xdp program to %s...\n", params[1])

		coll, err := ebpf.LoadCollection(obj)
		if err != nil {
			return err
		}

		mptcpLB := coll.Programs["mptcp_lb"]
		if mptcpLB == nil {
			return fmt.Errorf("eBPF prog 'mptcp_lb' not found")
		}

		services := coll.Maps["services"]
		if services == nil {
			return fmt.Errorf("eBPF map 'services' not found")
		}

		link, err := netlink.LinkByName(params[1])
		if err != nil {
			return err
		}

		if err := netlink.LinkSetXdpFd(link, mptcpLB.FD()); err != nil {
			return err
		}

		defer (func() {
			if err := netlink.LinkSetXdpFd(link, -1); err != nil {
				fmt.Println(err.Error())
			}
		})()

		quit := make(chan os.Signal)
		signal.Notify(quit, os.Interrupt)
		<-quit

		return nil
	}
	return errors.New("invalid command")
}

func help() {
	// TODO:
}
