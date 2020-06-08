package main

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/jessevdk/go-flags"
	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v2"
)

const obj = "kern/mptcp_lb_kern.o"

func main() {
	if err := cmd(os.Args[1:]); err != nil {
		fmt.Println(err.Error())
		help()
		os.Exit(1)
	}
}

type Config struct {
	Services []ServiceConfig `yaml:"services"`
}

type ServiceConfig struct {
	Port     uint16           `yaml:"port"`
	VIP      net.IP           `yaml:"vip"`
	AddrPool string           `yaml:"addr_pool"`
	Upstream []UpstreamConfig `yaml:"upstream"`
}

type UpstreamConfig struct {
	Addr net.IP `yaml:"addr"`
}

type servicesDst struct {
	addr net.IP
	port uint16
}

func (s *servicesDst) MarshalBinary() (data []byte, err error) {
	if len(s.addr) != 16 {
		return nil, fmt.Errorf("invalid vip: %s", s.addr)
	}
	buf := [18]byte{}
	for i := 0; i < 16; i++ {
		buf[i] = s.addr[i]
	}
	// TODO: ebpf endian check
	binary.LittleEndian.PutUint16(buf[16:18], s.port)
	return buf[:], nil
}

type upstream struct {
	addr net.IP
	port uint16
}

func (u *upstream) MarshalBinary() (data []byte, err error) {
	if len(u.addr) != 16 {
		return nil, fmt.Errorf("invalid vip: %s", u.addr)
	}
	return u.addr, nil
}

var opts struct {
	Iface  string `long:"iface" description:"interface" default:"eth0"`
	Config string `long:"config" description:"config file path" default:"config.yml"`
}

func cmd(params []string) error {
	if len(params) < 1 {
		return errors.New("invalid argument length")
	}
	switch params[0] {
	case "start":
		if len(params) < 2 {
			return errors.New("invalid argument length")
		}

		_, err := flags.ParseArgs(&opts, params[1:])
		if err != nil {
			return err
		}

		buf, err := ioutil.ReadFile(opts.Config)
		if err != nil {
			return err
		}

		conf := Config{}
		if err := yaml.Unmarshal([]byte(buf), &conf); err != nil {
			return err
		}

		fmt.Printf("Attaching the xdp program to %s...\n", opts.Iface)
		if err := startLB(conf); err != nil {
			return err
		}

		return err
	}
	return errors.New("invalid command")
}

func help() {
	// TODO:
}

func startLB(conf Config) error {
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		return err
	}
	spec.Maps["services"] = &ebpf.MapSpec{
		Type:       ebpf.HashOfMaps,
		KeySize:    18,
		MaxEntries: 64,
		InnerMap: &ebpf.MapSpec{
			Type:       ebpf.Array,
			KeySize:    4,
			ValueSize:  16,
			MaxEntries: 64,
		},
	}
	coll, err := ebpf.NewCollection(spec)
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

	for _, serviceConf := range conf.Services {
		inner, err := ebpf.NewMap(spec.Maps["services"].InnerMap)
		if err != nil {
			return err
		}
		for i, u := range serviceConf.Upstream {
			var value encoding.BinaryMarshaler = &upstream{
				addr: u.Addr,
			}
			inner.Put(uint32(i), value)
		}
		var key encoding.BinaryMarshaler = &servicesDst{
			addr: serviceConf.VIP,
			port: serviceConf.Port,
		}

		if err := services.Put(key, inner); err != nil {
			return err
		}
	}

	link, err := netlink.LinkByName(opts.Iface)
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
