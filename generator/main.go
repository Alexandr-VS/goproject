package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{},
		&layers.IPv4{
			SrcIP: net.IP{192, 168, 117, 147},
			DstIP: net.IP{192, 168, 117, 147},
		},
		&layers.TCP{},
		gopacket.Payload([]byte{1, 2, 3, 4}))
	packetData := buf.Bytes()

}
