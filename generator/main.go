package main

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	buf := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	eth := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP{127, 0, 0, 1},
		DstIP:    net.IP{127, 0, 0, 1},
		Protocol: layers.IPProtocolUDP,
	}

	udp := layers.UDP{
		SrcPort: 62003,
		DstPort: 8080,
	}

	udp.SetNetworkLayerForChecksum(&ip)

	payload := []byte{'a', 'b', 'c', 'd', '\n'}

	err := gopacket.SerializeLayers(buf, options,
		&eth,
		&ip,
		&udp,
		gopacket.Payload(payload),
	)

	if err != nil {
		panic(err)
	}

	packetData := buf.Bytes()

	handle, err := pcap.OpenLive("eth0", 1500, false, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	err = handle.WritePacketData(packetData)
	if err != nil {
		panic(err)
	}
}
