package main

import (
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	handle, err := pcap.OpenLive("eth0", 1500, false, pcap.BlockForever)

	if err != nil {
		panic(err)
	}

	defer handle.Close()

	for {
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

		n := rand.New(rand.NewSource(time.Now().UnixNano())).Intn(256)

		payload := make([]byte, n)

		r := rand.New(rand.NewSource(time.Now().UnixNano()))

		for i := range payload {
			payload[i] = byte(r.Intn(256))
		}

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

		err = handle.WritePacketData(packetData)
		if err != nil {
			panic(err)
		}

		time.Sleep(time.Millisecond * time.Duration(r.Intn(1000)))
	}
}
