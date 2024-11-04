package main

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("host 127.0.0.1"); err != nil {
		panic(err)
	} else {

		// Источник пакетов
		packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

		for packet := range packetSource.Packets() {
			handlePacket(packet)
			fmt.Println()
		}
	}
}

// Обработка пакетов

func handlePacket(packet gopacket.Packet) {

	//Получение уровня IP (источник, получатель)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {

		ip, _ := ipLayer.(*layers.IPv4)

		fmt.Printf("IP-адрес отправителя: %s\n"+"IP-адрес получателя: %s\n", ip.SrcIP, ip.DstIP)

	}

	// Получение уровня TCP из пакета
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		fmt.Println("Это TCP пакет")

		// Получение TCP-данных из этого уровня
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("Из порта-отправителя %d в порт-получатель %d\n", tcp.SrcPort, tcp.DstPort)

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {

		fmt.Println("Это UDP пакет")

		// Получение UDP-данных из этого уровня
		udp, _ := udpLayer.(*layers.UDP)

		fmt.Printf("Из порта-отправителя %d в порт-получатель %d\n", udp.SrcPort, udp.DstPort)

	}
	fmt.Println("Полезная нагрузка", packet.ApplicationLayer().Payload())
}
