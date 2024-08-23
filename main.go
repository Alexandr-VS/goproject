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
	} else if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		panic(err)
	} else {

		// Источник пакетов
		packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

		for packet := range packetSource.Packets() {
			handlePacket(packet)
		}
	}
}

// Обработка пакетов

func handlePacket(packet gopacket.Packet) {
	// Декодирование пакета
	//packet := gopacket.NewPacket(myPacketData, layers.LayerTypeEthernet, gopacket.Default)
	// Получение уровня TCP из пакета
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		fmt.Println("Это TCP пакет")

		// Получение TCP-данных из этого уровня
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("Из порта-отправителя %d в порт-получатель %d/n", tcp.SrcPort, tcp.DstPort)
	}
	for _, layer := range packet.Layers() {
		fmt.Println("Уровень пакета:", layer.LayerType())
	}
}
