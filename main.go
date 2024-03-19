package main

import (
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/lixiang4u/network-view/handler"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGKILL)

	deviceList, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("[FindDeviceError]", err.Error())
		return
	}
	for _, device := range deviceList {
		log.Println(fmt.Sprintf("[device] name=%s, desc=%s", device.Name, device.Description))
		if device.Description == "Realtek Gaming 2.5GbE Family Controller" {
			go handler.HandlePacketsLive(device.Name, 1024, false, time.Second/2)
		}
	}

	select {
	case _sig := <-sig:
		log.Println(fmt.Sprintf("[stop] %v\n", _sig))
	}
}
