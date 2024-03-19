package handler

import (
	"github.com/shirou/gopsutil/net"
	"log"
	"time"
)

func StatTicker() {
	var t = time.NewTicker(time.Second * 2)
	for {
		select {
		case <-t.C:
			stat, _ := net.IOCounters(true)
			log.Println("[stat]", ToJson(stat))
		}
	}
}
