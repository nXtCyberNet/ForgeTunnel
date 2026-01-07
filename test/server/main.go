package main

import (
	"log"
	"time"

	"forgetunnel/cmd/server"
)

func main() {
	// CONFIG
	controlAddr := ":7000" // Agent ↔ Server (tunnel)
	publicAddr := ":8080"  // Browser ↔ Server (HTTP)
	heartbeatTimeout := 30 * time.Second

	log.Println("Starting Forgetunnel Server")

	// Start heartbeat reaper
	go server.StartHeartbeatReaper(heartbeatTimeout)

	// Start control plane (agents)
	go server.StartControlServer(controlAddr)

	// Start public HTTP entrypoint
	go server.StartPublicHttpServer(publicAddr)

	// Block forever
	select {}
}
