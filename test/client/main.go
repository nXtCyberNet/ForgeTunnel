package main

import (
	"log"

	"forgetunnel/cmd/client"
)

func main() {
	// CONFIG
	serverAddr := "127.0.0.1:7000" // Control plane
	clientID := "myapp"            // Subdomain: myapp.tunnel.com

	log.Println("Starting Forgetunnel Client")

	err := client.StartClient(serverAddr, clientID)
	if err != nil {
		log.Fatalf("Client exited: %v", err)
	}
}
