package main

import (
	"forgetunnel/cmd/client" // Ensure this matches your go.mod module name
	"log"
	"time"
)

func main() {
	// --- Configuration ---
	// The address of your 'forgetunnel' server (Control Plane)
	serverAddr := "localhost:8080"

	// The subdomain you want to claim (e.g. "website.localhost")
	subdomain := "website"

	// The ID is just for logging/debugging

	log.Printf("Starting Client: Connecting to %s", serverAddr)
	log.Printf("Tunneling http://%s.localhost -> localhost:3000", subdomain)

	// --- Retry Loop ---
	for {
		// This function blocks until the connection is lost
		err := client.StartClient(serverAddr, subdomain)

		log.Printf("Disconnected: %v", err)
		log.Println("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}
