package main

import (
	"forgetunnel/cmd/client"
	"log"
	"time"
)

func main() {
	serverAddr := "34.205.75.182:8080"
	subdomain := "admin"
	port := 3000
	log.Printf("Starting Client: Connecting to %s", serverAddr)
	log.Printf("Tunneling http://%s.34.205.75.182 -> localhost:3000", subdomain)

	for {

		err := client.StartClient(serverAddr, subdomain, port)

		log.Printf("Disconnected: %v", err)
		log.Println("Reconnecting in 5 seconds...")
		time.Sleep(5 * time.Second)
	}
}
