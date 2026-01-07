package main

import (
	"forgetunnel/cmd/server" // Ensure this matches your go.mod module name
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// 1. Start Control Server (Port 8080)
	// Agents (the Go client) connect here to register and maintain the tunnel.
	go func() {
		log.Println("Starting Control Server on :8080...")
		// This blocks, so we run it in a goroutine
		server.StartControlServer(":8080")
	}()

	// 2. Start Public HTTP Server (Port 80)
	// External users/browsers connect here (e.g., http://myapp.localhost).
	go func() {
		log.Println("Starting Public HTTP Server on :80...")
		// Note: On Mac/Linux, you might need 'sudo' to bind to port 80.
		// If that's annoying, change this to ":8000" and access via http://myapp.localhost:8000
		server.StartPublicHttpServer(":8000")
	}()

	// 3. Keep Alive
	// Block the main thread until we receive Ctrl+C
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("\nShutting down servers...")
}
