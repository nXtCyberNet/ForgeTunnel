package main

import (
	"forgetunnel/cmd/server"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	go func() {
		log.Println("Starting Control Server on :8080...")

		server.StartControlServer(":8080")
	}()

	go func() {
		log.Println("Starting Public HTTP Server on :80...")
		server.StartPublicHttpServer(":8000")
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("\nShutting down servers...")
}
