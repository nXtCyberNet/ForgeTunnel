package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	clients = make(map[string]net.Conn)
	mu      sync.Mutex
)

type TunnelMessage struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    json.RawMessage     `json:"body"`
}

func writeMessage(conn net.Conn, msg Message) {
	data, _ := json.Marshal(msg)

	binary.Write(conn, binary.BigEndian, uint32(len(data)))
	conn.Write(data)
}

func readMessage(conn net.Conn) Message {
	var length uint32
	binary.Read(conn, binary.BigEndian, &length)

	buf := make([]byte, length)
	io.ReadFull(conn, buf)

	var msg Message
	json.Unmarshal(buf, &msg)
	return msg
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	// 1️⃣ First message must be identity
	msg := readMessage(conn)

	mu.Lock()
	clients[msg.From] = conn
	mu.Unlock()

	for {
		msg = readMessage(conn)
		routeMessage(msg)
	}
}

func startHeartbeat(conn net.Conn, clientID string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		msg := Message{
			From: clientID,
			Type: "heartbeat",
		}
		writeMessage(conn, msg)
	}
}

func main() {
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// 1️⃣ Create message
	msg := Message{
		Type:     "create",
		App:      "demo",
		Replicas: 2,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		log.Println(err)
	}

	if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
		log.Println(err)
	}

	if _, err := conn.Write(data); err != nil {
		panic(err)
	}

	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		if err != io.EOF {
			fmt.Println("read length error:", err)
		}
		return
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		fmt.Println("read body error:", err)
		return
	}

}
