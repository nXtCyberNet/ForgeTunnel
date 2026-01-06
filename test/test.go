package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

type Message struct {
	From    string          `json:"from"`
	To      string          `json:"to"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func main() {
	ln, err := net.Listen("tcp", ":9000")
	if err != nil {
		panic(err)
	}
	defer ln.Close()

	fmt.Println("TCP Server listening on :9000")

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Println("accept error:", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	for {
		// 1️⃣ Read frame length (4 bytes)
		var length uint32
		err := binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read length error:", err)
			}
			return
		}

		// 2️⃣ Read frame body
		buf := make([]byte, length)
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			fmt.Println("read body error:", err)
			return
		}

		// 3️⃣ Decode JSON
		var msg Message
		if err := json.Unmarshal(buf, &msg); err != nil {
			fmt.Println("json unmarshal error:", err)
			continue
		}

		fmt.Printf("Received message: %+v\n", msg)

		// 4️⃣ Send response
		resp := Message{
			Type: "received",
			To:   msg.From,
			From: "server",
			Payload: json.RawMessage(`{
				"hello": "yoo"
			}`),
		}

		data, err := json.Marshal(resp)
		if err != nil {
			fmt.Println("marshal error:", err)
			return
		}

		// 5️⃣ Write framed response
		if err := binary.Write(conn, binary.BigEndian, uint32(len(data))); err != nil {
			fmt.Println("write length error:", err)
			return
		}

		if _, err := conn.Write(data); err != nil {
			fmt.Println("write body error:", err)
			return
		}
	}
}
