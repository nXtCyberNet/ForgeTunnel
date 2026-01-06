package server

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"forgetunnel/protocol"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type ClientState struct {
	ID       string
	Conn     net.Conn
	WriteCh  chan protocol.Frame
	Streams  map[uint32]net.Conn
	mu       sync.Mutex
	NextID   uint32
	LastSeen time.Time
}

var (
	hostRegistry = make(map[string]*ClientState)
	registryMu   sync.RWMutex
)

func StartControlServer(port string) {
	ln, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Control server failed to listen on %s: %v", port, err)
	}
	log.Printf("Control Plane listening on %s (Agents connect here)", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleAgentRegistration(conn)
	}
}

func handleAgentRegistration(conn net.Conn) {

	frame, err := readFrame(conn)
	if err != nil {
		conn.Close()
		return
	}

	if frame.Kind != protocol.KindControl {
		log.Println("First frame was not control message")
		conn.Close()
		return
	}

	var ctrl protocol.ControlMessage
	if err := json.Unmarshal(frame.Payload, &ctrl); err != nil {
		log.Println("Invalid JSON in register")
		conn.Close()
		return
	}

	if ctrl.Type != "register" || ctrl.From == "" {
		log.Println("Invalid register command")
		conn.Close()
		return
	}

	subdomain := ctrl.From

	client := &ClientState{
		ID:       subdomain,
		Conn:     conn,
		WriteCh:  make(chan protocol.Frame, 128),
		Streams:  make(map[uint32]net.Conn),
		NextID:   1,
		LastSeen: time.Now(),
	}
	registryMu.Lock()

	if _, exists := hostRegistry[subdomain]; exists {
		registryMu.Unlock()
		log.Printf("Subdomain %s already taken", subdomain)
		conn.Close()
		return
	}
	hostRegistry[subdomain] = client
	registryMu.Unlock()

	log.Printf("Agent registered: %s.tunnel.com", subdomain)

	defer cleanupClient(subdomain)

	go agentWriter(client)

	for {
		frame, err := readFrame(conn)
		if err != nil {
			return
		}

		switch frame.Kind {
		case protocol.KindControl:
			handleControl(client, frame.Payload)

		case protocol.KindData:
			handleData(client, frame.StreamID, frame.Payload)
		}
	}
}

func StartPublicHttpServer(port string) {
	ln, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Public server failed to listen on %s: %v", port, err)
	}
	log.Printf("HTTP Server listening on %s (Browsers connect here)", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleBrowserRequest(conn)
	}
}

func handleBrowserRequest(browserConn net.Conn) {

	headerBuf := make([]byte, 4096)

	browserConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := browserConn.Read(headerBuf)
	if err != nil {
		browserConn.Close()
		return
	}
	browserConn.SetReadDeadline(time.Time{})

	host := extractHost(headerBuf[:n])
	if host == "" {
		browserConn.Close()
		return
	}

	subdomain := parseSubdomain(host)

	registryMu.RLock()
	client, ok := hostRegistry[subdomain]
	registryMu.RUnlock()

	if !ok {
		browserConn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 17\r\n\r\nTunnel not found"))
		browserConn.Close()
		return
	}

	client.mu.Lock()
	streamID := client.NextID
	client.NextID++
	client.Streams[streamID] = browserConn
	client.mu.Unlock()

	sendControl(client, "open_stream", streamID)

	client.WriteCh <- protocol.Frame{
		Kind:     protocol.KindData,
		StreamID: streamID,
		Payload:  headerBuf[:n],
	}

	go publicToTunnel(client, streamID, browserConn)
}

func parseSubdomain(fullHost string) string {

	if strings.Contains(fullHost, ":") {
		fullHost = strings.Split(fullHost, ":")[0]
	}

	parts := strings.Split(fullHost, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func extractHost(data []byte) string {

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return ""
	}
	return req.Host
}

func publicToTunnel(client *ClientState, streamID uint32, browserConn net.Conn) {

	buf := make([]byte, 32*1024)
	defer closeStream(client, streamID)

	for {
		n, err := browserConn.Read(buf)
		if err != nil {
			return
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		client.WriteCh <- protocol.Frame{
			Kind:     protocol.KindData,
			StreamID: streamID,
			Payload:  payload,
		}
	}
}

func handleControl(client *ClientState, payload []byte) {
	var ctrl protocol.ControlMessage
	if err := json.Unmarshal(payload, &ctrl); err != nil {
		return
	}

	switch ctrl.Type {
	case "heartbeat":
		client.mu.Lock()
		client.LastSeen = time.Now()
		client.mu.Unlock()
	case "close_stream":
		closeStream(client, ctrl.StreamID)
	}
}

func handleData(client *ClientState, streamID uint32, payload []byte) {
	client.mu.Lock()
	browserConn, ok := client.Streams[streamID]
	client.mu.Unlock()

	if ok {
		_, err := browserConn.Write(payload)
		if err != nil {
			closeStream(client, streamID)
		}
	}
}

func sendControl(client *ClientState, typeStr string, streamID uint32) {
	ctrl := protocol.ControlMessage{
		Type:     typeStr,
		StreamID: streamID,
	}
	payload, _ := json.Marshal(ctrl)

	client.WriteCh <- protocol.Frame{
		Kind:    protocol.KindControl,
		Payload: payload,
	}
}

func closeStream(client *ClientState, streamID uint32) {
	client.mu.Lock()
	conn, ok := client.Streams[streamID]
	if ok {
		conn.Close()
		delete(client.Streams, streamID)
	}
	client.mu.Unlock()

	if ok {
		sendControl(client, "close_stream", streamID)
	}
}

func cleanupClient(subdomain string) {
	registryMu.Lock()
	client, ok := hostRegistry[subdomain]
	if ok {
		delete(hostRegistry, subdomain)
		client.Conn.Close()

		client.mu.Lock()
		for _, stream := range client.Streams {
			stream.Close()
		}
		client.mu.Unlock()
	}
	registryMu.Unlock()
	log.Printf("Cleaned up client: %s", subdomain)
}

func agentWriter(client *ClientState) {
	for frame := range client.WriteCh {
		if err := writeFrame(client.Conn, frame); err != nil {
			return
		}
	}
}

func readFrame(conn net.Conn) (protocol.Frame, error) {
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return protocol.Frame{}, err
	}
	if length > 5_000_000 {
		return protocol.Frame{}, errors.New("frame too large")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return protocol.Frame{}, err
	}

	if len(buf) < 5 {
		return protocol.Frame{}, errors.New("frame too short")
	}

	return protocol.Frame{
		Kind:     buf[0],
		StreamID: binary.BigEndian.Uint32(buf[1:5]),
		Payload:  buf[5:],
	}, nil
}

func writeFrame(conn net.Conn, frame protocol.Frame) error {
	length := uint32(1 + 4 + len(frame.Payload))
	if err := binary.Write(conn, binary.BigEndian, length); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, frame.Kind); err != nil {
		return err
	}
	if err := binary.Write(conn, binary.BigEndian, frame.StreamID); err != nil {
		return err
	}
	_, err := conn.Write(frame.Payload)
	return err
}
