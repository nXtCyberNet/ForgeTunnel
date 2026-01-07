package server

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"forgetunnel/protocol" // Ensure this matches your module name
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- Keys ---
var serverStaticPrivKeyBytes, _ = hex.DecodeString("535c9350a87b334ad3ee9495da29bc7b6dc15e01fb3e40a208adac7cc26bf79dec3b1f069fdd7b8372cd4726a1873e5869992a08aebbb1a5476617ec6519acde")
var serverStaticPrivKey = ed25519.PrivateKey(serverStaticPrivKeyBytes)

// --- State ---
type ClientState struct {
	ID        string
	Conn      net.Conn
	WriteCh   chan protocol.Frame
	Streams   map[uint32]net.Conn
	mu        sync.Mutex
	NextID    uint32
	LastSeen  time.Time
	SendState *CryptoState
	RecvState *CryptoState
}

type CryptoState struct {
	AESGCM cipher.AEAD
	Nonce  uint64
}

var (
	hostRegistry = make(map[string]*ClientState)
	registryMu   sync.RWMutex
)

// --- Crypto Helpers (Fixed to use AAD) ---

func newAESGCM(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead
}

// encrypt now accepts 'aad' (Additional Authenticated Data)
func encrypt(aead cipher.AEAD, nonce uint64, plaintext, aad []byte) []byte {
	nonceBytes := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonceBytes[len(nonceBytes)-8:], nonce)
	return aead.Seal(nil, nonceBytes, plaintext, aad)
}

// decrypt now accepts 'aad'
func decrypt(aead cipher.AEAD, nonce uint64, ciphertext, aad []byte) ([]byte, error) {
	nonceBytes := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonceBytes[len(nonceBytes)-8:], nonce)
	return aead.Open(nil, nonceBytes, ciphertext, aad)
}

// --- Control Server ---

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

func performServerHandshake(conn net.Conn) (*CryptoState, *CryptoState, error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PublicKey()

	frame, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}
	clientPubKey, err := curve.NewPublicKey(frame.Payload)
	if err != nil {
		return nil, nil, err
	}

	// Sign Ephemeral Key
	signature := ed25519.Sign(serverStaticPrivKey, pubKey.Bytes())
	payload := append(pubKey.Bytes(), signature...)

	err = writeFrame(conn, protocol.Frame{
		Kind:     protocol.KindHandshake,
		StreamID: 0,
		Payload:  payload,
	})
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, _ := privKey.ECDH(clientPubKey)
	sessionKey := sha256.Sum256(sharedSecret)
	gcm := newAESGCM(sessionKey[:])

	return &CryptoState{AESGCM: gcm, Nonce: 0}, &CryptoState{AESGCM: gcm, Nonce: 0}, nil
}

func handleAgentRegistration(conn net.Conn) {
	sendState, recvState, err := performServerHandshake(conn)
	if err != nil {
		log.Printf("Handshake failed: %v", err)
		conn.Close()
		return
	}

	frame, err := readEncryptedFrame(conn, recvState)
	if err != nil {
		conn.Close()
		return
	}

	if frame.Kind != protocol.KindControl {
		conn.Close()
		return
	}

	var ctrl protocol.ControlMessage
	if err := json.Unmarshal(frame.Payload, &ctrl); err != nil {
		conn.Close()
		return
	}

	if ctrl.Type != "register" || ctrl.From == "" {
		conn.Close()
		return
	}

	subdomain := ctrl.From
	client := &ClientState{
		ID:        subdomain,
		Conn:      conn,
		WriteCh:   make(chan protocol.Frame, 128),
		Streams:   make(map[uint32]net.Conn),
		NextID:    1,
		LastSeen:  time.Now(),
		SendState: sendState,
		RecvState: recvState,
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

	log.Printf("Agent registered: %s (Secured)", subdomain)
	defer cleanupClient(subdomain)

	go agentWriter(client)

	for {
		frame, err := readEncryptedFrame(conn, recvState)
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

// --- Encrypted IO (Fixed for AAD) ---

func agentWriter(client *ClientState) {
	defer client.Conn.Close()
	// FIX: Create header buffer for AAD
	headerBuf := make([]byte, 5)

	for frame := range client.WriteCh {
		state := client.SendState

		// FIX: Populate AAD
		headerBuf[0] = frame.Kind
		binary.BigEndian.PutUint32(headerBuf[1:], frame.StreamID)

		// FIX: Pass AAD to encrypt
		frame.Payload = encrypt(state.AESGCM, state.Nonce, frame.Payload, headerBuf)
		state.Nonce++

		if err := writeFrame(client.Conn, frame); err != nil {
			return
		}
	}
}

func readEncryptedFrame(conn net.Conn, state *CryptoState) (protocol.Frame, error) {
	frame, err := readFrame(conn)
	if err != nil {
		return protocol.Frame{}, err
	}

	// FIX: Reconstruct AAD from read header
	headerBuf := make([]byte, 5)
	headerBuf[0] = frame.Kind
	binary.BigEndian.PutUint32(headerBuf[1:], frame.StreamID)

	// FIX: Pass AAD to decrypt
	plaintext, err := decrypt(state.AESGCM, state.Nonce, frame.Payload, headerBuf)
	if err != nil {
		return protocol.Frame{}, errors.New("decryption failed: " + err.Error())
	}
	state.Nonce++

	frame.Payload = plaintext
	return frame, nil
}

// --- Raw IO ---

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

// --- Public Server & Logic ---

func StartPublicHttpServer(port string) {
	ln, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Public server failed to listen on %s: %v", port, err)
	}
	log.Printf("HTTP Server listening on %s", port)

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
		browserConn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 16\r\n\r\nTunnel not found"))
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
	b, _ := json.Marshal(protocol.ControlMessage{Type: typeStr, StreamID: streamID})
	frame := protocol.Frame{Kind: protocol.KindControl, Payload: b}
	select {
	case client.WriteCh <- frame:
	default:
	}
}

func closeStream(client *ClientState, streamID uint32) {
	client.mu.Lock()
	conn, ok := client.Streams[streamID]
	if !ok {
		client.mu.Unlock()
		return
	}
	delete(client.Streams, streamID)
	client.mu.Unlock()
	conn.Close()
	sendControl(client, "close_stream", streamID)
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

func extractHost(data []byte) string {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return ""
	}
	return req.Host
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

func StartHeartbeatReaper(timeout time.Duration) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		registryMu.Lock()
		for id, client := range hostRegistry {
			client.mu.Lock()
			last := client.LastSeen
			client.mu.Unlock()
			if now.Sub(last) > timeout {
				log.Printf("Agent timed out: %s", id)
				go cleanupClient(id)
			}
		}
		registryMu.Unlock()
	}
}
