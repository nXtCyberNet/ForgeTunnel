package client

import (
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
	"forgetunnel/protocol"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var serverStaticPubKeyBytes, _ = hex.DecodeString("ec3b1f069fdd7b8372cd4726a1873e5869992a08aebbb1a5476617ec6519acde")
var serverStaticPubKey = ed25519.PublicKey(serverStaticPubKeyBytes)

type StreamState struct {
	ID   uint32
	Conn net.Conn
}

type SecureConn struct {
	Send CryptoState
	Recv CryptoState
}

type CryptoState struct {
	AESGCM cipher.AEAD
	Nonce  uint64
}

var (
	streams = make(map[uint32]*StreamState)
	sm      sync.Mutex
)

func SendRegistor(clientID string, writeCh chan protocol.Frame) error {
	ctrl := protocol.ControlMessage{
		Type: "register",
		From: clientID,
	}

	payload, err := json.Marshal(ctrl)
	if err != nil {
		return err
	}

	writeCh <- protocol.Frame{
		Kind:     protocol.KindControl,
		StreamID: 0,
		Payload:  payload,
	}
	return nil

}

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

func encrypt(aead cipher.AEAD, nonce uint64, plaintext, aad []byte) []byte {
	nonceBytes := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonceBytes[len(nonceBytes)-8:], nonce)
	return aead.Seal(nil, nonceBytes, plaintext, aad)
}

func decrypt(aead cipher.AEAD, nonce uint64, ciphertext, aad []byte) ([]byte, error) {
	nonceBytes := make([]byte, aead.NonceSize())
	binary.BigEndian.PutUint64(nonceBytes[len(nonceBytes)-8:], nonce)

	return aead.Open(nil, nonceBytes, ciphertext, aad)
}

func performHandshake(conn net.Conn) (*CryptoState, *CryptoState, error) {
	// 1. Generate Ephemeral Keys (Same as before)
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := privKey.PublicKey()

	// 2. Send Client Public Key (Same as before)
	err = writeFrame(conn, protocol.Frame{
		Kind:     protocol.KindHandshake,
		StreamID: 0,
		Payload:  pubKey.Bytes(),
	})
	if err != nil {
		return nil, nil, err
	}

	// 3. Read Server Response
	frame, err := readFrame(conn)
	if err != nil {
		return nil, nil, err
	}

	// --- NEW VERIFICATION STEP ---
	// Payload should be 32 bytes (Key) + 64 bytes (Sig) = 96 bytes
	if len(frame.Payload) != 96 {
		return nil, nil, errors.New("invalid handshake size")
	}

	serverEphemeralKey := frame.Payload[:32]
	signature := frame.Payload[32:]

	// Verify the signature
	// "Did the Static Key sign this Ephemeral Key?"
	valid := ed25519.Verify(serverStaticPubKey, serverEphemeralKey, signature)
	if !valid {
		return nil, nil, errors.New("MITM DETECTED: Invalid Server Signature!")
	}
	// -----------------------------

	// 4. Continue as normal
	serverPubKey, err := curve.NewPublicKey(serverEphemeralKey)
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := privKey.ECDH(serverPubKey)
	if err != nil {
		return nil, nil, err
	}

	sessionKey := sha256.Sum256(sharedSecret)
	block, _ := aes.NewCipher(sessionKey[:])
	gcm, _ := cipher.NewGCM(block)

	return &CryptoState{AESGCM: gcm, Nonce: 0}, &CryptoState{AESGCM: gcm, Nonce: 0}, nil
}

func StartClient(serverAddr, clientID string) error {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("Connected to server at %s", serverAddr)

	sendState, recvState, err := performHandshake(conn)
	if err != nil {
		return err
	}

	writeCh := make(chan protocol.Frame, 128)
	stop := make(chan struct{})

	// FIX 1: Close 'stop' when this function exits.
	// This tells startHeartbeat and writer to stop cleanly.
	defer close(stop)

	go writer(conn, writeCh, stop, sendState)

	if err := SendRegistor(clientID, writeCh); err != nil {
		return err
	}

	go startHeartbeat(writeCh, clientID, stop)

	for {
		frame, err := readEncryptedFrame(conn, recvState)
		if err != nil {
			// FIX 2: DELETE THIS LINE -> close(writeCh)
			// Just return. The 'defer close(stop)' above handles the cleanup.
			return err
		}

		switch frame.Kind {
		case protocol.KindControl:
			var ctrl protocol.ControlMessage
			if err := json.Unmarshal(frame.Payload, &ctrl); err != nil {
				log.Printf("Failed to unmarshal control msg: %v", err)
				continue
			}
			handleControl(ctrl, writeCh)

		case protocol.KindData:
			handleData(frame.StreamID, frame.Payload)
		}
	}
}

func handleControl(msg protocol.ControlMessage, writeCh chan<- protocol.Frame) {
	switch msg.Type {
	case "open_stream":
		log.Println("got the open_stream message ")
		log.Println(msg.StreamID)
		go openLocalStream(msg.StreamID, writeCh)

	case "close_stream":
		closeLocalStream(msg.StreamID)
		log.Println("got the close_stream message ")
		log.Println(msg.StreamID)
	}
}

func handleData(streamID uint32, payload []byte) {
	var stream *StreamState

	for i := 0; i < 10; i++ {
		sm.Lock()
		stream = streams[streamID]
		sm.Unlock()

		if stream != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if stream == nil {
		log.Printf("CLIENT: data for unknown stream %d (dropped)", streamID)
		return
	}

	_, err := stream.Conn.Write(payload)
	if err != nil {
		closeLocalStream(streamID)
	}
}

func openLocalStream(streamID uint32, writeCh chan<- protocol.Frame) {
	conn, err := net.Dial("tcp", "127.0.0.1:3000")
	if err != nil {
		log.Printf("Failed to dial local app: %v", err)
		sendCloseStream(streamID, writeCh)
		return
	}

	sm.Lock()
	streams[streamID] = &StreamState{
		ID:   streamID,
		Conn: conn,
	}
	sm.Unlock()
	log.Println("stream opened")

	go localToTunnel(streamID, conn, writeCh)
}

func localToTunnel(streamID uint32, localConn net.Conn, writeCh chan<- protocol.Frame) {
	buf := make([]byte, 32*1024)
	defer closeLocalStream(streamID)

	for {
		n, err := localConn.Read(buf)
		if err != nil {

			sendCloseStream(streamID, writeCh)
			return
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])

		writeCh <- protocol.Frame{
			Kind:     protocol.KindData,
			StreamID: streamID,
			Payload:  payload,
		}
		log.Println("message send to tunnel ")
	}
}

func closeLocalStream(streamID uint32) {
	sm.Lock()
	stream, ok := streams[streamID]
	if !ok {
		sm.Unlock()
		return
	}
	delete(streams, streamID)
	sm.Unlock()

	stream.Conn.Close()
}

func sendCloseStream(streamID uint32, writeCh chan<- protocol.Frame) {
	ctrl := protocol.ControlMessage{
		Type:     "close_stream",
		StreamID: streamID,
	}
	payload, _ := json.Marshal(ctrl)

	writeCh <- protocol.Frame{
		Kind:     protocol.KindControl,
		StreamID: 0,
		Payload:  payload,
	}
}

func startHeartbeat(writeCh chan<- protocol.Frame, clientID string, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return // Stop signal received, exit immediately
		case <-ticker.C:
			// Check stop again before doing work, just in case
			select {
			case <-stop:
				return
			default:
			}

			ctrl := protocol.ControlMessage{
				Type: "heartbeat",
				From: clientID,
			}
			payload, _ := json.Marshal(ctrl)

			// Try to send, but abort if 'stop' is closed
			select {
			case writeCh <- protocol.Frame{
				Kind:     protocol.KindControl,
				StreamID: 0,
				Payload:  payload,
			}:
				// Success
			case <-stop:
				return // Abort send if stopping
			}
		}
	}
}

func writer(conn net.Conn, writeCh <-chan protocol.Frame, stop <-chan struct{}, state *CryptoState) {
	headerBuf := make([]byte, 5)

	for {
		select {
		case frame, ok := <-writeCh:

			if !ok {
				return
			}
			headerBuf[0] = frame.Kind
			binary.BigEndian.PutUint32(headerBuf[1:], frame.StreamID)

			payload := encrypt(state.AESGCM, state.Nonce, frame.Payload, headerBuf)
			state.Nonce++

			frame.Payload = payload
			if err := writeFrame(conn, frame); err != nil {
				log.Println("frame send ")
				return
			}
		case <-stop:
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

func readEncryptedFrame(conn net.Conn, state *CryptoState) (protocol.Frame, error) {

	frame, err := readFrame(conn)
	if err != nil {
		return protocol.Frame{}, err
	}
	headerBuf := make([]byte, 5)
	headerBuf[0] = frame.Kind
	binary.BigEndian.PutUint32(headerBuf[1:], frame.StreamID)

	plaintext, err := decrypt(state.AESGCM, state.Nonce, frame.Payload, headerBuf)
	if err != nil {
		return protocol.Frame{}, errors.New("decryption failed: " + err.Error())
	}
	state.Nonce++

	frame.Payload = plaintext
	return frame, nil
}
