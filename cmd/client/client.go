package client

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"forgetunnel/protocol"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type Frame struct {
	Kind     byte
	StreamID uint32
	Payload  []byte
}

type StreamState struct {
	ID   uint32
	Conn net.Conn
}

var (
	streams = make(map[uint32]*StreamState)
	sm      sync.Mutex
)

func StartClient(serverAddr, clientID string) error {
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Printf("Connected to server at %s", serverAddr)

	writeCh := make(chan Frame, 128)
	stop := make(chan struct{})

	go writer(conn, writeCh, stop)

	go startHeartbeat(writeCh, clientID, stop)

	for {
		frame, err := readFrame(conn)
		if err != nil {
			close(writeCh)
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

func handleControl(msg protocol.ControlMessage, writeCh chan<- Frame) {
	switch msg.Type {
	case "open_stream":
		go openLocalStream(msg.StreamID, writeCh)

	case "close_stream":
		closeLocalStream(msg.StreamID)
	}
}

func handleData(streamID uint32, payload []byte) {
	sm.Lock()
	stream, ok := streams[streamID]
	sm.Unlock()

	if ok {
		_, err := stream.Conn.Write(payload)
		if err != nil {
			closeLocalStream(streamID)
		}
	}
}

func openLocalStream(streamID uint32, writeCh chan<- Frame) {
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

	go localToTunnel(streamID, conn, writeCh)
}

func localToTunnel(streamID uint32, localConn net.Conn, writeCh chan<- Frame) {
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

		writeCh <- Frame{
			Kind:     protocol.KindData,
			StreamID: streamID,
			Payload:  payload,
		}
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

func sendCloseStream(streamID uint32, writeCh chan<- Frame) {
	ctrl := protocol.ControlMessage{
		Type:     "close_stream",
		StreamID: streamID,
	}
	payload, _ := json.Marshal(ctrl)

	writeCh <- Frame{
		Kind:     protocol.KindControl,
		StreamID: 0,
		Payload:  payload,
	}
}

func startHeartbeat(writeCh chan<- Frame, clientID string, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctrl := protocol.ControlMessage{
				Type: "heartbeat",
				From: clientID,
			}
			payload, _ := json.Marshal(ctrl)

			writeCh <- Frame{
				Kind:     protocol.KindControl,
				StreamID: 0,
				Payload:  payload,
			}
		case <-stop:
			return
		}
	}
}

func writer(conn net.Conn, writeCh <-chan Frame, stop <-chan struct{}) {
	for {
		select {
		case frame, ok := <-writeCh:
			if !ok {
				return
			}
			if err := writeFrame(conn, frame); err != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func readFrame(conn net.Conn) (Frame, error) {
	var length uint32

	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return Frame{}, err
	}

	if length > 5_000_000 {
		return Frame{}, errors.New("frame too large")
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return Frame{}, err
	}

	if len(buf) < 5 {
		return Frame{}, errors.New("frame too short")
	}

	return Frame{
		Kind:     buf[0],
		StreamID: binary.BigEndian.Uint32(buf[1:5]),
		Payload:  buf[5:],
	}, nil
}

func writeFrame(conn net.Conn, frame Frame) error {

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
