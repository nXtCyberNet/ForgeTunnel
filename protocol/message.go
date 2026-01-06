package protocol

const (
	KindControl byte = 1
	KindData    byte = 2
)

type ControlMessage struct {
	Type     string `json:"type"`
	From     string `json:"from,omitempty"`
	StreamID uint32 `json:"stream_id,omitempty"`
}

type Frame struct {
	Kind     byte
	StreamID uint32
	Payload  []byte
}
