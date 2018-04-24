package packets

import (
	"math/rand"
	//"ndn-router/ndn/tlv"
	"encoding/binary"
	"ndn-router/nfd/tlv/name"
	"time"
)

// Interest ::= INTEREST-TYPE TLV-LENGTH
//					Name
//					Selectors?
//					Nonce
//					InterestLifetime?
//					ForwardingHint?
type Interest struct {
	Arr         time.Time
	name        name.Name
	Selector    Selectors
	nonce       [4]byte
	hasLifetime bool
	lifetime    time.Duration
	buffer      []byte
}

func NewInterest(name name.Name) *Interest {
	i := Interest{
		name: name,
	}
	i.GenerateNonce()
	return &i
}

//implementing the NdnPacket interface
func (i Interest) PacketType() uint64 {
	return 5
}

// getters and setters
func (i Interest) GetName() name.Name {
	if i.name == nil {
		i.name = name.Name{}
	}
	return i.name
}

func (i *Interest) SetName(n name.Name) {
	i.name = n
}

func (i *Interest) Setbuffer(b []byte) {
	i.buffer = b
}

func (i Interest) GetBuffer() []byte {
	return i.buffer
}

func (i Interest) GetInterestLifetime() time.Duration {
	if !i.hasLifetime {
		return 4 * time.Second
	}
	return i.lifetime
}

func (i *Interest) SetInterestLifetime(x time.Duration) {
	i.hasLifetime = true
	i.lifetime = x
}

func (i Interest) GetNonce() [4]byte {
	return i.nonce
}

func (i *Interest) SetNonce(n [4]byte) {
	i.nonce = n
}

func (i *Interest) GenerateNonce() {
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	randNonce := r.Int31()
	i.nonce = nonceToBytes(randNonce)
}

func nonceToBytes(n int32) [4]byte {
	b := [4]byte{}
	binary.BigEndian.PutUint32(b[:], uint32(n))
	return b
}
