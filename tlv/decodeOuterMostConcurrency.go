package tlv

import (
	"ndn-router/nfd/tlv/packets"
	"log"
)
func DecodeOuterMostConcurrency(packet []byte, result chan packets.NdnPacket) {
	t, _, _, _ := TlvFromBytes(packet)
	switch t.T {
	case INTEREST:
		resultInterest, _ := decodeInterest(t)
		resultInterest.Setbuffer(packet)
		result <- resultInterest
	case DATA:
		resultData, _ := decodeData(t)
		resultData.Setbuffer(packet)
		result <- resultData
	default:
		log.Println("unknown bytes")
	}
}
