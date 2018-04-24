package tlv

import (
	"log"
	"ndn-router/nfd/tlv/name"
	"ndn-router/nfd/tlv/packets"
//	"time"
)



//reads the input (bytes) swithes on the type and calls the appropriate decoder
func ConcurrentDecode(packet []byte) packets.NdnPacket {
	t, _, _, _ := TlvFromBytes(packet)
	switch t.T {
	case INTEREST:
		resultInterest, _ := concurrentDecodeInterest(t)
		resultInterest.Setbuffer(packet)
		return resultInterest
	case DATA:
		resultData, _ := decodeData(t)
		resultData.Setbuffer(packet)
		return resultData
	default:
		log.Println("unknown bytes")
		return nil
	}
}

func concurrentDecodeInterest(t Tlv) (packets.Interest, error) {
	tlvs, _ := ParseTlvsFromBytes(t.V)
	resultInterest := packets.Interest{}
	//channels
	chInterestName := make(chan name.Name)
	chInterestSelectors := make(chan packets.Selectors) 
	// chInterestNonce := make(chan [4]byte)
	// chInterestLifeTime := make(chan time.Duration)
	//launch go routines
	for _, tlv := range tlvs {
		switch (tlv.T){
		case NAME : 
			go concurrentDecodeInterestName(tlv, chInterestName)
		case SELECTORS:
			go concurrentDecodeInterestSelectors(tlv, chInterestSelectors)
			
		}
	}
	// go concurrentDecodeInterestName(tlvs[0], chInterestName)
	// go concurrentDecodeInterestSelectors(tlvs[1], chInterestSelectors)
	

	for i := 0; i < len(tlvs); i++ {
        select {
        case name := <-chInterestName:
			resultInterest.SetName(name)
		case sel := <- chInterestSelectors:
			resultInterest.Selector = sel
        } 
	}
	
	return resultInterest, nil
}

func concurrentDecodeInterestName(tlv Tlv, chInterestName chan name.Name) {
	//decodeName is common to both interest and data
	name, err := decodeName(tlv) //the name tlv is the first one tlvs[0]
	if err != nil {
		return
	}
	chInterestName <- name
}

func concurrentDecodeInterestSelectors(tlv Tlv, chInterestSelectors chan packets.Selectors) {
	selectorFields, _ := ParseTlvsFromBytes(tlv.V) // from []bytes to []Tlv
	sel := packets.Selectors{}
	for _, field := range selectorFields {
		switch field.T {
			case MIN_SUFFIX_COMPONENTS:
				x := DecodeNonNegativeInteger(field.V)
				sel.SetMinSuffixComponents(x)
			case MAX_SUFFIX_COMPONENTS:
				x := DecodeNonNegativeInteger(field.V)
				sel.SetMaxSuffixComponents(x)
			case PUBLISHER_PUB_KEY_LOCATOR:
				x, _, err := decodeKeyLocator(field)
				if err == nil {
					sel.SetPublisherPublicKeyLocator(x)
				}
			case EXCLUDE:
				x, _ := decodeExclude(field)
				sel.SetExclude(x)
			case CHILD_SELECTOR:
				x := DecodeNonNegativeInteger(field.V)
				sel.SetChildSelector(x)
			case MUST_BE_FRESH:
				x := decodeMustBeFresh(field)
				sel.SetMustBeFresh(x)
		}
	}
	chInterestSelectors <- sel
}
