package tlv

import (
	"errors"
	"log"
	"ndn-router/nfd/tlv/name"
	"ndn-router/nfd/tlv/packets"
	"time"
)

//reads the input (bytes) swithes on the type and calls the appropriate decoder
func Decode(packet []byte) packets.NdnPacket {
	t, _, _, _ := TlvFromBytes(packet)
	switch t.T {
	case INTEREST:
		resultInterest, _ := decodeInterest(t)
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

//take the value od the interest TLV and call the different decode functiond for each sub tlv
//and return ant interest
func decodeInterest(t Tlv) (packets.Interest, error) {
	tlvs, _ := ParseTlvsFromBytes(t.V)
	resultInterest := packets.Interest{}
	err := decodeTlvs(
		&resultInterest, tlvs,
		decodeInterestName,
		decodeInterestSelectors,
		decodeInterestNonce,
		decodeInterestLifeTime,
	)
	if err != nil {
		return packets.Interest{}, err
	}
	return resultInterest, nil
}

func decodeData(t Tlv) (packets.Data, error) {
	tlvs, _ := ParseTlvsFromBytes(t.V)
	resultData := packets.Data{}
	err := decodeTlvs(
		&resultData, tlvs,
		decodeDataName,
		decodeDataMetaInfo,
		decodeDataContent,
		decodeDataSignature,
	)
	if err != nil {
		return packets.Data{}, err
	}
	return resultData, nil
}

// a decoder is any function with this prototype
type decoder func(packet interface{}, tlvs []Tlv) ([]Tlv, error)

//+++++++++++++++++++++++++++++++++++++++
//might find a way to add concurrency here to have concurrency on the same packet
//+++++++++++++++++++++++++++++++++++++++
func decodeTlvs(packet interface{}, tlvs []Tlv, dec ...decoder) error {
	//var err error
	for _, d := range dec {
		tlvs, _ = d(packet, tlvs)
		/*if err != nil {
		  return err
		}*/
	}
	return nil
}

//takes the name tlv and calls the decode name to get the name back and sets the result's name
func decodeInterestName(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeInterestName : --- no tlvs to read ---")
	}
	//decodeName is common to both interest and data
	name, err := decodeName(tlvs[0]) //the name tlv is the first one tlvs[0]
	if err != nil {
		return tlvs, err
	}
	packet.(*packets.Interest).SetName(name) //the result
	return tlvs[1:], nil                     //get rid of the processed tlv
}

//get name of either interest or data
func decodeName(t Tlv) (name.Name, error) {
	if t.T != NAME {
		return nil, errors.New("--- Decode Name --- : unexpected type")
	}
	//since the name tlv is multi level we do the same as we did with the outer most tlv
	componentTlvs, err := ParseTlvsFromBytes(t.V) // from []bytes to []Tlv
	if err != nil {
		return nil, err
	}
	components := []name.Component{}
	for _, t := range componentTlvs {
		c, err := decodeNameComponent(t)
		if err != nil {
			return nil, err
		}
		components = append(components, c)
	}
	return name.NewName(components...), nil
}

func decodeNameComponent(t Tlv) (name.Component, error) {
	if t.T == ANY {
		return name.Any, nil
	}
	if t.T != NAME_COMPONENT {
		return name.Component{}, errors.New("--- Decode Name --- : unexpected type")
	}
	//take the value which is bytes and turn it into a component
	c := name.ComponentFromBytes(t.V)
	return c, nil
}

func decodeDataName(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeDataName : --- no tlvs to read ---")
	}
	//decodeName is common to both interest and data
	name, err := decodeName(tlvs[0]) //the name tlv is the first one tlvs[0]
	if err != nil {
		return tlvs, err
	}
	packet.(*packets.Data).SetName(name) //the result
	return tlvs[1:], nil                 //get rid of the processed tlv
}

func decodeInterestSelectors(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeInterestSelectors : --- no tlvs to read ---")
	}
	t := tlvs[0]
	if t.T != SELECTORS {
		return tlvs, errors.New("--- Decode Interest Selectors --- : unexpected type")
	}
	selectorFields, _ := ParseTlvsFromBytes(t.V) // from []bytes to []Tlv
	for _, field := range selectorFields {
		err := decodeSelectorField(field, packet.(*packets.Interest))
		if err != nil {
			return nil, err
		}
	}
	return tlvs[1:], nil
}

func decodeSelectorField(field Tlv, packet *packets.Interest) error {
	switch field.T {
	case MIN_SUFFIX_COMPONENTS:
		x := DecodeNonNegativeInteger(field.V)
		packet.Selector.SetMinSuffixComponents(x)
	case MAX_SUFFIX_COMPONENTS:
		x := DecodeNonNegativeInteger(field.V)
		packet.Selector.SetMaxSuffixComponents(x)
	case PUBLISHER_PUB_KEY_LOCATOR:
		x, _, err := decodeKeyLocator(field)
		if err == nil {
			packet.Selector.SetPublisherPublicKeyLocator(x)
		}
	case EXCLUDE:
		x, _ := decodeExclude(field)
		packet.Selector.SetExclude(x)
	case CHILD_SELECTOR:
		x := DecodeNonNegativeInteger(field.V)
		packet.Selector.SetChildSelector(x)
	case MUST_BE_FRESH:
		x := decodeMustBeFresh(field)
		packet.Selector.SetMustBeFresh(x)
	}
	return nil
}

func decodeExclude(t Tlv) (name.Exclude, error) {
	if t.T != EXCLUDE {
		return nil, errors.New("--- Decode Exclude --- : unexpected type")
	}
	//since the exclude tlv is multi level we do the same as we did with the outer most tlv
	componentTlvs, err := ParseTlvsFromBytes(t.V) // from []bytes to []Tlv
	if err != nil {
		return nil, err
	}
	components := []name.Component{}
	for _, t := range componentTlvs {
		c, err := decodeNameComponent(t)
		if err != nil {
			return nil, err
		}
		components = append(components, c)
	}
	return name.NewExclude(components...), nil
}

func decodeMustBeFresh(t Tlv) bool {
	return true
}

func decodeInterestNonce(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeDataName : --- no tlvs to read ---")
	}
	t := tlvs[0]
	if t.T != NONCE {
		return tlvs, errors.New("--- Decode Interest Nonce --- : unexpected type")
	}
	nonce := [4]byte{}
	for i := 0; i < len(nonce); i++ {
		nonce[i] = t.V[i]
	}
	packet.(*packets.Interest).SetNonce(nonce)
	return tlvs[1:], nil
}

func decodeInterestLifeTime(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeInterestLifeTime : --- no tlvs to read ---")
	}
	t := tlvs[0]
	if t.T != INTEREST_LIFETIME {
		return tlvs, errors.New("--- DecodeInterestLifeTime --- : unexpected type")
	}
	lifeTime := DecodeNonNegativeInteger(t.V)
	packet.(*packets.Interest).SetInterestLifetime(time.Duration(lifeTime))
	return tlvs[1:], nil
}

func decodeDataMetaInfo(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeDataMetaInfo : --- no tlvs to read ---")
	}
	t := tlvs[0]
	if t.T != META_INFO {
		return tlvs, errors.New("--- DecodeDataMetaInfo --- : unexpected type")
	}
	metaFields, _ := ParseTlvsFromBytes(t.V) // from []bytes to []Tlv
	for _, field := range metaFields {
		err := decodeMetaField(field, packet.(*packets.Data))
		if err != nil {
			return nil, err
		}
	}
	return tlvs[1:], nil
}

func decodeMetaField(field Tlv, packet *packets.Data) error {
	switch field.T {
	case CONTENT_TYPE:
		x := DecodeNonNegativeInteger(field.V)
		packet.MetaInfo.SetContentType(packets.ContentType(x))
	case FRESHNESS_PERIOD:
		x := DecodeNonNegativeInteger(field.V)
		packet.MetaInfo.SetFreshnessPeriod(time.Duration(x))

	case FINAL_BLOCK_ID:
		t, _, _, _ := TlvFromBytes(field.V)
		x, err := decodeNameComponent(t)
		if err != nil {
			return err
		}
		packet.MetaInfo.SetFinalBlockID(x)
	}
	return nil
}

func decodeDataContent(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 1 {
		return nil, errors.New("DecodeDataContent : --- no tlvs to read ---")
	}
	t := tlvs[0]
	if t.T != CONTENT {
		return tlvs, errors.New("--- DecodeDataContent --- : unexpected type")
	}
	//the content is []bytes, it is value of the current tlv
	packet.(*packets.Data).SetContent(t.V)
	return tlvs[1:], nil
}

func decodeDataSignature(packet interface{}, tlvs []Tlv) ([]Tlv, error) {
	if len(tlvs) < 2 {
		return nil, errors.New("DecodeDataContent : --- no tlvs to read ---")
	}
	info := tlvs[0]
	val := tlvs[1]
	if info.T != SIGNATURE_INFO {
		return tlvs, errors.New("--- DecodeDataSignature ..SigInfo.. --- : unexpected type")
	}
	if val.T != SIGNATURE_VALUE {
		return tlvs, errors.New("--- DecodeDataSignature ..SigVal.. --- : unexpected type")
	}
	valBytes, _ := decodeSignatureValue(val)
	sigInfo, _ := decodeSignatureInfo(info)
	sig := packets.NewSignature(sigInfo, valBytes)
	packet.(*packets.Data).SetSignature(sig)
	return tlvs[2:], nil
}

func decodeSignatureValue(t Tlv) ([]byte, error) {
	if t.T != SIGNATURE_VALUE {
		return nil, errors.New("DecodeSignatureValue : --- unexpected type ---")
	}
	return t.V, nil
}

func decodeSignatureInfo(t Tlv) (packets.SignatureInfo, error) {
	tlvs, _ := ParseTlvsFromBytes(t.V)
	sigTypeTlv := tlvs[0]
	keyLocatorTlv := Tlv{}
	//checking if the keyLocator is there
	if len(tlvs) > 1 {
		keyLocatorTlv = tlvs[1]
	}
	sigType, _ := decodeSignatureType(sigTypeTlv)
	keyLocator, hasKeyLoc, _ := decodeKeyLocator(keyLocatorTlv)
	result := packets.NewSignatureInfo(sigType, hasKeyLoc, keyLocator)
	return result, nil
}

func decodeSignatureType(t Tlv) (uint64, error) {
	if t.T != SIGNATURE_TYPE {
		return 0, errors.New("DecodeSignatureValue : --- unexpected type ---")
	}
	sigType := DecodeNonNegativeInteger(t.V)
	return sigType, nil
}

func decodeKeyLocator(t Tlv) (packets.KeyLocator, bool, error) {
	if t.T != KEY_LOCATOR {
		return packets.KeyLocator{}, false, errors.New("DecodeSignatureValue : --- unexpected type ---")
	}
	keyLocValueTlv, _, _, _ := TlvFromBytes(t.V)
	result := packets.KeyLocator{}
	switch keyLocValueTlv.T {
	case NAME:
		nameRef, _ := decodeName(keyLocValueTlv)
		//fmt.Printf("+++++ %v +++++", nameRef)
		//fmt.Printf("+++++ %v +++++", keyLocValueTlv)
		result = packets.KeyLocator{
			nameRef,
			true,
			nil,
			false,
		}
	case KEY_DIGEST:
		keyDigest, _ := decodeKeyDigest(keyLocValueTlv)
		result = packets.KeyLocator{
			name.NewName(),
			false,
			keyDigest,
			true,
		}

	}
	return result, true, nil
}

func decodeKeyDigest(t Tlv) ([]byte, error) {
	if t.T != KEY_DIGEST {
		return nil, errors.New("DecodeSignatureValue : --- unexpected type ---")
	}
	return t.V, nil
}
