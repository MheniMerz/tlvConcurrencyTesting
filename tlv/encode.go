package tlv

import (
	"bytes"
	"errors"
	"io"
	"log"

	"ndn-router/nfd/tlv/name"
	"ndn-router/nfd/tlv/packets"
)

//reads an NDNpacket and writes a stream of bytes to the writer
//provided as a second parameter
func Encode(packet packets.NdnPacket, byteStream io.Writer) error {
	t := Tlv{}
	switch packet.PacketType() {
	case INTEREST:
		t, _ = encodeInterest(packet.(packets.Interest))
	case DATA:
		t, _ = encodeData(packet.(packets.Data))
	default:
		return errors.New("Encode: -- unknown packet type --")
	}

	//write the tlv as bytes
	err := TlvToBytes(t, byteStream)
	return err
}

func encodeInterest(i packets.Interest) (Tlv, error) {
	//this returns a slice of Tlvs representing the value of the outer most Tlv
	val, err := encodeSubTlvs(
		i,
		encodeInterestName,
		encodeInterestSelectors,
		encodeInterestNonce,
		encodeInterestLifeTime,
	)

	if err != nil {
		return Tlv{}, err
	}

	var b bytes.Buffer
	TlvsToBytes(val, &b)
	result := Tlv{
		T: INTEREST,
		L: uint64(b.Len()),
		V: b.Next(b.Len()),
	}
	return result, nil
}

func encodeData(d packets.Data) (Tlv, error) {
	//this returns a slice of Tlvs representing the value of the outer most Tlv
	val, err := encodeSubTlvs(
		d,
		encodeDataName,
		encodeDataMetaInfo,
		encodeDataContent,
		encodeDataSignature,
	)
	if err != nil {
		return Tlv{}, err
	}

	var b bytes.Buffer
	TlvsToBytes(val, &b)
	result := Tlv{
		T: DATA,
		L: uint64(b.Len()),
		V: b.Next(b.Len()),
	}
	return result, nil
}

func encodeSubTlvs(packet interface{}, enc ...encoder) ([]Tlv, error) {
	//create a buffer here then get thte bytes back
	var t []Tlv
	var err error
	for _, e := range enc {
		t, err = e(packet, t)
		if err != nil {
			return t, err
		}
	}
	return t, nil
}

//an encode is any function of this format
type encoder func(packet interface{}, t []Tlv) ([]Tlv, error)

func encodeInterestName(packet interface{}, t []Tlv) ([]Tlv, error) {
	name := packet.(packets.Interest).GetName()
	if name.Size() == 0 {
		return nil, errors.New("Encode: -- a packet must have a name --")
	}
	return append(t, encodeName(name)), nil
}

func encodeDataName(packet interface{}, t []Tlv) ([]Tlv, error) {
	name := packet.(packets.Data).GetName()
	if name.Size() == 0 {
		return nil, errors.New("Encode: -- a packet must have a name --")
	}
	return append(t, encodeName(name)), nil
}

//encoding a name ==> goes back to encoding nae components
func encodeName(n name.Name) Tlv {
	t := []Tlv{}
	for _, comp := range n {
		t = append(t, encodeNameComponent(comp))
	}
	//need to convert []Tlv to []byte which will be the value of the name
	var b bytes.Buffer
	TlvsToBytes(t, &b)
	result := Tlv{
		T: NAME,
		L: uint64(b.Len()),
		V: b.Next(b.Len()),
	}
	return result
}

func encodeNameComponent(comp name.Component) Tlv {
	b := comp.ComponentToBytes()
	if comp == name.Any {
		t := Tlv{
			T: ANY,
			L: uint64(len(b)),
			V: b,
		}
		return t
	}
	t := Tlv{
		T: NAME_COMPONENT,
		L: uint64(len(b)),
		V: b,
	}
	return t
}

func encodeInterestSelectors(packet interface{}, t []Tlv) ([]Tlv, error) {
	sel := packet.(packets.Interest).Selector
	val := []Tlv{}
	var b bytes.Buffer

	if sel.IsEmpty() {
		//packet has no selectors ==> skip
		return t, nil
	}

	if sel.HasMinSuffixComponents {
		minSc := sel.GetMinSuffixComponents()
		minScToByte := EncodeNonNegativeInteger(uint64(minSc))
		x := Tlv{T: MIN_SUFFIX_COMPONENTS, L: uint64(len(minScToByte)), V: minScToByte}
		val = append(val, x)
	}

	if sel.HasMaxSuffixComponents {
		maxSc := sel.GetMaxSuffixComponents()
		maxScToByte := EncodeNonNegativeInteger(uint64(maxSc))
		x := Tlv{T: MAX_SUFFIX_COMPONENTS, L: uint64(len(maxScToByte)), V: maxScToByte}
		val = append(val, x)
	}

	if sel.HasPublisherPublicKeyLocator {
		pubKey := sel.GetPublisherPublicKeyLocator()
		keyLoc := encodeKeyLocator(pubKey)
		err := TlvToBytes(keyLoc, &b)
		if err != nil {
			return nil, err
		}
		x := Tlv{T: PUBLISHER_PUB_KEY_LOCATOR, L: uint64(b.Len()), V: b.Next(b.Len())}
		val = append(val, x)
	}

	if sel.HasExclude {
		ex := sel.GetExclude()
		val = append(val, encodeExclude(ex))
	}

	if sel.HasChildSelector {
		chSel := sel.GetChildSelector()
		chSelToBytes := EncodeNonNegativeInteger(uint64(chSel))
		x := Tlv{T: CHILD_SELECTOR, L: uint64(len(chSelToBytes)), V: chSelToBytes}
		val = append(val, x)
	}

	if sel.GetMustBeFresh() == true {
		x := Tlv{T: MUST_BE_FRESH, L: 0, V: nil}
		val = append(val, x)
	}

	err := TlvsToBytes(val, &b)
	if err != nil {
		return nil, err
	}
	result := Tlv{T: SELECTORS, L: uint64(b.Len()), V: b.Next(b.Len())}
	return append(t, result), nil
}

func encodeExclude(ex name.Exclude) Tlv {
	v := []Tlv{}
	for _, c := range ex {
		v = append(v, encodeNameComponent(c))
	}

	var b bytes.Buffer
	TlvsToBytes(v, &b)
	result := Tlv{
		T: EXCLUDE,
		L: uint64(b.Len()),
		V: b.Next(b.Len()),
	}
	return result
}

func encodeInterestNonce(packet interface{}, t []Tlv) ([]Tlv, error) {
	n := packet.(packets.Interest).GetNonce()
	nonce := Tlv{
		T: NONCE,
		L: uint64(len(n)),
		V: n[:],
	}
	return append(t, nonce), nil
}

func encodeInterestLifeTime(packet interface{}, t []Tlv) ([]Tlv, error) {
	lt := packet.(packets.Interest).GetInterestLifetime()
	lifeTime := Tlv{
		T: INTEREST_LIFETIME,
	}
	//this case should not occur but just in case it does
	if int64(lt) == -1 {
		return t, nil
		// lifeTime.L = 2                  // 4000 Millisecond is 0x0FA0 ==> 2 bytes
		// lifeTime.V = []byte{0x0F, 0xA0} // 4 Seconds
	} else {
		//need to convert lt to []byte
		b := EncodeNonNegativeInteger(uint64(lt))
		lifeTime.L = uint64(len(b))
		lifeTime.V = b
	}
	return append(t, lifeTime), nil
}

func encodeDataMetaInfo(packet interface{}, t []Tlv) ([]Tlv, error) {
	mi := packet.(packets.Data).GetMetaInfo()
	val := []Tlv{}
	if ct := mi.GetContentType(); ct != packets.Unknown {
		ctToByte := EncodeNonNegativeInteger(uint64(ct))
		x := Tlv{T: CONTENT_TYPE, L: uint64(len(ctToByte)), V: ctToByte}
		val = append(val, x)
	}
	if fp := mi.GetFreshnessPeriod(); fp != -1 {
		fpToByte := EncodeNonNegativeInteger(uint64(fp))
		x := Tlv{T: FRESHNESS_PERIOD, L: uint64(len(fpToByte)), V: fpToByte}
		val = append(val, x)
	}
	if id := mi.GetFinalBlockID(); len(id.GetValue()) > 0 {
		idToByte := id.ComponentToBytes()
		x := Tlv{T: CONTENT_TYPE, L: uint64(len(idToByte)), V: idToByte}
		val = append(val, x)
	}

	var b bytes.Buffer
	err := TlvsToBytes(val, &b)
	if err != nil {
		return t, err
	}
	metaInfo := Tlv{
		T: META_INFO,
		L: uint64(b.Len()),
		V: b.Next(b.Len()),
	}
	return append(t, metaInfo), nil
}

func encodeDataContent(packet interface{}, t []Tlv) ([]Tlv, error) {
	ct := packet.(packets.Data).GetContent()
	log.Printf("@@@@@@@@@@@@@@ %v", ct)
	x := Tlv{
		T: CONTENT,
		L: uint64(len(ct)),
		V: ct,
	}
	return append(t, x), nil
}

func encodeDataSignature(packet interface{}, t []Tlv) ([]Tlv, error) {
	sig := packet.(packets.Data).GetSignature()
	sigInfo := sig.GetsigInfo()
	sigVal := sig.GetsigVal()
	sigInfoTlv := encodeSignatureInfo(sigInfo)
	sigValTlv := encodeSignatureValue(sigVal)
	t = append(t, sigInfoTlv)
	return append(t, sigValTlv), nil
}

func encodeSignatureInfo(sigInfo packets.SignatureInfo) Tlv {
	sigType := sigInfo.GetsigType()
	keyLoc := sigInfo.GetKeyLocator()
	tmp := make([]Tlv, 2)
	tmp[0] = encodeSignatureType(sigType)
	tmp[1] = encodeKeyLocator(keyLoc)
	var b bytes.Buffer
	TlvsToBytes(tmp, &b)
	result := Tlv{
		T: SIGNATURE_INFO,
		L: uint64(b.Len()),
		V: b.Next(b.Len()),
	}
	return result
}

func encodeSignatureType(sigType uint64) Tlv {
	x := EncodeNonNegativeInteger(sigType)
	return Tlv{
		T: SIGNATURE_TYPE,
		L: uint64(len(x)),
		V: x,
	}
}

func encodeKeyLocator(keyLoc packets.KeyLocator) Tlv {
	var b bytes.Buffer
	if keyLoc.HasName {
		x := encodeName(keyLoc.Name)
		err := TlvToBytes(x, &b)
		if err != nil {
			return Tlv{}
		}
		return Tlv{
			T: KEY_LOCATOR,
			L: uint64(b.Len()),
			V: b.Next(b.Len()),
		}
	} else {
		if keyLoc.HasKeyDigest {
			x := encodeKeyDigest(keyLoc.KeyDigest)
			err := TlvToBytes(x, &b)
			if err != nil {
				return Tlv{}
			}
			return Tlv{
				T: KEY_LOCATOR,
				L: uint64(b.Len()),
				V: b.Next(b.Len()),
			}
		}
	}
	return Tlv{}
}

func encodeKeyDigest(kd []byte) Tlv {
	return Tlv{
		T: KEY_DIGEST,
		L: uint64(len(kd)),
		V: kd,
	}
}

func encodeSignatureValue(sigVal []byte) Tlv {
	return Tlv{
		T: SIGNATURE_VALUE,
		L: uint64(len(sigVal)),
		V: sigVal,
	}
}
