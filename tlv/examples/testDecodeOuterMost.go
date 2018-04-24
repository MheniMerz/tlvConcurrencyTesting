// package main

// import (
// 	// "bytes"
// 	"fmt"
// 	"ndn-router/nfd/tlv"
// 	"ndn-router/nfd/tlv/packets"
// 	"time"
// )

// func main() {
// 	//testing with interest

// 	d := []byte{
// 		0x05, 27,
// 		// Name
// 		0x07, 5,
// 		0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// 0x08, 3, 'f', 'o', 'o',
// 		// Selectors?
// 		0x09, 18,
// 		//   MinSuffixComponents?
// 		0x0d, 1, 1,
// 		//   MaxSuffixComponents?
// 		0x0e, 1, 1,
// 		//   PublisherPublicKeyLocator? (not for now)
// 		//   Exclude?
// 		0x10, 5, 0x08, 1, 'a', 0x13, 0,
// 		//   ChildSelector?
// 		0x11, 1, 0,
// 		//   MustBeFresh?
// 		0x12, 0,
// 		// Nonce
// 		// 0x0a, 4, 'a', 'b', 'c', 'd',
// 		// // InterestLifetime? (1000ms)
// 		// 0x0c, 2, 0x03, 0xe8,
// 	}

// 	// d := []byte{
// 	// 	0x05, 0x33, 0x07, 0x27, 0x08, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x04, 0x74, 0x65, 0x73, 0x74, 0x08, 0x04, 0x70, 0x69, 0x6e, 0x67, 0x08, 0x13, 0x33, 0x38, 0x39, 0x31, 0x32, 0x36, 0x31, 0x32, 0x34, 0x31, 0x35, 0x33, 0x35, 0x36, 0x37, 0x37, 0x31, 0x34, 0x38, 0x09, 0x02, 0x12, 0x00, 0x0a, 0x04, 0x84, 0xc4, 0x82, 0x5e,
// 	// }

// 	chResult := make(chan packets.NdnPacket, 1000)

// 	start := time.Now()
// 	for i := 0; i < 1000; i++ {
// 		go tlv.DecodeOuterMostConcurrency(d, chResult)

// 		// var b bytes.Buffer
// 		// y := <-chResult.(packets.Interest)
// 		// fmt.Printf("struct\t\t:: %v\n", y)
// 		// fmt.Printf("Name\t\t:: %s\n", y.GetName().ToString())
// 		// // fmt.Printf("canBePrefix\t:: %v\n", y.GetCanBePrefix())
// 		// // fmt.Printf("mustbeFresh\t:: %v\n", y.GetMustBeFresh())
// 		// fmt.Printf("Life Time\t:: %v\n", y.GetInterestLifetime())
// 		// fmt.Printf("Nonce\t\t:: %v\n", y.GetNonce())

// 		// tlv.Encode(result, &b)
// 		// fmt.Printf("the Original packet :\n %v\n", d)
// 		// fmt.Printf("the encoded packet  :\n %v\n", b.Next(b.Len()))	
// 	}

// 	for  i := 0; i < 1000; i++{
// 		y := <-chResult
// 		fmt.Printf("struct\t\t:: %v\n", y.(packets.Interest))
// 		fmt.Printf("Name\t\t:: %s\n", y.(packets.Interest).GetName().ToString())

// 	}

// 	elapsed := time.Since(start)
// 	fmt.Printf("time == %f\n", elapsed.Seconds())
// }
