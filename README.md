# tlvConcurrencyTesting

## tlv test benchmark

i have added 2 decoding models
- decodeConcurrency.go : go routines for each tlv, for now i have only tried name and selectors
- decodeOuterMostConcurrency : decode function is goroutine, others are normal function
### no concurrency
- testfile : tlv/examples/test.go
- 1000 packets : 0.404288, 0.445862, 0.435247

### concurency for each tlv
- testfile : tlv/examples/testConcurrentCodec.go
- 1000 packets :  0.421019, 0.440367, 0.462784

### outer most concurrency 
- testfile : tlv/examples/testDecodeOuterMost.go
- 1000 packets :  0.410745, 0.428470, 0.421668

PS : if you want to use the test files, you need to comment 2 of them and keep only 1 uncommented, 
because they all have main functions and that creates confuion for the compiler
