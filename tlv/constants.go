package tlv

const(
	//packet types
	INTEREST                   = 0x05
	DATA                       = 0x06
	//common fields
	NAME                       = 0x07
	NAME_COMPONENT             = 0x08
	IMPLICIT_DIGEST            = 0x01
	//interest packet
	SELECTORS                  = 0x09
	NONCE                      = 0x0a
	INTEREST_LIFETIME          = 0x0c
	//interest selectors
	MIN_SUFFIX_COMPONENTS      = 0x0d
	MAX_SUFFIX_COMPONENTS      = 0x0e
	PUBLISHER_PUB_KEY_LOCATOR  = 0x0f
	EXCLUDE                    = 0x10
	CHILD_SELECTOR             = 0x11
	MUST_BE_FRESH              = 0x12
	ANY                        = 0x13
	//Data packet
	META_INFO                  = 0x14
	CONTENT                    = 0x15
	SIGNATURE_INFO             = 0x16
	SIGNATURE_VALUE            = 0x17
	//Data META_INFO
	CONTENT_TYPE               = 0x18
	FRESHNESS_PERIOD           = 0x19
	FINAL_BLOCK_ID             = 0x1a
	//Data signature
	SIGNATURE_TYPE             = 0x1b
	KEY_LOCATOR                = 0x1c
	KEY_DIGEST                 = 0x1d
)
