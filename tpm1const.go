package tss

const (
	nvPerOwnerRead = 0x00100000
	nvPerAuthRead  = 0x00200000
)

// TPM1 Capability types.
const (
	CapAlg      uint32 = 0x00000002
	CapProperty uint32 = 0x00000005
	CapFlag     uint32 = 0x00000004
	CapNVList   uint32 = 0x0000000D
	CapNVIndex  uint32 = 0x00000011
	CapHandle   uint32 = 0x00000014
)

// TPM1 SubCapabilities
const (
	CapPropManufacturer uint32 = 0x00000103
	CapFlagPermanent    uint32 = 0x00000108
)
