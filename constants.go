package tss

// TPMVersion is used to configure a preference in
// which TPM to use, if multiple are available.
type TPMVersion uint8

// TPM versions
const (
	TPMVersionAgnostic TPMVersion = iota
	TPMVersion12
	TPMVersion20
)

// TPMInterface indicates how the client communicates
// with the TPM.
type TPMInterface uint8

// TPM interfaces
const (
	TPMInterfaceDirect TPMInterface = iota
	TPMInterfaceKernelManaged
	TPMInterfaceDaemonManaged
)
