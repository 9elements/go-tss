package tss

import (
	"errors"
	"fmt"

	tpm2 "github.com/google/go-tpm/tpm2"

	tpmutil "github.com/google/go-tpm/tpmutil"
)

// NewTPM looks for a TPM and initializes it for further use
func NewTPM() (*TPM, error) {
	candidateTPMs, err := probeSystemTPMs()
	if err != nil {
		return nil, err
	}

	for _, tpm := range candidateTPMs {
		tss, err := newTPM(tpm)
		if err != nil {
			continue
		}
		return tss, nil
	}

	return nil, errors.New("TPM device not available")
}

// Info returns information about the TPM.
func (t *TPM) Info() (*TPMInfo, error) {
	var info TPMInfo
	var err error
	switch t.Version {
	case TPMVersion12:
		info, err = readTPM12Information(t.RWC)
	case TPMVersion20:
		info, err = readTPM20Information(t.RWC)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
	}
	if err != nil {
		return nil, err
	}

	return &info, nil
}

// GetVersion returns the TPM version
func (t *TPM) GetVersion() TPMVersion {
	return t.Version
}

// Close closes the TPM socket and wipe locked buffers
func (t *TPM) Close() error {
	return t.RWC.Close()
}

// NVReadValue reads a value from a given NVRAM index
// Type and byte order for TPM1.2 interface:
// (offset uint32)
// Type and byte oder for TPM2.0 interface:
// (authhandle uint32)
func (t *TPM) NVReadValue(index uint32, ownerPassword string, size, offhandle uint32) ([]byte, error) {
	switch t.Version {
	case TPMVersion12:
		return nvRead12(t.RWC, index, offhandle, size, ownerPassword)
	case TPMVersion20:
		return nvRead20(t.RWC, tpmutil.Handle(index), tpmutil.Handle(offhandle), ownerPassword, int(size))
	}
	return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
}

// GetCapability requests the TPMs capability function and returns an interface.
// User needs to take care of the data for now.
func (t *TPM) GetCapability(cap, subcap uint32) ([]interface{}, error) {
	var err error
	var b []byte
	var ret []interface{}
	switch t.Version {
	case TPMVersion12:
		b, err = getCapability12(t.RWC, cap, subcap)
	case TPMVersion20:
		b, err = getCapability20(t.RWC, tpm2.Capability(cap), subcap)
	default:
		return nil, fmt.Errorf("unsupported TPM version: %x", t.Version)
	}
	if err != nil {
		return nil, err
	}
	ret = append(ret, b)
	return ret, nil
}

// ReadNVPublic reads public data about an NVRAM index. Permissions and what so not.
func (t *TPM) ReadNVPublic(index uint32) ([]byte, error) {
	var raw []byte
	var err error
	switch t.Version {
	case TPMVersion12:
		raw, err = readNVPublic12(t.RWC, index)
		if err != nil {
			return nil, err
		}
		return raw, nil
	case TPMVersion20:
		raw, err = readNVPublic20(t.RWC, index)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported TPM version %v", t.Version)
	}

	return raw, nil
}
