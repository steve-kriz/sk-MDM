//go:build windows

package platform

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// SystemProtector is the real SecretProtector: DPAPI with machine scope.
//
// CRYPTPROTECT_LOCAL_MACHINE lets any process on this machine decrypt the
// blob -- which is what lets the LocalSystem service read what an
// administrator's `mdmagent login` wrote -- and the file's ACL under
// ProgramData is what keeps other users out. CRYPTPROTECT_UI_FORBIDDEN makes
// DPAPI fail rather than prompt, since the service has no desktop.
type SystemProtector struct{}

// NewSecretProtector returns the host's SecretProtector.
func NewSecretProtector() SecretProtector { return SystemProtector{} }

const dpapiFlags = windows.CRYPTPROTECT_LOCAL_MACHINE | windows.CRYPTPROTECT_UI_FORBIDDEN

// Protect encrypts plaintext with DPAPI.
func (SystemProtector) Protect(plaintext []byte) ([]byte, error) {
	in := newBlob(plaintext)
	var out windows.DataBlob
	if err := windows.CryptProtectData(in, nil, nil, 0, nil, dpapiFlags, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

// Unprotect decrypts a blob Protect produced.
func (SystemProtector) Unprotect(ciphertext []byte) ([]byte, error) {
	in := newBlob(ciphertext)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(in, nil, nil, 0, nil, dpapiFlags, &out); err != nil {
		return nil, err
	}
	return takeBlob(&out), nil
}

func newBlob(data []byte) *windows.DataBlob {
	if len(data) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
}

// takeBlob copies DPAPI's output into Go memory and frees the original.
func takeBlob(blob *windows.DataBlob) []byte {
	if blob.Data == nil {
		return []byte{}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(blob.Data)))
	return append([]byte(nil), unsafe.Slice(blob.Data, blob.Size)...)
}
