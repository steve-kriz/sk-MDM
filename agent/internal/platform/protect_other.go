//go:build !windows

package platform

// SystemProtector is the real SecretProtector off Windows: the identity.
//
// On macOS the token file is written mode 0600 and owned by root, the same
// protection the device secret in state.json has. The Keychain is not used:
// the agent is built with CGO_ENABLED=0, so Security.framework is out of
// reach, and the `security` CLI would put the secret on a command line.
type SystemProtector struct{}

// NewSecretProtector returns the host's SecretProtector.
func NewSecretProtector() SecretProtector { return SystemProtector{} }

// Protect returns plaintext unchanged.
func (SystemProtector) Protect(plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

// Unprotect returns ciphertext unchanged.
func (SystemProtector) Unprotect(ciphertext []byte) ([]byte, error) {
	return append([]byte(nil), ciphertext...), nil
}
