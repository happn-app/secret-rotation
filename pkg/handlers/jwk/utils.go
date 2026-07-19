package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// keyBits returns the parameter size of the key in bits.
func GetKeyBits(key jwk.Key) (int, error) {
	raw, err := jwk.Export[any](key)
	if err != nil {
		return 0, err
	}
	switch k := raw.(type) {
	case *rsa.PrivateKey:
		return k.N.BitLen(), nil
	case *rsa.PublicKey:
		return k.N.BitLen(), nil
	case *ecdsa.PrivateKey:
		return k.Curve.Params().BitSize, nil // 256, 384, 521
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize, nil
	case ed25519.PublicKey:
		return len(k) * 8, nil // 256 (curve size)
	case ed25519.PrivateKey:
		return 256, nil // stored as 64B seed+pub; curve is 256-bit
	case []byte:
		return len(k) * 8, nil // symmetric: this IS the entropy bound
	}
	return 0, fmt.Errorf("unsupported key type")
}
