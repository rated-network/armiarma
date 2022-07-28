package utils

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"strings"

	gcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/libp2p/go-libp2p-core/crypto"
)

// Parse a Secp256k1PrivateKey from string, checking if it has the proper curve
func ParsePrivateKey(v string) (*crypto.Secp256k1PrivateKey, error) {

	if strings.HasPrefix(v, "0x") {
		v = v[2:]
	}
	privKeyBytes, err := hex.DecodeString(v)
	if err != nil {
		log.Debugf("cannot parse private key, expected hex string: %v", err)
		return nil, err
	}
	var priv crypto.PrivKey
	priv, err = crypto.UnmarshalSecp256k1PrivateKey(privKeyBytes)
	if err != nil {
		log.Debugf("cannot parse private key, invalid private key (Secp256k1): %v", err)
		return nil, err
	}
	key := (priv).(*crypto.Secp256k1PrivateKey)
	// key.Curve = gcrypto.S256()              // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1
	// if !key.Curve.IsOnCurve(key.X, key.Y) { // TODO: should we be checking this?
	// 	log.Debugf("invalid private key, not on curve")
	// 	return nil, nil
	// }
	return key, nil
}

// Export Private Key to a string
func PrivKeyToString(input_key *crypto.Secp256k1PrivateKey) string {

	keyBytes, err := input_key.Raw()

	if err != nil {
		log.Debugf("Could not Export Private Key to String")
		return ""
	}

	return hex.EncodeToString(keyBytes)
}

// taken from Prysm
func ConvertFromInterfacePrivKey(privkey crypto.PrivKey) (*ecdsa.PrivateKey, error) {
	secpKey := (privkey.(*crypto.Secp256k1PrivateKey))
	rawKey, err := secpKey.Raw()
	if err != nil {
		return nil, err
	}
	privKey := new(ecdsa.PrivateKey)
	k := new(big.Int).SetBytes(rawKey)
	privKey.D = k
	privKey.Curve = gcrypto.S256() // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1.
	privKey.X, privKey.Y = gcrypto.S256().ScalarBaseMult(rawKey)
	return privKey, nil
}

func GeneratePrivKey() *ecdsa.PrivateKey {
	priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
	if err != nil {
		log.Panicf("failed to generate key: %v", err)
	}
	k, err := ConvertFromInterfacePrivKey(priv)
	if err != nil {
		panic(err)
	}
	return k
}
