package web3sig

import (
	"github.com/ethereum/go-ethereum/crypto"
)

func Valid(data []byte, sig []byte, publicKey []byte) bool {
	hash := crypto.Keccak256Hash(data)

	signatureNoRecoverID := sig[:len(sig)-1]
	return crypto.VerifySignature(publicKey, hash.Bytes(), signatureNoRecoverID)
}

func Recover(data []byte, sig []byte) (string, error) {
	hash := crypto.Keccak256Hash(data)

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), sig)
	if err != nil {
		return "", err
	}

	addr := crypto.PubkeyToAddress(*sigPublicKeyECDSA)

	return addr.Hex(), nil
}
