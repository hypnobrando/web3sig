package web3sig

import (
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

func Valid(data string, sig string, publicKey string) bool {
	decodedData, err := hexutil.Decode(data)
	if err != nil {
		return false
	}

	hash := crypto.Keccak256Hash(decodedData)

	decodedPublicKey, err := hexutil.Decode(publicKey)
	if err != nil {
		return false
	}

	decodedSignature, err := hexutil.Decode(sig)
	if err != nil {
		return false
	}

	signatureNoRecoverID := decodedSignature[:len(decodedSignature)-1]
	return crypto.VerifySignature(decodedPublicKey, hash.Bytes(), signatureNoRecoverID)
}

func Recover(data string, sig string) (string, error) {
	decodedData, err := hexutil.Decode(data)
	if err != nil {
		return "", err
	}

	decodedSignature, err := hexutil.Decode(sig)
	if err != nil {
		return "", err
	}

	hash := crypto.Keccak256Hash(decodedData)

	sigPublicKeyECDSA, err := crypto.SigToPub(hash.Bytes(), decodedSignature)
	if err != nil {
		return "", err
	}

	addr := crypto.PubkeyToAddress(*sigPublicKeyECDSA)

	return addr.Hex(), nil
}
