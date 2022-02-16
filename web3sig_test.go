package web3sig

import (
	"crypto/ecdsa"
	"log"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

func TestValid(t *testing.T) {
	assert.False(t, Valid([]byte("hello"), []byte("incorrect signature"), []byte("incorrect public key")))

	data, signature, publicKey := testData(t)
	assert.True(t, Valid(data, signature, publicKey))
}

func TestRecover(t *testing.T) {
	_, err := Recover([]byte("invalid bytes"), []byte("invalid signature"))
	assert.NotNil(t, err)

	data, signature, _ := testData(t)
	address, err := Recover(data, signature)
	assert.Nil(t, err)
	assert.Equal(t, "0x96216849c49358B10257cb55b28eA603c874b05E", address)
}

func testData(t *testing.T) ([]byte, []byte, []byte) {
	privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal(err)
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	data := []byte(time.Now().Format(time.RFC3339))
	hash := crypto.Keccak256Hash(data)

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		t.Fatal(err)
	}

	return data, signature, publicKeyBytes
}
