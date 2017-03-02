package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

const (
	TEST_PRIVATE_KEY = "fe90f04022ee37dfb4ccae2c9d2610932a1c7bd8f92b0a2e05cf8c7031ad5b1c"
	TEST_PUBLIC_KEY  = "023f00e77837b341841f587385594951d65179364c2d435d44457df19797012975"
)

func TestSignatureCommand(t *testing.T) {
	command := SignatureCommand{}
	command.Type = TYPE_REGISTER_SIGNATURE
	command.Username = "TestUser"
	command.ImageName = "TestImage"
	command.TagName = "TestTag"
	command.KeyId = 0
	command.Digests = append(command.Digests, "sha256:eed4da4937cb562e9005f3c66eb8c3abc14bb95ad497c03dc89d66bcd172fc7f")
	command.Digests = append(command.Digests, "sha256:b6ca02dfe5e62c58dacb1dec16eb42ed35761c15562485f9da9364bb7c90b9b3")
	command.Digests = append(command.Digests, "sha256:afbfb84fad8a4d9a9818efcb4f084bde4b14934c91a531ae344814a5191a2eb6")
	command.Digests = append(command.Digests, "sha256:41829a143bccc7bee3849353e1ce4358d4cf1c7481f236d8194ea36113bf73d9")
	command.Digests = append(command.Digests, "sha256:86726b2a83fc76e0eeabb1ae34b1a128e1bb41d1efc2242c0a39cd7b94ca2b98")
	command.Digests = append(command.Digests, "sha256:5b0e63da2fb4bc9917bb6d00046cc7db229c15649cabe61439a6b2c0f01c5bf9")
	command.Digests = append(command.Digests, "sha256:c418a51fc08117c4b436d1c4317dc4c567f1874abb9d7297b8d794ce3ac59407")
	command.Digests = append(command.Digests, "sha256:eae6e471b603f3df6028a2a932a211707ce4032ab223e352b82ef62821d30a4c")

	var setSuccess bool
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D, setSuccess = new(big.Int).SetString(TEST_PRIVATE_KEY, 16)
	if !setSuccess {
		t.Error(errors.New("Private Key is invalid."))
	}
	privateKey.PublicKey.Curve = secp256k1Curve
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, command.BytesForSigning())
	if err != nil {
		t.Error(err)
	}
	signature := r.Bytes()
	signature = append(signature, s.Bytes()...)
	copy(command.Signature[:], signature)

	commandStr := fmt.Sprintf("%+v", command)
	t.Logf("SignatureCommand: %s\n", commandStr)

	packedCommand := command.Bytes()
	t.Logf("Packed SignatureCommand (%d): %x\n", len(packedCommand), packedCommand)

	command2 := *NewSignatureCommandFromBytes(packedCommand)
	command2Str := fmt.Sprintf("%+v", command2)
	t.Logf("SignatureCommand: %s\n", command2Str)

	if commandStr != command2Str {
		t.Error("Failed to pack and unpack while preserving data\n")
	}
}
