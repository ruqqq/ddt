// The codes here are based on btcd project
// ISC License
//
// Copyright (c) 2013-2017 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package main

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"math/big"
)

func SerializePublicKeyCompressed(pubKey ecdsa.PublicKey) []byte {
	b := make([]byte, 0, 33)
	format := byte(0x2)
	if isOdd(pubKey.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return append(b, pubKey.X.Bytes()...)
}

func UnserializePublicKeyCompressed(curve *secp256k1.BitCurve, data []byte) (ecdsa.PublicKey, error) {
	var err error

	pubKey := ecdsa.PublicKey{Curve: curve}

	format := data[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	if format != 0x2 {
		return pubKey, fmt.Errorf("invalid magic in compressed pubkey string: %d", data[0])
	}

	pubKey.X = new(big.Int).SetBytes(data[1:33])
	pubKey.Y, err = decompressPoint(curve, pubKey.X, ybit)
	if err != nil {
		return pubKey, err
	}

	return pubKey, nil
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func decompressPoint(curve *secp256k1.BitCurve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	q := new(big.Int).Div(new(big.Int).Add(curve.P, big.NewInt(1)), big.NewInt(4))
	y := new(big.Int).Exp(x3, q, curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}
