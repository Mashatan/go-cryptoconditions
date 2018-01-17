//Date: 2017 Q4
//Email: ali.mashatan@gmail.com
//Author: Ali Mashatan

package GoCryptoConditions

import (
	"bytes"
	"encoding/hex"
	"testing"

	base58 "github.com/jbenet/go-base58"
	"golang.org/x/crypto/ed25519"
)

func TestHash(t *testing.T) {

	var (
		Alice = "3th33iKfYoPXQ6YL8mXcD3gzgMppEEHFBPFqch4Cn5d3"
	//Bob   = "4ScATKswfFYUw3FDoxDoUWsRzBh3BUqTmizmCBNRoPiz"
	)

	buf := bytes.NewBuffer(base58.Decode(Alice))
	pubInner, privInner, _ := ed25519.GenerateKey(buf)
	publicStr := hex.EncodeToString(pubInner)
	privateStr := hex.EncodeToString(privInner)
	t.Log("Public key orginal  : ", publicStr)
	t.Log("Private key orginal  : ", privateStr)
}

func TestEd25519sha256(t *testing.T) {

	const publicStr = "de38dcd65a92a0a8fdf9d7c81f36e9f699544c5fb23cecb9a2d2262a622f553b"
	const privateStr = "2af5435e885fb89a9548dd56ad9f5933f622704dbf95c6e5d8b393890370b3d2de38dcd65a92a0a8fdf9d7c81f36e9f699544c5fb23cecb9a2d2262a622f553b"
	pubInner, _ := hex.DecodeString(publicStr)
	privInner, _ := hex.DecodeString(privateStr)
	var message []byte = []byte("Hello World! Conditions are here!")
	signInner := ed25519.Sign(ed25519.PrivateKey(privInner), message)

	t.Log("Public key orginal  : ", publicStr)
	t.Log("Private key orginal  : ", privateStr)
	t.Log("Sign key orginal  : ", hex.EncodeToString(signInner))

	ee, _ := NewEd25519Sha256(pubInner, signInner)

	tt, _ := ee.Encode()
	t.Log("Fulfillment : ", Base64UrlEncode(tt))

	kk := ee.Condition().URI()
	t.Log("Condition : ", kk)

	vv, _ := NewEd25519Sha256(pubInner, privInner)
	vv.DecodeFulfillment(tt)
	//t.Log("Public key orginal  : ", base58.Encode(pubInner))
	//t.Log("Public key extract  : ", base58.Encode(vv.asn1.PublicKey))
	/*if !bytes.Equal(vv.asn1.PublicKey, []byte(pubInner)) {
		t.Fail()
	}*/
}
