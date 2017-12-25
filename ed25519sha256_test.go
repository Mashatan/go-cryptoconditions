//Date: 2017 Q4
//Email: ali.mashatan@gmail.com
//Author: Ali Mashatan

package GoCryptoConditions

import (
	"bytes"
	"testing"

	base58 "github.com/jbenet/go-base58"
	"golang.org/x/crypto/ed25519"
)

func TestEd25519sha256(t *testing.T) {

	var (
		Alice = "3th33iKfYoPXQ6YL8mXcD3gzgMppEEHFBPFqch4Cn5d3"
		//Bob   = "4ScATKswfFYUw3FDoxDoUWsRzBh3BUqTmizmCBNRoPiz"
	)

	buf := bytes.NewBuffer(base58.Decode(Alice))
	pubInner, privInner, _ := ed25519.GenerateKey(buf)

	ee, _ := NewEd25519Sha256(pubInner, privInner)
	tt, _ := ee.Encode()
	t.Log("Encode : ", base58.Encode(tt))

	kk := ee.Condition().URI()
	t.Log("Condition : ", kk)

	vv, _ := NewEd25519Sha256(pubInner, privInner)
	vv.DecodeFulfillment(tt)
	t.Log("Public key orginal  : ", base58.Encode(pubInner))
	t.Log("Public key extract  : ", base58.Encode(vv.asn1.PublicKey))
	/*if !bytes.Equal(vv.asn1.PublicKey, []byte(pubInner)) {
		t.Fail()
	}*/
}
