//Date: 2017 Q4
//Email: ali.mashatan@gmail.com
//Author: Ali Mashatan

package GoCryptoConditions

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/Mashatan/asn1"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ed25519"
)

type ed25519Sha256Asn1 struct {
	PublicKey []byte `asn1:"tag:0"`
	Signature []byte `asn1:"tag:1"`
}

type Ed25519Sha256 struct {
	asn1Context *asn1.Context
	asn1        ed25519Sha256Asn1
}

func NewEd25519Sha256(pubkey []byte, signature []byte) (*Ed25519Sha256, error) {

	if len(pubkey) != ed25519.PublicKeySize {
		return nil, errors.Errorf(
			"wrong pubkey size (%d)", len(pubkey))
	}
	/*if len(signature) != ed25519.SignatureSize {
		return nil, errors.Errorf(
			"wrong signature size (%d)", len(signature))
	}*/
	ed := new(Ed25519Sha256)
	ed.asn1.PublicKey = pubkey
	ed.asn1.Signature = signature
	ed.asn1Context = ed.buildASN1Context()
	return ed, nil

}

func (f Ed25519Sha256) Ed25519PublicKey() ed25519.PublicKey {
	return ed25519.PublicKey(f.asn1.PublicKey)
}

func (f Ed25519Sha256) ConditionType() ConditionType {
	return CTEd25519Sha256
}

func (f Ed25519Sha256) Cost() int {
	return 131072
}

func (f Ed25519Sha256) fingerprintContents() []byte {
	content := struct {
		PubKey []byte `asn1:"tag:0"`
	}{
		PubKey: f.asn1.PublicKey,
	}

	encoded, err := f.asn1Context.Encode(content)
	if err != nil {
		panic(err) //TODO check when this can happen
	}

	return encoded
}

func (f Ed25519Sha256) fingerprint() []byte {
	hash := sha256.Sum256(f.fingerprintContents())
	return hash[:]
}

func (f Ed25519Sha256) Condition() *Conditions {
	return NewSimpleCondition(f.ConditionType(), f.fingerprint(), f.Cost())
}

func (f Ed25519Sha256) Encode() ([]byte, error) {
	return f.encodeFulfillment()
}

func (f Ed25519Sha256) Validate(condition *Conditions, message []byte) error {
	/*if !matches(f, condition) {
		return fulfillmentDoesNotMatchConditionError
	}*/

	if ed25519.Verify(f.Ed25519PublicKey(), message, f.asn1.Signature) {
		return nil
	} else {
		return fmt.Errorf("Unable to Validate Ed25519Sha256 fulfillment: "+
			"signature verification failed for message %x", message)
	}
}

func (f Ed25519Sha256) buildASN1Context() *asn1.Context {
	ctx := asn1.NewContext()
	ctx.SetDer(true, true)

	// Define the Fulfillment CHOICE element.
	fulfillmentChoices := []asn1.Choice{
		/*{
			Options: fmt.Sprintf("tag:%d", CTThresholdSha256),
			Type:    reflect.TypeOf(FfThresholdSha256{}),
		},*/
		{
			Options: fmt.Sprintf("tag:%d", CTEd25519Sha256),
			Type:    reflect.TypeOf(ed25519Sha256Asn1{}),
		},
	}
	if err := ctx.AddChoice("fulfillment", fulfillmentChoices); err != nil {
		panic(err)
	}

	return ctx
}

func (f Ed25519Sha256) encodeFulfillment() ([]byte, error) {
	encoded, err := f.asn1Context.Encode(
		f.asn1)
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 encoding failed")
	}
	return encoded, nil
}

func (f Ed25519Sha256) DecodeFulfillment(encodedFulfillment []byte) error {
	var obj interface{}
	rest, err := f.asn1Context.DecodeWithOptions(
		encodedFulfillment, &obj, "choice:fulfillment")
	if err != nil {
		return errors.Wrap(err, "ASN.1 decoding failed")
	}
	if len(rest) != 0 {
		return errors.Errorf(
			"Encoding was not minimal. Excess bytes: %x", rest)
	}

	ptr := reflect.Indirect(reflect.New(reflect.TypeOf(obj)))
	ptr.Set(reflect.ValueOf(obj))
	obj = ptr.Addr().Interface()

	ff := obj.(*ed25519Sha256Asn1)
	/*if !err {
		return errors.New("Encoded object was not a fulfillment")
	}*/
	f.asn1.PublicKey = f.asn1.PublicKey[:0]
	f.asn1.Signature = f.asn1.Signature[:0]

	f.asn1.PublicKey = append(ff.PublicKey)
	f.asn1.Signature = append(ff.Signature)

	return nil
}
