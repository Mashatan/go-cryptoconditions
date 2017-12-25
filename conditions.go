//Date: 2017 Q4
//Email: ali.mashatan@gmail.com
//Author: Ali Mashatan

package GoCryptoConditions

import (
	"bytes"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/Mashatan/asn1"
	"github.com/kalaspuffar/base64url"
	"github.com/pkg/errors"
)

type encodableEd25519Sha256 struct {
	Fingerprint []byte `asn1:"tag:0"`
	Cost        int    `asn1:"tag:1"`
}

type Conditions struct {
	conditionType ConditionType
	fingerprint   []byte
	cost          int
	asn1Context   *asn1.Context
}

func NewSimpleCondition(conditionType ConditionType, fingerprint []byte, cost int) *Conditions {

	sc := new(Conditions)
	sc.conditionType = conditionType
	sc.fingerprint = fingerprint
	sc.cost = cost
	sc.asn1Context = sc.buildASN1Context()
	return sc
}

func (c Conditions) Type() ConditionType {
	return c.conditionType
}

func (c Conditions) Fingerprint() []byte {
	return c.fingerprint
}

func (c Conditions) Cost() int {
	return c.cost
}

func (c *Conditions) Equals(other *Conditions) bool {
	return c.Type() == other.Type() &&
		bytes.Equal(c.fingerprint, other.Fingerprint()) &&
		c.Cost() == other.Cost()
}

func (c *Conditions) URI() string {
	return c.generateURI()
}

func (c *Conditions) Encode() ([]byte, error) {
	return c.encodeCondition()
}

func (c *Conditions) generateURI() string {
	params := make(url.Values)
	params.Set("cost", fmt.Sprintf("%d", c.Cost()))
	params.Set("fpt", strings.ToLower(c.Type().String()))

	encodedFingerprint := base64url.Encode(c.Fingerprint())
	uri := url.URL{
		Scheme:   "ni",
		Path:     "/sha-256;" + encodedFingerprint,
		RawQuery: params.Encode(),
	}

	return uri.String()
}

func (c *Conditions) buildASN1Context() *asn1.Context {
	ctx := asn1.NewContext()
	ctx.SetDer(true, true)

	conditionChoices := []asn1.Choice{
		{
			Options: fmt.Sprintf("tag:%d", CTEd25519Sha256),
			Type:    reflect.TypeOf(encodableEd25519Sha256{}),
		},
	}
	if err := ctx.AddChoice("condition", conditionChoices); err != nil {
		panic(err)
	}

	return ctx
}

func (c *Conditions) castToEncodableCondition() interface{} {
	switch c.conditionType {
	case CTEd25519Sha256:
		return encodableEd25519Sha256{
			Fingerprint: c.Fingerprint(),
			Cost:        c.Cost(),
		}
	}
	return nil
}

func (c *Conditions) encodeCondition() ([]byte, error) {
	var encoded = c.castToEncodableCondition()
	encoding, err := c.asn1Context.EncodeWithOptions(encoded, "choice:condition")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 encoding failed")
	}
	return encoding, nil
}

func (c *Conditions) DecodeCondition(encodedCondition []byte) (*Conditions, error) {
	var obj interface{}
	rest, err := c.asn1Context.DecodeWithOptions(
		encodedCondition, &obj, "choice:condition")
	if err != nil {
		return nil, errors.Wrap(err, "ASN.1 decoding failed")
	}
	if len(rest) != 0 {
		return nil, errors.Errorf(
			"Encoding was not minimal. Excess bytes: %x", rest)
	}

	var cond *Conditions
	switch obj.(type) {
	case encodableEd25519Sha256:
		c := obj.(encodableEd25519Sha256)
		cond = NewSimpleCondition(CTEd25519Sha256, c.Fingerprint, c.Cost)

	default:
		return nil, errors.New("encoding was not a condition")
	}

	return cond, nil
}
