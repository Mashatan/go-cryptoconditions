//Date: 2017 Q4
//Email: ali.mashatan@gmail.com
//Author: Ali Mashatan

package GoCryptoConditions

import "fmt"

type ConditionType int

const (
	CTThresholdSha256 ConditionType = 2
	CTEd25519Sha256   ConditionType = 4
	nbKnownConditionTypes
)

var conditionTypeDictionary = map[string]ConditionType{
	"THRESHOLD-SHA-256": CTThresholdSha256,
	"ED25519-SHA-256":   CTEd25519Sha256,
}

func (t ConditionType) IsCompound() bool {
	switch t {
	case CTThresholdSha256:
		return true
	case CTEd25519Sha256:
		return false
	}
	panic(fmt.Sprintf("ConditionType %d does not exist", t))
}

func (t ConditionType) String() string {
	switch t {
	case CTThresholdSha256:
		return "THRESHOLD-SHA-256"
	case CTEd25519Sha256:
		return "ED25519-SHA-256"
	}
	panic(fmt.Sprintf("ConditionType %d does not exist", t))
}
