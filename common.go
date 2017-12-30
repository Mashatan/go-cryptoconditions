//Date: 2017 Q4
//Email: ali.mashatan@gmail.com
//Author: Ali Mashatan

package GoCryptoConditions

import (
	"encoding/base64"
	"strings"
)

func Base64UrlEncode(p []byte) string {
	str := base64.RawURLEncoding.EncodeToString(p)
	{
		str = strings.Replace(str, "+", "-", -1)
		str = strings.Replace(str, "/", "_", -1)
		str = strings.Replace(str, "=", "", -1)
	}
	return str
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
