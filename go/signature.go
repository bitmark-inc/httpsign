package httpsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// VerifySignature verify if the signature is hashed by the payload and the secret key
func VerifySignature(payload, signature, secretKey string) bool {
	calculated := CalculateHMAC(payload, secretKey)

	s, err := hex.DecodeString(signature)
	if err != nil {
		return false
	}

	return hmac.Equal(calculated, s)
}

// EncodeBodyToHex encode the body to hex string
func EncodeBodyToHex(body []byte) string {
	h := sha256.New()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// CalculateHMAC calculate the hmac of the payload
func CalculateHMAC(payload, secretKey string) []byte {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(payload))
	return h.Sum(nil)
}
