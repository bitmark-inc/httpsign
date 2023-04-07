package httpsign

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// VerifySignature verify if the signature is hashed by the payload and the secret key
func VerifySignature(payload, signature, secretKey string) bool {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(payload))
	calculated := h.Sum(nil)

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
