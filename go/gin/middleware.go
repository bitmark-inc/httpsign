package middleware

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	httpsign "github.com/bitmark-inc/httpsign/go"
)

// New return a middleware that verify the signature of the request
func New(secretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		signatureString, err := BuildSignatureString(c)
		if err != nil {
			httpsign.AbortWithError(c, http.StatusInternalServerError, "error occur when build string to verify signature", err)
			return
		}

		var signature = c.Request.Header.Get("X-Api-Signature")
		if signature == "" {
			httpsign.AbortWithError(c, http.StatusForbidden, "invalid signature", fmt.Errorf("invalid signature"))
			return
		}

		if !httpsign.VerifySignature(signatureString, signature, secretKey) {
			httpsign.AbortWithError(c, http.StatusForbidden, "signature does not match", fmt.Errorf("invalid signature"))
			return
		}

		c.Next()
	}
}

// BuildSignatureString is a function that build the string to verify
func BuildSignatureString(c *gin.Context) (string, error) {
	contentType := c.ContentType()

	var encodedBody string

	if IsFormData(contentType) || c.Request.Method == http.MethodGet {
		encodedBody = ""
	} else {
		bodyBuf, err := io.ReadAll(c.Request.Body)
		if err != nil {
			return "", err
		}

		encodedBody = httpsign.EncodeBodyToHex(bodyBuf)

		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
	}

	var timestamp = c.Request.Header.Get("X-Api-Timestamp")

	i, err := strconv.Atoi(timestamp)
	if err != nil {
		return "", err
	}

	if time.Since(time.Unix(int64(i), 0)) > time.Minute {
		return "", fmt.Errorf("request time too skewed")
	}

	var stringToVerify = fmt.Sprintf("%s|%s|%s", c.Request.URL.Path, encodedBody, timestamp)

	return stringToVerify, nil
}

// IsFormData is a function that check if the content type is form data
func IsFormData(contentType string) bool {
	return strings.HasPrefix(contentType, "multipart/form-data")
}

func AddSignHeaderToRequest(r *http.Request, secretKey string) *http.Request {
	var encodedBody string

	contentType := r.Header.Get("Content-Type")
	if IsFormData(contentType) || r.Method == http.MethodGet {
		encodedBody = ""
	} else {
		bodyBuf, err := io.ReadAll(r.Body)
		if err != nil {
			return r
		}

		encodedBody = httpsign.EncodeBodyToHex(bodyBuf)

		r.Body = io.NopCloser(bytes.NewBuffer(bodyBuf))
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	message := fmt.Sprintf("%s|%s|%s", r.URL.Path, encodedBody, timestamp)

	hmacSignature := httpsign.CalculateHMAC(message, secretKey)

	r.Header.Set("X-Api-Signature", hex.EncodeToString(hmacSignature))
	r.Header.Set("X-Api-Timestamp", timestamp)
	return r
}
