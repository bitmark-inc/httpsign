package middleware

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	httpsign "github.com/bitmark-inc/httpsign/go"
)

func New(secretKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		contentType := c.Request.Header.Get("Content-Type")

		isFormData, err := regexp.MatchString("multipart/form-data", contentType)
		if err != nil {
			httpsign.AbortWithError(c, http.StatusInternalServerError, "can not read request body content-type", err)
			return
		}

		var body string

		if isFormData {
			body = ""
		} else {
			bodyBuf, err := io.ReadAll(c.Request.Body)
			if err != nil {
				httpsign.AbortWithError(c, http.StatusForbidden, "can not read body", err)
				return
			}

			body = httpsign.EncodeBodyToHex(bodyBuf)
		}

		var signature = c.Request.Header.Get("X-Api-Signature")
		if signature == "" {
			httpsign.AbortWithError(c, http.StatusForbidden, "invalid signature", fmt.Errorf("invalid signature"))
			return
		}
		var timestamp = c.Request.Header.Get("X-Api-Timestamp")
		i, err := strconv.Atoi(timestamp)
		if err != nil {
			httpsign.AbortWithError(c, http.StatusForbidden, "error occur when convert timestamp", fmt.Errorf("invalid timestamp"))
			return
		}

		if time.Since(time.Unix(int64(i), 0)) > time.Minute {
			httpsign.AbortWithError(c, http.StatusForbidden, err.Error(), fmt.Errorf("request time too skewed"))
			return
		}

		var stringToVerify = fmt.Sprintf("%s|%s|%s", c.Request.URL, body, timestamp)

		if !httpsign.VerifySignature(stringToVerify, signature, secretKey) {
			httpsign.AbortWithError(c, http.StatusForbidden, "signature does not match", fmt.Errorf("invalid signature"))
			return
		}

		c.Next()
	}
}
