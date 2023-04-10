package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	httpsign "github.com/bitmark-inc/httpsign/go"
)

func main() {
	err := serveApplication()
	if err != nil {
		panic(err)
	}
}

// serveApplication is a function that serve the application
// you can sign a message by using postman docs of postcard api. Just replace the host
func serveApplication() error {
	router := gin.Default()

	v1 := router.Group("/v1")
	v1.POST("/postcard/claim", signMiddleware)
	v1.GET("/postcard/claim/:share_code", signMiddleware)
	v1.POST("/postcard/:token_id/share", signMiddleware)
	v1.GET("/postcard/:token_id", signMiddleware)
	v1.POST("/postcard/:token_id/stamp", signMiddleware)

	return router.Run(":8009")
}

// signMiddleware is a middleware that generate the signature of the request
func signMiddleware(ctx *gin.Context) {
	contentType := ctx.Request.Header.Get("Content-Type")

	isFormData, err := regexp.MatchString("multipart/form-data", contentType)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "can not read request body content-type",
			"error":   err,
		})
		return
	}

	var body string

	if isFormData || ctx.Request.Method == http.MethodGet {
		body = ""
	} else {
		bodyBuf, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			ctx.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"message": "can not read bodyr",
				"error":   err,
			})
			return
		}

		body = httpsign.EncodeBodyToHex(bodyBuf)
	}

	var timestamp = ctx.Request.Header.Get("X-Api-Timestamp")

	message := fmt.Sprintf("%s|%s|%s", ctx.Request.URL, body, timestamp)

	signature := Sign([]byte(message), []byte(viper.GetString("server.secret_key")))

	ctx.JSON(http.StatusOK, gin.H{
		"signature": signature,
		"message":   message,
	})
}

func Sign(msg, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)

	calculated := mac.Sum(nil)

	return hex.EncodeToString(calculated)
}
