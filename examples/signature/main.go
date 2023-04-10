package main

import (
	"encoding/hex"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"

	httpsign "github.com/bitmark-inc/httpsign/go"
	httpsignMiddleware "github.com/bitmark-inc/httpsign/go/gin"
)

func main() {
	err := ServeApplication()
	if err != nil {
		panic(err)
	}
}

// ServeApplication is a function that serve the application
// you can sign a message by using postman docs of postcard api. Just replace the host
func ServeApplication() error {
	router := gin.Default()

	v1 := router.Group("/v1")
	v1.Any("/*proxyPath", SignMiddleware)

	return router.Run(":8009")
}

// SignMiddleware is a middleware that generate the signature of the request
func SignMiddleware(ctx *gin.Context) {
	signatureString, err := httpsignMiddleware.BuildSignatureString(ctx)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"message": "error occur when build signature string",
			"error":   err.Error(),
		})
		return
	}

	signature := Sign(signatureString, viper.GetString("server.secret_key"))

	ctx.JSON(http.StatusOK, gin.H{
		"signature": signature,
		"message":   signatureString,
	})
}

func Sign(payload, secretKey string) string {
	calculated := httpsign.CalculateHMAC(payload, secretKey)

	return hex.EncodeToString(calculated)
}
