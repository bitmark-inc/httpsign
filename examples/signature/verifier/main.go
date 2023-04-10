package main

import (
	"io"

	"github.com/gin-gonic/gin"

	httpsign "github.com/bitmark-inc/httpsign/go/gin"
)

func main() {
	r := gin.New()

	r.Use(httpsign.New(""))

	r.Any("/*any", func(c *gin.Context) {
		b, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.String(500, err.Error())
		}

		c.String(200, string(b))
	})

	r.Run(":9090")
}
