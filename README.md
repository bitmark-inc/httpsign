# httpsign

This is a package for bitmark http message signing.



## Go

### Quick Start

```go
pacakge main

import (
	"github.com/gin-gonic/gin"

	httpsign "github.com/bitmark-inc/httpsign/go/gin"
)

func main() {
	app := gin.Default()
	app.Use(httpsign.New(secretKey))

	app.Run(":8080")
}

```
