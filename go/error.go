package httpsign

import (
	"net/http"

	"github.com/bitmark-inc/traceutils"
	"github.com/gin-gonic/gin"
)

// AbortWithError abort the request with error message
func AbortWithError(c *gin.Context, code int, message string, traceErr error) {
	if code == http.StatusInternalServerError {
		traceutils.CaptureException(c, traceErr)
	}

	c.AbortWithStatusJSON(code, gin.H{
		"message": message,
	})
}
