package httpsign

import (
	"net/http"

	"github.com/bitmark-inc/traceutils"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/bitmark-inc/autonomy-postcard/log"
)

// AbortWithError abort the request with error message
func AbortWithError(c *gin.Context, code int, message string, traceErr error) {
	if code == http.StatusInternalServerError {
		traceutils.CaptureException(c, traceErr)
	}

	log.Error("request error", zap.Int("http code", code), zap.Error(traceErr))

	c.AbortWithStatusJSON(code, gin.H{
		"message": message,
	})
}