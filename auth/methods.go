package auth

import (
	"base/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetUser(c *gin.Context) *models.User {
	user, exists := c.Get("user")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		c.Abort()
		return nil
	}

	// Convert interface{} to *User
	currentUser, ok := user.(*models.User)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user data"})
		c.Abort()
		return nil
	}

	return currentUser
}
