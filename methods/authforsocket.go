package methods

import (
	"base/initials"
	"base/models"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"
)

func AuthForSocket(c *gin.Context) *models.User {
	accessToken := c.Query("token")
	if accessToken == "" {
		log.Println("Missing token in query parameters")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return nil
	}

	// Parse and validate the access token
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid access token",
		})
		c.Abort()
		return nil
	}

	// Extract user ID from the access token claims
	var userID string
	switch v := claims["sub"].(type) {
	case string:
		// If the user ID is stored as a string, directly assign it
		userID = v
	case float64:
		// If the user ID is stored as a number (float64), convert it to string
		userID = fmt.Sprintf("%.0f", v)
	default:
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "invalid user ID type in token",
		})
		c.Abort()
		return nil
	}

	// Fetch user from the database
	var user models.User
	if err := initials.DB.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "user not found",
		})
		c.Abort()
		return nil
	}

	// Convert RoomIDs from []uint to pq.Int64Array
	var roomIDs pq.Int64Array
	for _, id := range user.RoomIDs {
		roomIDs = append(roomIDs, int64(id))
	}

	// Assign the converted array back to the user struct
	user.RoomIDs = roomIDs

	return &user
}
